// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/webapp/webauth/jwtutil"
	"gopkg.in/yaml.v3"
)

func ExampleJWTIssuer() {
	// 1. Setup signing keys.
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := jwtutil.NewED25519Signer(priv, "key-1")

	mux := http.NewServeMux()

	// 2. Direct issuance (e.g. for API clients or curl):
	// Returns a JSON payload {"token": "..."} to any visitor.
	apiIssuer := jwtutil.JWTIssuerMust(signer,
		jwtutil.WithSubject("service-account"),
		jwtutil.WithIssuer("auth-service"),
		jwtutil.WithAudience("api.example.com"),
		jwtutil.WithClaim("role", "reader"),
		jwtutil.WithExpiration(time.Hour),
		jwtutil.WithJSON(true),
	)
	mux.Handle("/api/token", apiIssuer)

	// 3. Cookie issuance with redirect (e.g. for browser login into a localhost app):
	// Sets a secure HTTP cookie and redirects the browser to the dashboard.
	loginIssuer := jwtutil.JWTIssuerMust(signer,
		jwtutil.WithSubject("local-user"),
		jwtutil.WithClaim("role", "admin"),
		jwtutil.WithExpiration(8*time.Hour),
		jwtutil.WithCookie("session_token"),
		jwtutil.WithRedirect("/dashboard"),
	)
	mux.Handle("/login", loginIssuer)

	fmt.Println("Auth endpoints registered at /api/token and /login")

	_ = http.ListenAndServe("127.0.0.1:8080", mux) //nolint:gosec // G114: example code, not meant to be run.
}

// exampleKeyStore returns a context containing the key store that the
// configurations in the examples below refer to, along with the public key of
// the signing key it contains. A real application would read the keys from a
// keychain or a configuration file, eg. using keys.InMemoryKeyStore.ReadYAML,
// and store them in the context using keys.ContextWithKeyStore.
func exampleKeyStore() (context.Context, ed25519.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	store := keys.NewInMemoryKeyStore()
	spec := fmt.Sprintf(`
- key_id: jwt-signing-key
  user: service
  token: %v
  extra:
    algorithm: EdDSA
`, base64.StdEncoding.EncodeToString(priv))
	if err := yaml.Unmarshal([]byte(spec), store); err != nil {
		panic(err)
	}
	return keys.ContextWithKeyStore(context.Background(), store), pub
}

// ExampleJWTSignerConfig illustrates creating a signer, and the matching
// verifier, from a YAML configuration and a key store held in a context.
func ExampleJWTSignerConfig() {
	ctx, _ := exampleKeyStore()

	var cfg jwtutil.JWTSignerConfig
	if err := yaml.Unmarshal([]byte(`
jwt_issuer: auth.example.com
jwt_audience:
  - api.example.com
jwt_signing_key:
  key_id: jwt-signing-key
  user: service
`), &cfg); err != nil {
		fmt.Println(err)
		return
	}

	// The signing key is read from the key store in the context.
	signer, err := cfg.NewSigner(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Builder sets the issuer and audience from the configuration, as well as
	// the issued at and expiration claims.
	token, err := cfg.Builder(time.Hour).Subject("service-account").
		Claim("role", "reader").Build()
	if err != nil {
		fmt.Println(err)
		return
	}
	signed, err := signer.Sign(ctx, token)
	if err != nil {
		fmt.Println(err)
		return
	}

	// A service that issues and verifies its own tokens can derive the
	// verifier configuration from the signer configuration. The Verifier
	// checks the issuer and audience in addition to the signature.
	verifier, err := cfg.VerifierConfig().NewVerifier(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}
	parsed, err := verifier.ParseAndValidate(ctx, signed)
	if err != nil {
		fmt.Println(err)
		return
	}
	issuer, _ := parsed.Issuer()
	audience, _ := parsed.Audience()
	subject, _ := parsed.Subject()
	var role string
	if err := parsed.Get("role", &role); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(issuer, audience, subject, role)

	// Output:
	// auth.example.com [api.example.com] service-account reader
}

// ExampleJWTVerifierConfig illustrates a service that verifies tokens issued
// elsewhere and hence holds public keys only. Multiple verification keys can be
// configured to allow for key rotation.
func ExampleJWTVerifierConfig() {
	// The issuing service signs a token.
	signerCtx, pub := exampleKeyStore()
	signerCfg := jwtutil.JWTSignerConfig{
		Issuer:     "auth.example.com",
		Audience:   []string{"api.example.com"},
		SigningKey: keys.KeySpec{ID: "jwt-signing-key", User: "service"},
	}
	signer, err := signerCfg.NewSigner(signerCtx)
	if err != nil {
		fmt.Println(err)
		return
	}
	token, err := signerCfg.Builder(time.Hour).Subject("service-account").Build()
	if err != nil {
		fmt.Println(err)
		return
	}
	signed, err := signer.Sign(signerCtx, token)
	if err != nil {
		fmt.Println(err)
		return
	}

	// The verifying service holds the public key for the current key, and for
	// the key that it replaced, as the token value.
	store := keys.NewInMemoryKeyStore()
	publicKeys := fmt.Sprintf(`
- key_id: jwt-signing-key
  token: %v
- key_id: retired-signing-key
  token: %v
`, base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)))
	if err := yaml.Unmarshal([]byte(publicKeys), store); err != nil {
		fmt.Println(err)
		return
	}
	ctx := keys.ContextWithKeyStore(context.Background(), store)

	var cfg jwtutil.JWTVerifierConfig
	if err := yaml.Unmarshal([]byte(`
jwt_issuer: auth.example.com
jwt_audience:
  - api.example.com
jwt_verification_keys:
  - key_id: jwt-signing-key
  - key_id: retired-signing-key
`), &cfg); err != nil {
		fmt.Println(err)
		return
	}
	verifier, err := cfg.NewVerifier(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}
	parsed, err := verifier.ParseAndValidate(ctx, signed)
	if err != nil {
		fmt.Println(err)
		return
	}
	subject, _ := parsed.Subject()
	fmt.Println("verified:", subject)

	// A token for another audience is rejected even though its signature is
	// valid.
	otherCfg := signerCfg
	otherCfg.Audience = []string{"other.example.com"}
	other, err := otherCfg.Builder(time.Hour).Subject("service-account").Build()
	if err != nil {
		fmt.Println(err)
		return
	}
	otherSigned, err := signer.Sign(signerCtx, other)
	if err != nil {
		fmt.Println(err)
		return
	}
	if _, err := verifier.ParseAndValidate(ctx, otherSigned); err != nil {
		fmt.Println("rejected: wrong audience")
	}

	// Output:
	// verified: service-account
	// rejected: wrong audience
}

// ExampleJWTCookieSignerConfig illustrates issuing a JWT in a cookie and
// validating it on a subsequent request.
func ExampleJWTCookieSignerConfig() {
	ctx, _ := exampleKeyStore()

	var cfg jwtutil.JWTCookieSignerConfig
	if err := yaml.Unmarshal([]byte(`
name: session_token
validation_time_skew: 30s
domain: app.example.com
path: /
duration: 8h
jwt_issuer: auth.example.com
jwt_audience:
  - app.example.com
jwt_signing_key:
  key_id: jwt-signing-key
  user: service
`), &cfg); err != nil {
		fmt.Println(err)
		return
	}

	signer, err := cfg.NewCookieSigner(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}

	// A login handler issues the cookie, which is scoped and expires as per
	// the configuration.
	login := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := signer.Issue(r.Context(), w, "local-user", map[string]any{"role": "admin"}); err != nil {
			http.Error(w, "failed to issue token", http.StatusInternalServerError)
		}
	})
	rec := httptest.NewRecorder()
	login.ServeHTTP(rec, httptest.NewRequest("POST", "/login", nil).WithContext(ctx))

	cookie := rec.Result().Cookies()[0]
	fmt.Printf("%v: path=%v domain=%v secure=%v httponly=%v maxage=%v\n",
		cookie.Name, cookie.Path, cookie.Domain, cookie.Secure, cookie.HttpOnly, cookie.MaxAge)

	// The client returns the cookie on its next request, which the verifier
	// created from the same configuration validates.
	verifier, err := cfg.VerifierConfig().NewCookieVerifier(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(cookie)

	token, err := verifier.ValidateRequest(ctx, req)
	if err != nil {
		fmt.Println(err)
		return
	}
	subject, _ := token.Subject()
	var role string
	if err := token.Get("role", &role); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(subject, role)

	// A request without the cookie is reported as such.
	if _, err := verifier.ValidateRequest(ctx, httptest.NewRequest("GET", "/dashboard", nil)); errors.Is(err, jwtutil.ErrNoCookie) {
		fmt.Println("no cookie:", err)
	}

	// Output:
	// session_token: path=/ domain=app.example.com secure=true httponly=true maxage=28800
	// local-user admin
	// no cookie: no such cookie: session_token
}
