// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/webapp/cookies"
	"cloudeng.io/webapp/webauth/jwtutil"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"gopkg.in/yaml.v3"
)

func ExampleJWTIssuer() {
	// 1. Setup signing keys.
	info, _ := jwtutil.NewED25519KeyInfo("", "key-1")
	signer, _ := jwtutil.NewSignerFromKeyInfo(context.Background(), info)

	mux := http.NewServeMux()

	// 2. Direct issuance (e.g. for API clients or curl):
	// Returns a JSON payload {"token": "..."} to any visitor.
	apiIssuer := jwtutil.JWTIssuerMust(signer,
		jwtutil.WithSubject("service-account"),
		jwtutil.WithIssuer("auth-service"),
		jwtutil.WithAudience("api.example.com"),
		jwtutil.WithClaims(map[string]any{"role": "reader"}),
		jwtutil.WithExpiration(time.Hour),
		jwtutil.WithJSON(true),
	)
	mux.Handle("/api/token", apiIssuer)

	// 3. Cookie issuance with redirect (e.g. for browser login into a localhost app):
	// Sets a secure HTTP cookie and redirects the browser to the dashboard.
	loginIssuer := jwtutil.JWTIssuerMust(signer,
		jwtutil.WithSubject("local-user"),
		jwtutil.WithClaims(map[string]any{"role": "admin"}),
		jwtutil.WithExpiration(8*time.Hour),
		jwtutil.WithSecureCookie("session_token", cookies.ScopeAndDuration{}),
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
	info, err := jwtutil.NewED25519KeyInfo("service", "jwt-signing-key")
	if err != nil {
		panic(err)
	}
	var extra jwtutil.KeyExtra
	if err := info.UnmarshalExtra(&extra); err != nil {
		panic(err)
	}
	pub, err := base64.StdEncoding.DecodeString(extra.PublicKey)
	if err != nil {
		panic(err)
	}
	store := keys.NewInMemoryKeyStore()
	store.Add(info)
	return keys.ContextWithKeyStore(context.Background(), store), ed25519.PublicKey(pub)
}

// publicKeyInfo returns a verification-only key holding no private key
// material, just the public key recorded in its extra information, as
// described by jwtutil.KeyExtra.
func publicKeyInfo(id string, pub ed25519.PublicKey) keys.Info {
	info := keys.NewInfo("", id, nil)
	info.WithExtra(jwtutil.KeyExtra{
		Algorithm: jwa.EdDSAEd25519().String(),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	})
	return info
}

// ExampleJWTSignerConfig illustrates creating a signer, and the matching
// validator, from a YAML configuration and a key store held in a context.
func ExampleJWTSignerConfig() {
	ctx, pub := exampleKeyStore()
	signingKey := keys.KeySpec{ID: "jwt-signing-key", User: "service"}

	var cfg jwtutil.JWTSignerConfig
	if err := yaml.Unmarshal([]byte(`
jwt_issuer: auth.example.com
jwt_audience:
  - api.example.com
`), &cfg); err != nil {
		fmt.Println(err)
		return
	}

	// The signing key is read from the key store in the context.
	signer, err := jwtutil.SignerForKey(ctx, signingKey)
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

	// A service that issues and verifies its own tokens configures a matching
	// JWTValidatorConfig and builds a Validator directly from the signing
	// key's public half; neither config carries any key material itself.
	vc := jwtutil.JWTValidatorConfig{Issuer: cfg.Issuer, Audience: cfg.Audience}
	validator, err := jwtutil.ValidatorForKeys(ctx, publicKeyInfo(signingKey.ID, pub))
	if err != nil {
		fmt.Println(err)
		return
	}
	parsed, err := validator.ParseAndValidate(ctx, signed, vc.ValidateOptions()...)
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

// ExampleJWTValidatorConfig illustrates a service that verifies tokens issued
// elsewhere and hence holds public keys only. Multiple verification keys can be
// supplied to allow for key rotation.
func ExampleJWTValidatorConfig() {
	// The issuing service signs a token.
	signerCtx, pub := exampleKeyStore()
	signingKey := keys.KeySpec{ID: "jwt-signing-key", User: "service"}
	signerCfg := jwtutil.JWTSignerConfig{
		Issuer:   "auth.example.com",
		Audience: []string{"api.example.com"},
	}
	signer, err := jwtutil.SignerForKey(signerCtx, signingKey)
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
	// the key that it replaced. Neither entry carries any private key
	// material, and neither is looked up from a context-based store: they are
	// supplied directly to ValidatorForKeys.
	verificationKeys := []keys.Info{
		publicKeyInfo("jwt-signing-key", pub),
		publicKeyInfo("retired-signing-key", make(ed25519.PublicKey, ed25519.PublicKeySize)),
	}

	var vc jwtutil.JWTValidatorConfig
	if err := yaml.Unmarshal([]byte(`
jwt_issuer: auth.example.com
jwt_audience:
  - api.example.com
`), &vc); err != nil {
		fmt.Println(err)
		return
	}
	ctx := context.Background()
	validator, err := jwtutil.ValidatorForKeys(ctx, verificationKeys...)
	if err != nil {
		fmt.Println(err)
		return
	}
	parsed, err := validator.ParseAndValidate(ctx, signed, vc.ValidateOptions()...)
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
	if _, err := validator.ParseAndValidate(ctx, otherSigned, vc.ValidateOptions()...); err != nil {
		fmt.Println("rejected: wrong audience")
	}

	// Output:
	// verified: service-account
	// rejected: wrong audience
}

// ExampleJWTCookieSignerConfig illustrates issuing a JWT in a cookie and
// validating it on a subsequent request.
func ExampleJWTCookieSignerConfig() {
	ctx, pub := exampleKeyStore()
	signingKey := keys.KeySpec{ID: "jwt-signing-key", User: "service"}

	var cfg jwtutil.JWTCookieSignerConfig
	if err := yaml.Unmarshal([]byte(`
cookie:
  name: session_token
  domain: app.example.com
  path: /
  duration: 8h
jwt_issuer: auth.example.com
jwt_audience:
  - app.example.com
`), &cfg); err != nil {
		fmt.Println(err)
		return
	}

	signer, err := cfg.NewCookieSigner(ctx, signingKey)
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
	// created from the same configuration validates against the signing
	// key's public half.
	verifier, err := cfg.VerifierConfig().NewCookieVerifier(ctx, publicKeyInfo(signingKey.ID, pub))
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
