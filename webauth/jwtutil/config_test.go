// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/webapp/cookies"
	"cloudeng.io/webapp/webauth/jwtutil"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	testKeyID   = "jwt-signing-key"
	testKeyUser = "tester"
	testIssuer  = "test-issuer"
)

var testKeySpec = keys.KeySpec{ID: testKeyID, User: testKeyUser}

// storeKey returns a context containing a key store holding a single key with
// the supplied token and extra information.
func storeKey(ctx context.Context, spec keys.KeySpec, token []byte, extra any) context.Context {
	info := keys.NewInfo(spec.ID, spec.User, token)
	if extra != nil {
		info.WithExtra(extra)
	}
	return keys.ContextWithKey(ctx, info)
}

// newED25519Key returns a key pair and the context containing it, encoded as
// 'jwt create' stores it, ie. a base64 encoded private key with the algorithm
// and public key recorded in the extra information.
func newED25519Key(t *testing.T) (context.Context, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	extra := map[string]any{
		"algorithm":  "EdDSA",
		"public_key": base64.StdEncoding.EncodeToString(pub),
	}
	token := []byte(base64.StdEncoding.EncodeToString(priv))
	return storeKey(context.Background(), testKeySpec, token, extra), pub
}

func signerConfig() jwtutil.JWTSignerConfig {
	return jwtutil.JWTSignerConfig{
		Issuer:     testIssuer,
		Audience:   []string{"test-audience"},
		SigningKey: testKeySpec,
	}
}

// TestConfigSignAndVerify covers the round trip from a signer created from a
// JWTSignerConfig to a verifier created from the corresponding
// JWTVerifierConfig.
func TestConfigSignAndVerify(t *testing.T) {
	ctx, _ := newED25519Key(t)
	sc := signerConfig()
	signer, err := sc.NewSigner(ctx)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := sc.Builder(time.Hour).Subject("subject").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	signed, err := signer.Sign(ctx, tok)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifier, err := sc.VerifierConfig().NewVerifier(ctx)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	parsed, err := verifier.ParseAndValidate(ctx, signed)
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	if sub, _ := parsed.Subject(); sub != "subject" {
		t.Errorf("subject: got %q, want %q", sub, "subject")
	}
	if iss, _ := parsed.Issuer(); iss != testIssuer {
		t.Errorf("issuer: got %q, want %q", iss, testIssuer)
	}
	if aud, _ := parsed.Audience(); len(aud) != 1 || aud[0] != "test-audience" {
		t.Errorf("audience: got %v, want [test-audience]", aud)
	}
}

// TestConfigVerifyPublicKeyOnly verifies that a verification key need not hold
// any private key material, covering both the extra public_key field and a
// token holding the public key alone.
func TestConfigVerifyPublicKeyOnly(t *testing.T) {
	ctx, pub := newED25519Key(t)
	signer, err := signerConfig().NewSigner(ctx)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signed, err := signer.Sign(ctx, newConfigToken(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for _, tc := range []struct {
		name  string
		token []byte
		extra any
	}{
		{"public key in token", []byte(base64.StdEncoding.EncodeToString(pub)), nil},
		{"public key in extra", nil, map[string]any{"public_key": base64.StdEncoding.EncodeToString(pub)}},
		{"hex encoded public key", []byte(hex.EncodeToString(pub)), nil},
		{"raw public key", pub, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The key store contains only the public key, the signed token
			// must still verify against it.
			vctx := storeKey(context.Background(), testKeySpec, append([]byte(nil), tc.token...), tc.extra)
			vc := jwtutil.JWTVerifierConfig{
				Issuer:           testIssuer,
				Audience:         []string{"test-audience"},
				VerificationKeys: []keys.KeySpec{testKeySpec},
			}
			verifier, err := vc.NewVerifier(vctx)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			if _, err := verifier.ParseAndValidate(vctx, signed); err != nil {
				t.Errorf("ParseAndValidate: %v", err)
			}
		})
	}
}

func newConfigToken(t *testing.T) jwt.Token {
	t.Helper()
	tok, err := signerConfig().Builder(time.Hour).Subject("subject").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return tok
}

// TestConfigHexAndSeedSigningKey covers the encodings accepted for raw ed25519
// signing key material.
func TestConfigHexAndSeedSigningKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	for _, tc := range []struct {
		name  string
		token []byte
	}{
		{"base64", []byte(base64.StdEncoding.EncodeToString(priv))},
		{"base64 raw url", []byte(base64.RawURLEncoding.EncodeToString(priv))},
		{"hex", []byte(hex.EncodeToString(priv))},
		{"raw", priv},
		{"seed", priv.Seed()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := storeKey(context.Background(), testKeySpec, append([]byte(nil), tc.token...), nil)
			sc := signerConfig()
			signer, err := sc.NewSigner(ctx)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			signed, err := signer.Sign(ctx, newConfigToken(t))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			// All encodings must yield the same key, so a verifier built from
			// the base64 form of the same key accepts the token.
			vctx := storeKey(context.Background(), testKeySpec,
				[]byte(base64.StdEncoding.EncodeToString(priv)), nil)
			verifier, err := sc.VerifierConfig().NewVerifier(vctx)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			if _, err := verifier.ParseAndValidate(vctx, signed); err != nil {
				t.Errorf("ParseAndValidate: %v", err)
			}
		})
	}
}

// TestConfigJWKKey covers key material stored as a JWK, which is the only way
// to use an algorithm other than EdDSA.
func TestConfigJWKKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	key, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	token, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshalling jwk: %v", err)
	}
	ctx := storeKey(context.Background(), testKeySpec, append([]byte(nil), token...),
		map[string]any{"algorithm": "RS256"})

	sc := signerConfig()
	signer, err := sc.NewSigner(ctx)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signed, err := signer.Sign(ctx, newConfigToken(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// The verifier uses the public half of the same JWK.
	verifier, err := sc.VerifierConfig().NewVerifier(ctx)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier.ParseAndValidate(ctx, signed); err != nil {
		t.Errorf("ParseAndValidate: %v", err)
	}
}

// TestConfigAudienceAndIssuer verifies that a verifier accepts a token whose
// audience matches any one of the configured audiences and rejects tokens from
// another issuer or for another audience.
func TestConfigAudienceAndIssuer(t *testing.T) {
	ctx, _ := newED25519Key(t)
	signer, err := signerConfig().NewSigner(ctx)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	sign := func(t *testing.T, issuer string, audience []string) []byte {
		t.Helper()
		tok, err := jwt.NewBuilder().Issuer(issuer).Audience(audience).
			Subject("subject").IssuedAt(time.Now()).
			Expiration(time.Now().Add(time.Hour)).Build()
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		signed, err := signer.Sign(ctx, tok)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return signed
	}

	vc := jwtutil.JWTVerifierConfig{
		Issuer:           testIssuer,
		Audience:         []string{"first", "second"},
		VerificationKeys: []keys.KeySpec{testKeySpec},
	}
	verifier, err := vc.NewVerifier(ctx)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	for _, audience := range [][]string{{"first"}, {"second"}, {"second", "other"}} {
		if _, err := verifier.ParseAndValidate(ctx, sign(t, testIssuer, audience)); err != nil {
			t.Errorf("audience %v: %v", audience, err)
		}
	}
	for _, tc := range []struct {
		name     string
		issuer   string
		audience []string
	}{
		{"wrong issuer", "other-issuer", []string{"first"}},
		{"wrong audience", testIssuer, []string{"other"}},
		{"no audience", testIssuer, nil},
	} {
		if _, err := verifier.ParseAndValidate(ctx, sign(t, tc.issuer, tc.audience)); err == nil {
			t.Errorf("%v: got nil error, want the token to be rejected", tc.name)
		}
	}

	// The Validator returned by NewValidator verifies the signature alone.
	validator, err := vc.NewValidator(ctx)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if _, err := validator.ParseAndValidate(ctx, sign(t, "other-issuer", []string{"other"})); err != nil {
		t.Errorf("NewValidator: %v", err)
	}
}

// TestConfigKeyRotation verifies that a token signed by any one of the
// configured verification keys is accepted.
func TestConfigKeyRotation(t *testing.T) {
	ctx := context.Background()
	specs := []keys.KeySpec{{ID: "old", User: testKeyUser}, {ID: "new", User: testKeyUser}}
	for _, spec := range specs {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		ctx = storeKey(ctx, spec, []byte(base64.StdEncoding.EncodeToString(priv)), nil)
	}
	vc := jwtutil.JWTVerifierConfig{
		Issuer:           testIssuer,
		Audience:         []string{"test-audience"},
		VerificationKeys: specs,
	}
	verifier, err := vc.NewVerifier(ctx)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	for _, spec := range specs {
		sc := signerConfig()
		sc.SigningKey = spec
		signer, err := sc.NewSigner(ctx)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		signed, err := signer.Sign(ctx, newConfigToken(t))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, err := verifier.ParseAndValidate(ctx, signed); err != nil {
			t.Errorf("key %v: %v", spec, err)
		}
	}
}

// TestConfigMissingKeys covers the errors reported when the keys named by a
// configuration are not available from the context.
func TestConfigMissingKeys(t *testing.T) {
	sc := signerConfig()
	vc := sc.VerifierConfig()
	csc := cookieSignerConfig()

	if _, err := sc.NewSigner(context.Background()); !errors.Is(err, jwtutil.ErrNoKeyStore) {
		t.Errorf("NewSigner: got %v, want ErrNoKeyStore", err)
	}
	if _, err := vc.NewValidator(context.Background()); !errors.Is(err, jwtutil.ErrNoKeyStore) {
		t.Errorf("NewValidator: got %v, want ErrNoKeyStore", err)
	}
	if _, err := csc.NewCookieSigner(context.Background()); !errors.Is(err, jwtutil.ErrNoKeyStore) {
		t.Errorf("NewCookieSigner: got %v, want ErrNoKeyStore", err)
	}
	if _, err := csc.VerifierConfig().NewCookieVerifier(context.Background()); !errors.Is(err, jwtutil.ErrNoKeyStore) {
		t.Errorf("NewCookieVerifier: got %v, want ErrNoKeyStore", err)
	}

	// A key store that does not contain the configured key.
	ctx := keys.ContextWithKeyStore(context.Background(), keys.NewInMemoryKeyStore())
	if _, err := sc.NewSigner(ctx); !errors.Is(err, jwtutil.ErrKeyNotFound) {
		t.Errorf("NewSigner: got %v, want ErrKeyNotFound", err)
	}
	if _, err := vc.NewValidator(ctx); !errors.Is(err, jwtutil.ErrKeyNotFound) {
		t.Errorf("NewValidator: got %v, want ErrKeyNotFound", err)
	}

	// An empty key store stored as a nil pointer must not panic.
	if _, err := sc.NewSigner(keys.ContextWithoutKeyStore(context.Background())); !errors.Is(err, jwtutil.ErrNoKeyStore) {
		t.Errorf("NewSigner: got %v, want ErrNoKeyStore", err)
	}
}

// TestConfigInvalidKeys covers key material that cannot be used for signing or
// verification.
func TestConfigInvalidKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token []byte
		extra any
	}{
		{"empty", nil, nil},
		{"wrong length", []byte(base64.StdEncoding.EncodeToString(countingBytes(48))), nil},
		{"not encoded key material", []byte("this is not a key!"), nil},
		{"invalid jwk", []byte(`{"kty":"bogus"}`), nil},
		{"unsupported algorithm", []byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize))),
			map[string]any{"algorithm": "not-an-algorithm"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := storeKey(context.Background(), testKeySpec, append([]byte(nil), tc.token...), tc.extra)
			if _, err := signerConfig().NewSigner(ctx); err == nil {
				t.Errorf("NewSigner: got nil error, want the key to be rejected")
			}
		})
	}
	// An unsupported algorithm is only detected for a JWK, raw key material is
	// always ed25519, so check that a non-ed25519 algorithm is reported there.
	ctx := storeKey(context.Background(), testKeySpec, []byte(`{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAA"}`),
		map[string]any{"algorithm": "not-an-algorithm"})
	if _, err := signerConfig().NewSigner(ctx); err == nil ||
		!strings.Contains(err.Error(), "unsupported signature algorithm") {
		t.Errorf("NewSigner: got %v, want an unsupported algorithm error", err)
	}
}

// TestConfigValidate covers the validation of incomplete configurations, which
// the constructors perform before reading any keys.
func TestConfigValidate(t *testing.T) {
	ctx, _ := newED25519Key(t)
	valid := signerConfig()

	noIssuer, noAudience, noKey := valid, valid, valid
	noIssuer.Issuer = ""
	noAudience.Audience = nil
	noKey.SigningKey = keys.KeySpec{}
	for _, cfg := range []jwtutil.JWTSignerConfig{noIssuer, noAudience, noKey} {
		if _, err := cfg.NewSigner(ctx); err == nil {
			t.Errorf("%#v: got nil error, want an invalid configuration", cfg)
		}
	}

	vc := valid.VerifierConfig()
	noVerificationKeys := vc
	noVerificationKeys.VerificationKeys = nil
	if _, err := noVerificationKeys.NewValidator(ctx); err == nil {
		t.Error("NewValidator: got nil error, want an invalid configuration")
	}

	csc := cookieSignerConfig()
	noName, negativeSkew := csc, csc
	noName.Name = ""
	negativeSkew.ValidationTimeSkew = -time.Second
	for _, cfg := range []jwtutil.JWTCookieSignerConfig{noName, negativeSkew} {
		if _, err := cfg.NewCookieSigner(ctx); err == nil {
			t.Errorf("%#v: got nil error, want an invalid configuration", cfg)
		}
	}
	cvc := csc.VerifierConfig()
	cvc.Name = ""
	if _, err := cvc.NewCookieVerifier(ctx); err == nil {
		t.Error("NewCookieVerifier: got nil error, want an invalid configuration")
	}
}

func cookieSignerConfig() jwtutil.JWTCookieSignerConfig {
	return jwtutil.JWTCookieSignerConfig{
		Name:               "jwt",
		ValidationTimeSkew: time.Minute,
		ScopeAndDuration: cookies.ScopeAndDuration{
			Domain:   "example.com",
			Path:     "/app",
			Duration: time.Hour,
		},
		JWTSignerConfig: signerConfig(),
	}
}

// TestCookieSignerAndVerifier covers issuing a cookie containing a JWT and
// validating it from a request.
func TestCookieSignerAndVerifier(t *testing.T) {
	ctx, _ := newED25519Key(t)
	csc := cookieSignerConfig()
	cs, err := csc.NewCookieSigner(ctx)
	if err != nil {
		t.Fatalf("NewCookieSigner: %v", err)
	}
	if got, want := cs.Name(), "jwt"; got != want {
		t.Errorf("Name: got %v, want %v", got, want)
	}

	rec := httptest.NewRecorder()
	if err := cs.Issue(ctx, rec, "subject", map[string]any{"scope": "admin"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookie := responseCookie(t, rec, "jwt")
	// The cookie must be scoped and secured as configured.
	if cookie.Path != "/app" || cookie.Domain != "example.com" {
		t.Errorf("cookie scope: got %v %v, want /app example.com", cookie.Path, cookie.Domain)
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie is not secure: %#v", cookie)
	}
	if got, want := cookie.MaxAge, int(time.Hour.Seconds()); got != want {
		t.Errorf("cookie MaxAge: got %v, want %v", got, want)
	}

	// The signer validates the cookies that it issues itself.
	if _, err := cs.ParseAndValidate(ctx, []byte(cookie.Value)); err != nil {
		t.Errorf("CookieSigner.ParseAndValidate: %v", err)
	}
}

// TestCookieVerifier covers validating a cookie issued by a CookieSigner from a
// request, and requesting its removal.
func TestCookieVerifier(t *testing.T) {
	ctx, _ := newED25519Key(t)
	csc := cookieSignerConfig()
	cs, err := csc.NewCookieSigner(ctx)
	if err != nil {
		t.Fatalf("NewCookieSigner: %v", err)
	}
	rec := httptest.NewRecorder()
	if err := cs.Issue(ctx, rec, "subject", map[string]any{"scope": "admin"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookie := responseCookie(t, rec, "jwt")

	cvc := csc.VerifierConfig()
	cv, err := cvc.NewCookieVerifier(ctx)
	if err != nil {
		t.Fatalf("NewCookieVerifier: %v", err)
	}
	if got, want := cv.Name(), "jwt"; got != want {
		t.Errorf("Name: got %v, want %v", got, want)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	tok, err := cv.ValidateRequest(ctx, req)
	if err != nil {
		t.Fatalf("ValidateRequest: %v", err)
	}
	if sub, _ := tok.Subject(); sub != "subject" {
		t.Errorf("subject: got %v, want subject", sub)
	}
	var scope string
	if err := tok.Get("scope", &scope); err != nil || scope != "admin" {
		t.Errorf("scope claim: got %v, %v, want admin", scope, err)
	}
	// The expiration is derived from the configured cookie duration.
	exp, ok := tok.Expiration()
	if !ok {
		t.Fatal("token has no expiration")
	}
	if d := time.Until(exp); d > time.Hour || d < time.Hour-time.Minute {
		t.Errorf("expiration: got %v from now, want approximately 1h", d)
	}

	// A request without the cookie is reported as such.
	if _, err := cv.ValidateRequest(ctx, httptest.NewRequest("GET", "/", nil)); !errors.Is(err, jwtutil.ErrNoCookie) {
		t.Errorf("ValidateRequest: got %v, want ErrNoCookie", err)
	}

}

// TestCookieVerifierClearCookie verifies that clearing the cookie requests its
// removal, keeping its scope so that the client removes the cookie that was set.
func TestCookieVerifierClearCookie(t *testing.T) {
	ctx, _ := newED25519Key(t)
	cv, err := cookieSignerConfig().VerifierConfig().NewCookieVerifier(ctx)
	if err != nil {
		t.Fatalf("NewCookieVerifier: %v", err)
	}
	rec := httptest.NewRecorder()
	cv.ClearCookie(rec)
	cleared := responseCookie(t, rec, "jwt")
	if cleared.MaxAge != -1 || cleared.Value != "" {
		t.Errorf("cleared cookie: got %#v, want MaxAge -1 and an empty value", cleared)
	}
	if cleared.Path != "/app" || cleared.Domain != "example.com" {
		t.Errorf("cleared cookie scope: got %v %v, want /app example.com", cleared.Path, cleared.Domain)
	}
}

// TestCookieValidationTimeSkew verifies that the configured time skew is
// applied when validating a token.
func TestCookieValidationTimeSkew(t *testing.T) {
	ctx, _ := newED25519Key(t)
	csc := cookieSignerConfig()
	cs, err := csc.NewCookieSigner(ctx)
	if err != nil {
		t.Fatalf("NewCookieSigner: %v", err)
	}
	// A token that expired within the allowed skew, and one that expired
	// outside of it.
	sign := func(t *testing.T, expiredBy time.Duration) []byte {
		t.Helper()
		tok, err := csc.JWTSignerConfig.Builder(0).Subject("subject").
			Expiration(time.Now().Add(-expiredBy)).Build()
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		signed, err := cs.Sign(ctx, tok)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return signed
	}

	cv, err := csc.VerifierConfig().NewCookieVerifier(ctx)
	if err != nil {
		t.Fatalf("NewCookieVerifier: %v", err)
	}
	for _, tc := range []struct {
		expiredBy time.Duration
		valid     bool
	}{
		{30 * time.Second, true},
		{2 * time.Minute, false},
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "jwt", Value: string(sign(t, tc.expiredBy))}) //nolint:gosec // G124: a request cookie carries no attributes.
		_, err := cv.ValidateRequest(ctx, req)
		if got := err == nil; got != tc.valid {
			t.Errorf("expired by %v: got err %v, want valid=%v", tc.expiredBy, err, tc.valid)
		}
	}
}

// countingBytes returns n bytes with increasing values, ie. material that is
// neither all zeros nor, when base64 encoded, a valid hex encoding of a key of
// a different size.
func countingBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func responseCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	t.Fatalf("no cookie named %v in %v", name, rec.Result().Header)
	return nil
}

// TestConfigJWKAlgorithm covers the algorithm used with a key stored as a JWK
// when it is not named by the extra information.
func TestConfigJWKAlgorithm(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	key, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}

	// Without an algorithm in either the JWK or the extra information there is
	// nothing to sign with.
	noAlgo, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshalling jwk: %v", err)
	}
	ctx := storeKey(context.Background(), testKeySpec, append([]byte(nil), noAlgo...), nil)
	if _, err := signerConfig().NewSigner(ctx); err == nil ||
		!strings.Contains(err.Error(), "no signature algorithm") {
		t.Errorf("NewSigner: got %v, want a missing algorithm error", err)
	}

	// The algorithm in the JWK itself is used when the extra information does
	// not name one.
	if err := key.Set(jwk.AlgorithmKey, "EdDSA"); err != nil {
		t.Fatalf("setting alg: %v", err)
	}
	withAlgo, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshalling jwk: %v", err)
	}
	ctx = storeKey(context.Background(), testKeySpec, append([]byte(nil), withAlgo...), nil)
	sc := signerConfig()
	signer, err := sc.NewSigner(ctx)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signed, err := signer.Sign(ctx, newConfigToken(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifier, err := sc.VerifierConfig().NewVerifier(ctx)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier.ParseAndValidate(ctx, signed); err != nil {
		t.Errorf("ParseAndValidate: %v", err)
	}
}

// TestCookieSignerValidator verifies that a CookieSigner parses and validates
// tokens separately as well as in one step.
func TestCookieSignerValidator(t *testing.T) {
	ctx, _ := newED25519Key(t)
	csc := cookieSignerConfig()
	cs, err := csc.NewCookieSigner(ctx)
	if err != nil {
		t.Fatalf("NewCookieSigner: %v", err)
	}
	tok, err := cs.NewToken("subject", nil)
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	signed, err := cs.Sign(ctx, tok)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := cs.Parse(ctx, signed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cs.Validate(ctx, parsed); err != nil {
		t.Errorf("Validate: %v", err)
	}
	// The configured issuer and audience are checked, so an additional
	// validator for another subject must fail.
	if err := cs.Validate(ctx, parsed, jwt.WithSubject("someone-else")); err == nil {
		t.Error("Validate: got nil error, want the subject check to fail")
	}
	// A token signed by another key is not accepted.
	other, _ := newED25519Key(t)
	otherSigner, err := csc.NewCookieSigner(other)
	if err != nil {
		t.Fatalf("NewCookieSigner: %v", err)
	}
	otherSigned, err := otherSigner.Sign(other, tok)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := cs.ParseAndValidate(ctx, otherSigned); err == nil {
		t.Error("ParseAndValidate: got nil error, want the signature check to fail")
	}
}

// TestConfigTokenLifecycle covers the claims set on a token created via
// JWTSignerConfig.Builder and the conditions under which the corresponding
// Verifier rejects it.
func TestConfigTokenLifecycle(t *testing.T) {
	ctx, _ := newED25519Key(t)
	sc := signerConfig()
	signer, err := sc.NewSigner(ctx)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := sc.VerifierConfig().NewVerifier(ctx)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	sign := func(t *testing.T, tok jwt.Token) []byte {
		t.Helper()
		signed, err := signer.Sign(ctx, tok)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return signed
	}

	// Builder sets the issuer and audience from the configuration along with
	// the issued at and expiration claims.
	before := time.Now()
	tok, err := sc.Builder(time.Hour).Subject("subject").Claim("role", "reader").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	iat, ok := tok.IssuedAt()
	if !ok || iat.Before(before.Add(-time.Second)) || iat.After(time.Now().Add(time.Second)) {
		t.Errorf("issued at: got %v (ok=%v), want approximately %v", iat, ok, before)
	}
	exp, ok := tok.Expiration()
	if !ok || exp.Sub(iat) != time.Hour {
		t.Errorf("expiration: got %v (ok=%v), want an hour after %v", exp, ok, iat)
	}

	signed := sign(t, tok)
	parsed, err := verifier.ParseAndValidate(ctx, signed)
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	var role string
	if err := parsed.Get("role", &role); err != nil || role != "reader" {
		t.Errorf("role claim: got %v, %v, want reader", role, err)
	}

	// Additional validators are applied alongside those from the
	// configuration.
	if err := verifier.Validate(ctx, parsed, jwt.WithClaimValue("role", "reader")); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if err := verifier.Validate(ctx, parsed, jwt.WithClaimValue("role", "admin")); err == nil {
		t.Error("Validate: got nil error, want the role check to fail")
	}

}

// TestConfigTokenRejection covers the tokens that a Verifier created from a
// JWTVerifierConfig rejects.
func TestConfigTokenRejection(t *testing.T) {
	ctx, _ := newED25519Key(t)
	sc := signerConfig()
	signer, err := sc.NewSigner(ctx)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := sc.VerifierConfig().NewVerifier(ctx)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	sign := func(t *testing.T, tok jwt.Token) []byte {
		t.Helper()
		signed, err := signer.Sign(ctx, tok)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return signed
	}
	tok, err := sc.Builder(time.Hour).Subject("subject").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	signed := sign(t, tok)

	// An expired token is rejected when no clock skew is allowed, as is one
	// that is not yet valid.
	expired, err := sc.Builder(0).Subject("subject").
		Expiration(time.Now().Add(-time.Minute)).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := verifier.ParseAndValidate(ctx, sign(t, expired)); err == nil {
		t.Error("ParseAndValidate: got nil error, want an expired token to be rejected")
	}
	notYet, err := sc.Builder(time.Hour).Subject("subject").
		NotBefore(time.Now().Add(time.Minute)).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := verifier.ParseAndValidate(ctx, sign(t, notYet)); err == nil {
		t.Error("ParseAndValidate: got nil error, want a not yet valid token to be rejected")
	}

	// A token whose signature does not match its contents is rejected by
	// Parse, ie. before any claim is validated.
	tampered := slices.Clone(signed)
	tampered[len(tampered)/2] ^= 0xff
	if _, err := verifier.Parse(ctx, tampered); err == nil {
		t.Error("Parse: got nil error, want a tampered token to be rejected")
	}

	// A token signed with a key that is not in the key set, ie. with an
	// unknown key id, is also rejected by Parse.
	otherCtx, _ := newED25519Key(t)
	otherSC := signerConfig()
	otherSC.SigningKey = keys.KeySpec{ID: "other-key", User: testKeyUser}
	otherCtx = storeKey(otherCtx, otherSC.SigningKey, []byte(base64.StdEncoding.EncodeToString(newRawKey(t))), nil)
	otherSigner, err := otherSC.NewSigner(otherCtx)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	otherSigned, err := otherSigner.Sign(otherCtx, tok)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := verifier.Parse(ctx, otherSigned); err == nil {
		t.Error("Parse: got nil error, want a token signed by an unknown key to be rejected")
	}
}

func newRawKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return priv
}
