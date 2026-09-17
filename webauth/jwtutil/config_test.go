// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/webapp/cookies"
	"cloudeng.io/webapp/webauth/jwtutil"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gopkg.in/yaml.v3"
)

const (
	testKeyID   = "jwt-signing-key"
	testKeyUser = "tester"
	testIssuer  = "test-issuer"
)

var testKeySpec = keys.KeySpec{ID: testKeyID, User: testKeyUser}

// ed25519Algorithm is the algorithm name that NewED25519KeyInfo records in a
// key's extra information, and hence the name that an ED25519 key must be
// registered under for algoImpl to find it.
var ed25519Algorithm = jwa.EdDSAEd25519().String()

// newKeyInfo returns a keys.Info for spec holding token and extra. extra, if
// not nil, must be a jwtutil.KeyExtra: keys.Info.WithExtra only unmarshals
// into a value of the same concrete type it was given.
func newKeyInfo(spec keys.KeySpec, token []byte, extra any) keys.Info {
	info := keys.NewInfo(spec.User, spec.ID, token)
	if extra != nil {
		info.WithExtra(extra)
	}
	return info
}

// storeKey returns a context containing a key store holding a single key with
// the supplied token and extra information.
func storeKey(ctx context.Context, spec keys.KeySpec, token []byte, extra any) context.Context {
	return keys.ContextWithKey(ctx, newKeyInfo(spec, token, extra))
}

// newED25519Key generates an ed25519 key pair via NewED25519KeyInfo, ie. as
// 'jwt create' would, stores it (with its private key material) in a context
// for signing, and returns that context along with the public-only keys.Info
// for verification: ValidatorForKeys takes keys directly rather than looking
// them up from a context-based store, so no context is needed on the
// verification side.
func newED25519Key(t *testing.T) (context.Context, keys.Info) {
	t.Helper()
	info, err := jwtutil.NewED25519KeyInfo(testKeyUser, testKeyID)
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	ctx := keys.ContextWithKey(context.Background(), info)
	return ctx, jwtutil.CloneKeyInfoForPublicKey(info)
}

func signerConfig() jwtutil.JWTSignerConfig {
	return jwtutil.JWTSignerConfig{
		Issuer:   testIssuer,
		Audience: []string{"test-audience"},
	}
}

// verifierConfigFor returns the validator configuration matching sc, namely
// the same issuer, audience, subject and claims. Neither JWTSignerConfig nor
// JWTValidatorConfig carries key material, so this is purely a claims-shape
// derivation; the matching keys must still be supplied separately wherever a
// Validator is constructed.
func verifierConfigFor(sc jwtutil.JWTSignerConfig) jwtutil.JWTValidatorConfig {
	return jwtutil.JWTValidatorConfig{
		Issuer:   sc.Issuer,
		Audience: slices.Clone(sc.Audience),
		Subject:  sc.Subject,
		Claims:   maps.Clone(sc.Claims),
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

// testVerifier pairs a Validator with the jwt.ValidateOptions implied by a
// JWTValidatorConfig. JWTValidatorConfig has no NewVerifier of its own, since
// it carries no keys (see config_cookies.go's CookieVerifier, which is built
// the same way internally), so tests that need both the signature check and
// the issuer/audience/subject/claims checks build one this way.
type testVerifier struct {
	set  jwk.Set
	opts []jwt.ValidateOption
}

func newTestVerifier(ctx context.Context, vc jwtutil.JWTValidatorConfig, verificationKeys ...keys.Info) (*testVerifier, error) {
	set, err := jwtutil.KeySetForKeys(ctx, verificationKeys...)
	if err != nil {
		return nil, err
	}
	return &testVerifier{set: set, opts: vc.ValidateOptions()}, nil
}

// Parse verifies the signature of token and returns it without validating any
// of its claims, which is left to Validate so that opts (including any
// allowance for clock skew) are applied instead of jwt.Parse's own defaults.
func (v *testVerifier) Parse(_ context.Context, token []byte) (jwt.Token, error) {
	return jwt.Parse(token, jwt.WithKeySet(v.set), jwt.WithValidate(false))
}

func (v *testVerifier) Validate(_ context.Context, token jwt.Token, validators ...jwt.ValidateOption) error {
	return jwt.Validate(token, append(slices.Clone(v.opts), validators...)...)
}

func (v *testVerifier) ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error) {
	parsed, err := v.Parse(ctx, token)
	if err != nil {
		return nil, err
	}
	if err := v.Validate(ctx, parsed, validators...); err != nil {
		return nil, err
	}
	return parsed, nil
}

// TestConfigSignAndVerify covers the round trip from a signer created for a
// key to a verifier created from the matching JWTValidatorConfig.
func TestConfigSignAndVerify(t *testing.T) {
	ctx, pubInfo := newED25519Key(t)
	sc := signerConfig()
	signer, err := jwtutil.SignerForKey(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
	}
	tok, err := sc.Builder(time.Hour).Subject("subject").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	signed, err := signer.Sign(ctx, tok)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifier, err := newTestVerifier(ctx, verifierConfigFor(sc), pubInfo)
	if err != nil {
		t.Fatalf("newTestVerifier: %v", err)
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
// any private key material: the public-only keys.Info returned by
// newED25519Key is enough.
func TestConfigVerifyPublicKeyOnly(t *testing.T) {
	ctx, pubInfo := newED25519Key(t)
	signer, err := jwtutil.SignerForKey(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
	}
	signed, err := signer.Sign(ctx, newConfigToken(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	vc := jwtutil.JWTValidatorConfig{
		Issuer:   testIssuer,
		Audience: []string{"test-audience"},
	}
	verifier, err := newTestVerifier(context.Background(), vc, pubInfo)
	if err != nil {
		t.Fatalf("newTestVerifier: %v", err)
	}
	if _, err := verifier.ParseAndValidate(context.Background(), signed); err != nil {
		t.Errorf("ParseAndValidate: %v", err)
	}
}

// TestConfigVerifyRequiresPublicKey verifies that a verification key without a
// public_key in its extra information is rejected up front, even when its
// token holds key material of the right size.
func TestConfigVerifyRequiresPublicKey(t *testing.T) {
	info := newKeyInfo(testKeySpec,
		[]byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))),
		jwtutil.KeyExtra{Algorithm: ed25519Algorithm})
	vc := jwtutil.JWTValidatorConfig{Issuer: testIssuer, Audience: []string{"test-audience"}}
	if _, err := newTestVerifier(context.Background(), vc, info); err == nil {
		t.Error("newTestVerifier: got nil error, want the missing public_key to be rejected")
	}
}

// TestConfigSigningKeyEncoding covers the key material accepted for an
// ed25519 signing key: the base64, standard encoding, of the 64 byte private
// key. Neither its 32 byte seed nor any other encoding is accepted.
func TestConfigSigningKeyEncoding(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("failed to derive the public key")
	}

	t.Run("valid base64 private key", func(t *testing.T) {
		extra := jwtutil.KeyExtra{
			Algorithm: ed25519Algorithm,
			PublicKey: base64.StdEncoding.EncodeToString(pub),
		}
		ctx := storeKey(context.Background(), testKeySpec,
			[]byte(base64.StdEncoding.EncodeToString(priv)), extra)
		sc := signerConfig()
		signer, err := jwtutil.SignerForKey(ctx, testKeySpec)
		if err != nil {
			t.Fatalf("SignerForKey: %v", err)
		}
		signed, err := signer.Sign(ctx, newConfigToken(t))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		verifyInfo := newKeyInfo(testKeySpec, nil, extra)
		verifier, err := newTestVerifier(ctx, verifierConfigFor(sc), verifyInfo)
		if err != nil {
			t.Fatalf("newTestVerifier: %v", err)
		}
		if _, err := verifier.ParseAndValidate(ctx, signed); err != nil {
			t.Errorf("ParseAndValidate: %v", err)
		}
	})

	// Only the 64 byte private key, base64 standard encoding, is accepted.
	for _, tc := range []struct {
		name  string
		token []byte
	}{
		{"seed", []byte(base64.StdEncoding.EncodeToString(priv.Seed()))},
		{"hex", []byte(hex.EncodeToString(priv))},
		{"raw bytes", priv},
		{"base64 raw url", []byte(base64.RawURLEncoding.EncodeToString(priv))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := storeKey(context.Background(), testKeySpec, append([]byte(nil), tc.token...),
				jwtutil.KeyExtra{Algorithm: ed25519Algorithm})
			if _, err := jwtutil.SignerForKey(ctx, testKeySpec); err == nil {
				t.Error("SignerForKey: got nil error, want the encoding to be rejected")
			}
		})
	}
}

// TestConfigAudienceAndIssuer verifies that a verifier accepts a token whose
// audience matches any one of the configured audiences and rejects tokens from
// another issuer or for another audience.
func TestConfigAudienceAndIssuer(t *testing.T) {
	ctx, pubInfo := newED25519Key(t)
	signer, err := jwtutil.SignerForKey(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
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

	vc := jwtutil.JWTValidatorConfig{
		Issuer:   testIssuer,
		Audience: []string{"first", "second"},
	}
	verifier, err := newTestVerifier(ctx, vc, pubInfo)
	if err != nil {
		t.Fatalf("newTestVerifier: %v", err)
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

	// The Validator returned by ValidatorForKeys verifies the signature alone.
	validator, err := jwtutil.ValidatorForKeys(ctx, pubInfo)
	if err != nil {
		t.Fatalf("ValidatorForKeys: %v", err)
	}
	if _, err := validator.ParseAndValidate(ctx, sign(t, "other-issuer", []string{"other"})); err != nil {
		t.Errorf("ValidatorForKeys: %v", err)
	}
}

// TestConfigKeyRotation verifies that a token signed by any one of the
// configured verification keys is accepted.
func TestConfigKeyRotation(t *testing.T) {
	ctx := context.Background()
	specs := []keys.KeySpec{{ID: "old", User: testKeyUser}, {ID: "new", User: testKeyUser}}
	var pubInfos []keys.Info
	for _, spec := range specs {
		info, err := jwtutil.NewED25519KeyInfo(spec.User, spec.ID)
		if err != nil {
			t.Fatalf("NewED25519KeyInfo: %v", err)
		}
		ctx = keys.ContextWithKey(ctx, info)
		pubInfos = append(pubInfos, jwtutil.CloneKeyInfoForPublicKey(info))
	}
	vc := jwtutil.JWTValidatorConfig{
		Issuer:   testIssuer,
		Audience: []string{"test-audience"},
	}
	verifier, err := newTestVerifier(ctx, vc, pubInfos...)
	if err != nil {
		t.Fatalf("newTestVerifier: %v", err)
	}
	for _, spec := range specs {
		signer, err := jwtutil.SignerForKey(ctx, spec)
		if err != nil {
			t.Fatalf("SignerForKey: %v", err)
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

// TestConfigMissingKeys covers the errors reported when a signing key named
// by a context-based key store is not available. JWTSignerConfig no longer
// names a key at all, and a JWTValidatorConfig's verification keys are
// supplied directly rather than looked up this way, so neither has an
// equivalent lookup failure mode.
func TestConfigMissingKeys(t *testing.T) {
	if _, err := jwtutil.SignerForKey(context.Background(), testKeySpec); !errors.Is(err, jwtutil.ErrNoKeyStore) {
		t.Errorf("SignerForKey: got %v, want ErrNoKeyStore", err)
	}
	csc := cookieSignerConfig()
	if _, err := csc.NewCookieSigner(context.Background(), testKeySpec); !errors.Is(err, jwtutil.ErrNoKeyStore) {
		t.Errorf("NewCookieSigner: got %v, want ErrNoKeyStore", err)
	}

	// A key store that does not contain the configured key.
	ctx := keys.ContextWithKeyStore(context.Background(), keys.NewInMemoryKeyStore())
	if _, err := jwtutil.SignerForKey(ctx, testKeySpec); !errors.Is(err, jwtutil.ErrKeyNotFound) {
		t.Errorf("SignerForKey: got %v, want ErrKeyNotFound", err)
	}

	// An empty key store stored as a nil pointer must not panic.
	if _, err := jwtutil.SignerForKey(keys.ContextWithoutKeyStore(context.Background()), testKeySpec); !errors.Is(err, jwtutil.ErrNoKeyStore) {
		t.Errorf("SignerForKey: got %v, want ErrNoKeyStore", err)
	}

	// NewCookieVerifier's verification keys are supplied directly rather than
	// looked up from a context store, so calling it with none is simply "no
	// keys supplied", not ErrNoKeyStore.
	if _, err := csc.VerifierConfig().NewCookieVerifier(context.Background()); err == nil {
		t.Error("NewCookieVerifier: got nil error, want at least one verification key to be required")
	}
}

// TestConfigInvalidKeys covers key material that cannot be used for signing.
func TestConfigInvalidKeys(t *testing.T) {
	validAlgo := jwtutil.KeyExtra{Algorithm: ed25519Algorithm}
	for _, tc := range []struct {
		name  string
		token []byte
		extra any
	}{
		{"empty", nil, validAlgo},
		{"wrong length", []byte(base64.StdEncoding.EncodeToString(make([]byte, 48))), validAlgo},
		{"not base64 encoded", []byte("this is not a key!"), validAlgo},
		{"no algorithm specified", []byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize))), nil},
		{"unsupported algorithm", []byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize))),
			jwtutil.KeyExtra{Algorithm: "not-an-algorithm"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := storeKey(context.Background(), testKeySpec, append([]byte(nil), tc.token...), tc.extra)
			if _, err := jwtutil.SignerForKey(ctx, testKeySpec); err == nil {
				t.Error("SignerForKey: got nil error, want the key to be rejected")
			}
		})
	}
}

// TestConfigValidate covers the validation of incomplete configurations.
// Neither JWTSignerConfig nor JWTValidatorConfig carries key material, so
// this covers only their claims-related fields directly via Validate, without
// needing any key machinery at all.
func TestConfigValidate(t *testing.T) {
	valid := signerConfig()

	noIssuer, noAudience := valid, valid
	noIssuer.Issuer = ""
	noAudience.Audience = nil
	for _, cfg := range []jwtutil.JWTSignerConfig{noIssuer, noAudience} {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%#v: got nil error, want an invalid configuration", cfg)
		}
	}

	csc := cookieSignerConfig()
	noName, zeroDuration := csc, csc
	noName.Name = ""
	// JWTCookieConfig.Duration must be named explicitly here: JWTSignerConfig
	// has its own, shallower Duration, which an unqualified
	// zeroDuration.Duration would resolve to instead.
	zeroDuration.JWTCookieConfig.Duration = 0
	for _, cfg := range []jwtutil.JWTCookieSignerConfig{noName, zeroDuration} {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%#v: got nil error, want an invalid configuration", cfg)
		}
	}

	cvc := csc.VerifierConfig()
	noVerifierName, negativeSkew := cvc, cvc
	noVerifierName.Name = ""
	negativeSkew.ValidationTimeSkew = -time.Second
	for _, cfg := range []jwtutil.JWTCookieValidatorConfig{noVerifierName, negativeSkew} {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%#v: got nil error, want an invalid configuration", cfg)
		}
	}
}

// TestJWTCookieConfigValidate covers JWTCookieConfig.Validate directly: a
// name, domain, path and a positive duration are all required.
func TestJWTCookieConfigValidate(t *testing.T) {
	valid := jwtutil.JWTCookieConfig{
		Name: "jwt",
		ScopeAndDuration: cookies.ScopeAndDuration{
			Domain:   "example.com",
			Path:     "/app",
			Duration: time.Hour,
		},
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid config: got %v, want nil", err)
	}

	// Host-only cookie (empty domain) and default path (empty path) are valid.
	hostOnly := valid
	hostOnly.Domain = ""
	if err := hostOnly.Validate(); err != nil {
		t.Errorf("host-only config: got %v, want nil", err)
	}
	defaultPath := valid
	defaultPath.Path = ""
	if err := defaultPath.Validate(); err != nil {
		t.Errorf("default path config: got %v, want nil", err)
	}

	noName, zeroDuration, negativeDuration := valid, valid, valid
	noName.Name = ""
	zeroDuration.Duration = 0
	negativeDuration.Duration = -time.Hour
	for _, cfg := range []jwtutil.JWTCookieConfig{noName, zeroDuration, negativeDuration} {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%#v: got nil error, want an invalid configuration", cfg)
		}
	}
}

func cookieSignerConfig() jwtutil.JWTCookieSignerConfig {
	// The JWT's own validity (JWTSignerConfig.Duration) is set to match the
	// cookie's lifetime (JWTCookieConfig.Duration) here, though the two are
	// independent: see TestCookieSigner's MaxAge assertion versus
	// TestCookieVerifier's expiration assertion for tests that pin each down
	// separately.
	sc := signerConfig()
	sc.Duration = time.Hour
	return jwtutil.JWTCookieSignerConfig{
		JWTCookieConfig: jwtutil.JWTCookieConfig{
			Name: "jwt",
			ScopeAndDuration: cookies.ScopeAndDuration{
				Domain:   "example.com",
				Path:     "/app",
				Duration: time.Hour,
			},
		},
		JWTSignerConfig: sc,
	}
}

// TestCookieSigner covers issuing a cookie containing a JWT. CookieSigner only
// signs; see TestCookieVerifier for validating the cookie it issues.
func TestCookieSigner(t *testing.T) {
	ctx, _ := newED25519Key(t)
	csc := cookieSignerConfig()
	cs, err := csc.NewCookieSigner(ctx, testKeySpec)
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
}

// TestCookieSignerDefaultsJWTDuration verifies that if JWTSignerConfig.Duration
// was left at 0, NewCookieSigner defaults it to JWTCookieConfig.Duration so the
// issued token does not lack an expiration.
func TestCookieSignerDefaultsJWTDuration(t *testing.T) {
	ctx, _ := newED25519Key(t)
	csc := cookieSignerConfig()
	csc.Duration = 0
	csc.JWTCookieConfig.Duration = 3 * time.Hour
	cs, err := csc.NewCookieSigner(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("NewCookieSigner: %v", err)
	}
	tok, err := cs.NewToken("user", nil)
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	iat, _ := tok.IssuedAt()
	if exp, ok := tok.Expiration(); !ok || exp.Sub(iat) != 3*time.Hour {
		t.Errorf("expiration: got %v (ok=%v), want 3h matching cookie duration", exp.Sub(iat), ok)
	}
}

// TestCookieInsecure covers Insecure: unlike the secure-by-default case, the
// cookie carries none of the Secure/HttpOnly/SameSite attributes, and a
// request carrying it (set without those attributes, as a real insecure
// client would receive it) still validates.
func TestCookieInsecure(t *testing.T) {
	ctx, pubInfo := newED25519Key(t)
	csc := cookieSignerConfig()
	csc.Insecure = true
	cs, err := csc.NewCookieSigner(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("NewCookieSigner: %v", err)
	}

	rec := httptest.NewRecorder()
	if err := cs.Issue(ctx, rec, "subject", nil); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookie := responseCookie(t, rec, "jwt")
	// Once round-tripped through the wire, an unset SameSite (ie. never
	// written to the Set-Cookie header, which is what SameSiteDefaultMode
	// means) reads back as the zero value, not SameSiteDefaultMode itself.
	if cookie.Secure || cookie.HttpOnly || cookie.SameSite != 0 {
		t.Errorf("cookie is not insecure: %#v", cookie)
	}

	cvc := csc.VerifierConfig()
	cv, err := cvc.NewCookieVerifier(ctx, pubInfo)
	if err != nil {
		t.Fatalf("NewCookieVerifier: %v", err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	if _, err := cv.ValidateRequest(ctx, req); err != nil {
		t.Errorf("ValidateRequest: %v", err)
	}
}

// TestCookieVerifier covers validating a cookie issued by a CookieSigner from a
// request, and requesting its removal.
func TestCookieVerifier(t *testing.T) {
	ctx, pubInfo := newED25519Key(t)
	csc := cookieSignerConfig()
	cs, err := csc.NewCookieSigner(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("NewCookieSigner: %v", err)
	}
	rec := httptest.NewRecorder()
	if err := cs.Issue(ctx, rec, "subject", map[string]any{"scope": "admin"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookie := responseCookie(t, rec, "jwt")

	cvc := csc.VerifierConfig()
	cv, err := cvc.NewCookieVerifier(ctx, pubInfo)
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
	ctx, pubInfo := newED25519Key(t)
	cv, err := cookieSignerConfig().VerifierConfig().NewCookieVerifier(ctx, pubInfo)
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
	ctx, pubInfo := newED25519Key(t)
	csc := cookieSignerConfig()
	cs, err := csc.NewCookieSigner(ctx, testKeySpec)
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

	cvc := csc.VerifierConfig()
	cvc.ValidationTimeSkew = time.Minute
	cv, err := cvc.NewCookieVerifier(ctx, pubInfo)
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

// TestCookieSignAndVerifySeparately verifies that a token signed by a
// CookieSigner can be parsed and validated separately, in two steps, by a
// CookieVerifier built from the matching JWTCookieValidatorConfig, as well as
// in one step via ParseAndValidate.
func TestCookieSignAndVerifySeparately(t *testing.T) {
	ctx, pubInfo := newED25519Key(t)
	csc := cookieSignerConfig()
	cs, err := csc.NewCookieSigner(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("NewCookieSigner: %v", err)
	}
	cv, err := csc.VerifierConfig().NewCookieVerifier(ctx, pubInfo)
	if err != nil {
		t.Fatalf("NewCookieVerifier: %v", err)
	}
	tok, err := cs.NewToken("subject", nil)
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	signed, err := cs.Sign(ctx, tok)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := cv.Parse(ctx, signed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cv.Validate(ctx, parsed); err != nil {
		t.Errorf("Validate: %v", err)
	}
	// The configured issuer and audience are checked, so an additional
	// validator for another subject must fail.
	if err := cv.Validate(ctx, parsed, jwt.WithSubject("someone-else")); err == nil {
		t.Error("Validate: got nil error, want the subject check to fail")
	}
	// A token signed by another key is not accepted.
	other, _ := newED25519Key(t)
	otherSigner, err := jwtutil.SignerForKey(other, testKeySpec)
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
	}
	otherSigned, err := otherSigner.Sign(other, tok)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := cv.ParseAndValidate(ctx, otherSigned); err == nil {
		t.Error("ParseAndValidate: got nil error, want the signature check to fail")
	}
}

// TestCookieSignerReservedClaims verifies that CookieSigner.NewToken and Issue
// reject attempts to overwrite standard reserved claims (iss, sub, aud, exp, nbf, iat, jti).
func TestCookieSignerReservedClaims(t *testing.T) {
	ctx, _ := newED25519Key(t)
	csc := cookieSignerConfig()
	cs, err := csc.NewCookieSigner(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("NewCookieSigner: %v", err)
	}

	reservedClaims := []string{
		jwt.IssuerKey,
		jwt.SubjectKey,
		jwt.AudienceKey,
		jwt.ExpirationKey,
		jwt.NotBeforeKey,
		jwt.IssuedAtKey,
		jwt.JwtIDKey,
	}

	for _, claim := range reservedClaims {
		t.Run("NewToken/"+claim, func(t *testing.T) {
			_, err := cs.NewToken("subject", map[string]any{claim: "override"})
			if err == nil {
				t.Errorf("NewToken: got nil error, want ErrReservedClaim for %q", claim)
			}
			if !errors.Is(err, jwtutil.ErrReservedClaim) {
				t.Errorf("NewToken: got error %v, want ErrReservedClaim", err)
			}
		})

		t.Run("Issue/"+claim, func(t *testing.T) {
			rec := httptest.NewRecorder()
			err := cs.Issue(ctx, rec, "subject", map[string]any{claim: "override"})
			if err == nil {
				t.Errorf("Issue: got nil error, want ErrReservedClaim for %q", claim)
			}
			if !errors.Is(err, jwtutil.ErrReservedClaim) {
				t.Errorf("Issue: got error %v, want ErrReservedClaim", err)
			}
		})
	}

	// Custom claims that are not reserved should succeed.
	tok, err := cs.NewToken("subject", map[string]any{"custom": "value", "role": "admin"})
	if err != nil {
		t.Fatalf("NewToken with custom claims: %v", err)
	}
	var customVal any
	if err := tok.Get("custom", &customVal); err != nil || customVal != "value" {
		t.Errorf("custom claim: got %v, want value", customVal)
	}
}

// TestConfigTokenLifecycle covers the claims set on a token created via
// JWTSignerConfig.Builder and the conditions under which the corresponding
// Verifier rejects it.
func TestConfigTokenLifecycle(t *testing.T) {
	ctx, pubInfo := newED25519Key(t)
	sc := signerConfig()
	signer, err := jwtutil.SignerForKey(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
	}
	verifier, err := newTestVerifier(ctx, verifierConfigFor(sc), pubInfo)
	if err != nil {
		t.Fatalf("newTestVerifier: %v", err)
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

// TestConfigSubjectClaimsDuration covers JWTSignerConfig.Subject, Claims and
// Duration: Builder applies them automatically, a caller can still override
// subject and claims explicitly, and JWTValidatorConfig (whether derived via
// VerifierConfig or configured directly) enforces them.
// subjectClaimsSigner returns a context, a JWTSignerConfig with Subject,
// Duration and Claims all set, a Signer for it, the matching public keys.Info,
// and a verifier derived from it via VerifierConfig, for the tests below that
// exercise those three fields.
func subjectClaimsSigner(t *testing.T) (context.Context, jwtutil.JWTSignerConfig, jwtutil.Signer, keys.Info, *testVerifier) {
	t.Helper()
	ctx, pubInfo := newED25519Key(t)
	sc := signerConfig()
	sc.Subject = "configured-subject"
	sc.Duration = 30 * time.Minute
	sc.Claims = map[string]string{"role": "admin", "scope": "rw"}
	signer, err := jwtutil.SignerForKey(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
	}
	verifier, err := newTestVerifier(ctx, verifierConfigFor(sc), pubInfo)
	if err != nil {
		t.Fatalf("newTestVerifier: %v", err)
	}
	return ctx, sc, signer, pubInfo, verifier
}

// TestConfigBuilderAppliesSubjectClaimsDuration covers JWTSignerConfig.Subject,
// Duration and Claims: Builder(0) applies all three automatically, and the
// resulting token validates against a Verifier derived from the same
// configuration.
func TestConfigBuilderAppliesSubjectClaimsDuration(t *testing.T) {
	ctx, sc, signer, _, verifier := subjectClaimsSigner(t)
	tok, err := sc.Builder(0).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if sub, _ := tok.Subject(); sub != sc.Subject {
		t.Errorf("subject: got %q, want %q", sub, sc.Subject)
	}
	iat, _ := tok.IssuedAt()
	if exp, ok := tok.Expiration(); !ok || exp.Sub(iat) != sc.Duration {
		t.Errorf("expiration: got %v after issue (ok=%v), want %v", exp.Sub(iat), ok, sc.Duration)
	}
	for k, want := range sc.Claims {
		var got string
		if err := tok.Get(k, &got); err != nil || got != want {
			t.Errorf("claim %q: got %v, %v, want %q", k, got, err, want)
		}
	}

	signed, err := signer.Sign(ctx, tok)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := verifier.ParseAndValidate(ctx, signed); err != nil {
		t.Errorf("a token with the configured subject and claims must validate: %v", err)
	}
}

// TestConfigBuilderExpiresInOverridesDuration verifies that an explicit,
// positive expiresIn passed to Builder overrides the configured Duration.
func TestConfigBuilderExpiresInOverridesDuration(t *testing.T) {
	_, sc, _, _, _ := subjectClaimsSigner(t)
	tok, err := sc.Builder(time.Hour).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	iat, _ := tok.IssuedAt()
	if exp, ok := tok.Expiration(); !ok || exp.Sub(iat) != time.Hour {
		t.Errorf("expiration: got %v after issue (ok=%v), want 1h, not the configured %v", exp.Sub(iat), ok, sc.Duration)
	}
}

// TestConfigBuilderDefaultDuration verifies that if neither an explicit
// duration nor a configured Duration is provided, Builder defaults to 24h.
func TestConfigBuilderDefaultDuration(t *testing.T) {
	sc := signerConfig() // Duration is 0
	tok, err := sc.Builder(0).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	iat, _ := tok.IssuedAt()
	if exp, ok := tok.Expiration(); !ok || exp.Sub(iat) != 24*time.Hour {
		t.Errorf("expiration: got %v after issue (ok=%v), want 24h default", exp.Sub(iat), ok)
	}
}

// TestConfigBuilderSubjectOverride verifies that calling Subject on the
// jwt.Builder returned by Builder overrides the configured Subject.
func TestConfigBuilderSubjectOverride(t *testing.T) {
	_, sc, _, _, _ := subjectClaimsSigner(t)
	tok, err := sc.Builder(0).Subject("override-subject").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if sub, _ := tok.Subject(); sub != "override-subject" {
		t.Errorf("subject: got %q, want override-subject", sub)
	}
}

// TestConfigVerifierRejectsWrongSubjectOrClaim covers a Verifier derived via
// VerifierConfig rejecting a token whose subject or claim value does not
// match the configuration it was derived from.
func TestConfigVerifierRejectsWrongSubjectOrClaim(t *testing.T) {
	ctx, sc, signer, _, verifier := subjectClaimsSigner(t)
	sign := func(t *testing.T, subject, role string) []byte {
		t.Helper()
		tok, err := sc.Builder(0).Subject(subject).Claim("role", role).Build()
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		signed, err := signer.Sign(ctx, tok)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return signed
	}
	if _, err := verifier.ParseAndValidate(ctx, sign(t, "someone-else", "admin")); err == nil {
		t.Error("ParseAndValidate: got nil error, want the wrong subject to be rejected")
	}
	if _, err := verifier.ParseAndValidate(ctx, sign(t, sc.Subject, "user")); err == nil {
		t.Error("ParseAndValidate: got nil error, want the wrong role claim to be rejected")
	}
}

// TestConfigVerifierConfigOwnSubjectAndClaims covers a JWTValidatorConfig used
// directly (not derived from a JWTSignerConfig) enforcing its own Subject and
// Claims fields.
func TestConfigVerifierConfigOwnSubjectAndClaims(t *testing.T) {
	ctx, sc, signer, pubInfo, _ := subjectClaimsSigner(t)
	vc := jwtutil.JWTValidatorConfig{
		Issuer:   sc.Issuer,
		Audience: sc.Audience,
		Subject:  "direct-subject",
		Claims:   map[string]string{"role": "viewer"},
	}
	dv, err := newTestVerifier(ctx, vc, pubInfo)
	if err != nil {
		t.Fatalf("newTestVerifier: %v", err)
	}
	good, err := sc.Builder(time.Hour).Subject("direct-subject").Claim("role", "viewer").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	signedGood, err := signer.Sign(ctx, good)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := dv.ParseAndValidate(ctx, signedGood); err != nil {
		t.Errorf("ParseAndValidate: %v", err)
	}

	bad, err := sc.Builder(time.Hour).Subject("direct-subject").Claim("role", "admin").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	signedBad, err := signer.Sign(ctx, bad)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := dv.ParseAndValidate(ctx, signedBad); err == nil {
		t.Error("ParseAndValidate: got nil error, want the wrong role claim to be rejected")
	}
}

// TestConfigReservedClaims covers the guard, shared by JWTSignerConfig and
// JWTValidatorConfig, against configuring a Claims entry that shadows one of
// the standard claims already covered by a dedicated field or mechanism.
func TestConfigReservedClaims(t *testing.T) {
	sc := signerConfig()
	sc.Claims = map[string]string{"sub": "not allowed here"}
	if err := sc.Validate(); !errors.Is(err, jwtutil.ErrReservedClaim) {
		t.Errorf("JWTSignerConfig.Validate: got %v, want ErrReservedClaim", err)
	}

	vc := verifierConfigFor(sc)
	vc.Claims = map[string]string{"iss": "not allowed here"}
	if err := vc.Validate(); !errors.Is(err, jwtutil.ErrReservedClaim) {
		t.Errorf("JWTValidatorConfig.Validate: got %v, want ErrReservedClaim", err)
	}
}

// TestConfigValidateOptionsSkipsReservedClaims covers ValidateOptions' own
// defense against a Claims entry that shadows a reserved claim. Validate
// normally rejects such a configuration, but ValidateOptions can be called
// independently of Validate (as it is by, e.g., an issuer config's own
// ValidateOptions method), and a raw jwt.WithClaimValue for a reserved claim
// like exp would never match (exp is a time.Time, not a string), silently
// rejecting every otherwise-valid token.
func TestConfigValidateOptionsSkipsReservedClaims(t *testing.T) {
	sc := signerConfig()
	tok, err := sc.Builder(time.Hour).Subject("subject").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	vc := verifierConfigFor(sc)
	// Bypasses Validate, which would otherwise reject this.
	vc.Claims = map[string]string{"exp": "not-a-real-claim-value"}

	if err := jwt.Validate(tok, vc.ValidateOptions()...); err != nil {
		t.Errorf("ValidateOptions: got %v, want the bogus %q claim entry to be ignored", err, "exp")
	}
}

// TestConfigTokenRejection covers the tokens that a Verifier created from a
// JWTValidatorConfig rejects.
func TestConfigTokenRejection(t *testing.T) {
	ctx, pubInfo := newED25519Key(t)
	sc := signerConfig()
	signer, err := jwtutil.SignerForKey(ctx, testKeySpec)
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
	}
	verifier, err := newTestVerifier(ctx, verifierConfigFor(sc), pubInfo)
	if err != nil {
		t.Fatalf("newTestVerifier: %v", err)
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
	otherInfo, err := jwtutil.NewED25519KeyInfo(testKeyUser, "other-key")
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	otherCtx := keys.ContextWithKey(context.Background(), otherInfo)
	otherSigner, err := jwtutil.SignerForKey(otherCtx, otherInfo.KeySpec())
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
	}
	otherSigned, err := otherSigner.Sign(otherCtx, tok)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := verifier.Parse(ctx, otherSigned); err == nil {
		t.Error("Parse: got nil error, want a token signed by an unknown key to be rejected")
	}
}

// TestNewED25519KeyInfo covers the key pairs created for use with the
// configurations in this package, ie. that the key material they store can be
// used for both signing and verification.
func TestNewED25519KeyInfo(t *testing.T) {
	info, err := jwtutil.NewED25519KeyInfo(testKeyUser, testKeyID)
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	if got, want := info.KeySpec(), testKeySpec; got != want {
		t.Errorf("KeySpec: got %v, want %v", got, want)
	}
	var extra jwtutil.KeyExtra
	if err := info.UnmarshalExtra(&extra); err != nil {
		t.Fatalf("UnmarshalExtra: %v", err)
	}
	if got, want := extra.Algorithm, ed25519Algorithm; got != want {
		t.Errorf("algorithm: got %v, want %v", got, want)
	}
	pub, err := base64.StdEncoding.DecodeString(extra.PublicKey)
	if err != nil {
		t.Fatalf("decoding public key: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key: got %v bytes, want %v", len(pub), ed25519.PublicKeySize)
	}

	// The key is usable for signing and the public key stored with it verifies
	// what it signs.
	ctx := keys.ContextWithKey(context.Background(), info)
	signer, err := jwtutil.SignerForKey(ctx, info.KeySpec())
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
	}
	signed, err := signer.Sign(ctx, newConfigToken(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	validator, err := jwtutil.ValidatorForKeys(ctx, info)
	if err != nil {
		t.Fatalf("ValidatorForKeys: %v", err)
	}
	if _, err := validator.ParseAndValidate(ctx, signed); err != nil {
		t.Errorf("ParseAndValidate: %v", err)
	}
}

// TestNewED25519KeyInfoYAMLRoundTrip verifies that a keys.Info created by
// NewED25519KeyInfo, once marshalled to YAML as it would be when written to a
// keychain item and read back, still signs and, once resolved from the
// round-tripped store, still verifies correctly.
func TestNewED25519KeyInfoYAMLRoundTrip(t *testing.T) {
	info, err := jwtutil.NewED25519KeyInfo(testKeyUser, testKeyID)
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	ctx := keys.ContextWithKey(context.Background(), info)
	signer, err := jwtutil.SignerForKey(ctx, info.KeySpec())
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
	}
	signed, err := signer.Sign(ctx, newConfigToken(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	buf, err := yaml.Marshal([]keys.Info{info})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	store := keys.NewInMemoryKeyStore()
	if err := yaml.Unmarshal(buf, store); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	rctx := keys.ContextWithKeyStore(context.Background(), store)
	if _, err := jwtutil.SignerForKey(rctx, info.KeySpec()); err != nil {
		t.Errorf("SignerForKey after a YAML round trip: %v", err)
	}

	// A verification key resolved from the round-tripped store still
	// validates.
	spec := info.KeySpec()
	roundTripped, ok := store.Get(spec.User, spec.ID)
	if !ok {
		t.Fatalf("key not found in round-tripped store")
	}
	validator, err := jwtutil.ValidatorForKeys(rctx, roundTripped)
	if err != nil {
		t.Fatalf("ValidatorForKeys: %v", err)
	}
	if _, err := validator.ParseAndValidate(rctx, signed); err != nil {
		t.Errorf("ParseAndValidate after a YAML round trip: %v", err)
	}
}

// TestKeyLookupByID covers a key spec that does not name a user, which
// matches a key with the same id belonging to any user provided that it is
// unambiguous, when looking up a signing key from the context-based key store
// (see SignerForKey). Verification keys are supplied directly rather than
// looked up this way, so no equivalent ambiguity exists for them.
func TestKeyLookupByID(t *testing.T) {
	info, err := jwtutil.NewED25519KeyInfo(testKeyUser, testKeyID)
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	ctx := keys.ContextWithKey(context.Background(), info)

	// The user is not named by the spec but the key is the only one with that
	// id.
	byID := keys.KeySpec{ID: testKeyID}
	if _, err := jwtutil.SignerForKey(ctx, byID); err != nil {
		t.Errorf("SignerForKey: %v", err)
	}

	// A second key with the same id makes the spec ambiguous: it is reported
	// the same way as a key that does not exist at all.
	other, err := jwtutil.NewED25519KeyInfo("another-user", testKeyID)
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	ctx = keys.ContextWithKey(ctx, other)
	if _, err := jwtutil.SignerForKey(ctx, byID); !errors.Is(err, jwtutil.ErrKeyNotFound) {
		t.Errorf("SignerForKey: got %v, want ErrKeyNotFound (ambiguous id)", err)
	}

	// A spec naming a user that holds no such key is not found.
	if _, err := jwtutil.SignerForKey(ctx, keys.KeySpec{ID: testKeyID, User: "nobody"}); !errors.Is(err, jwtutil.ErrKeyNotFound) {
		t.Errorf("SignerForKey: got %v, want ErrKeyNotFound", err)
	}
}

// TestUnsupportedAlgorithm covers the error reported when a key names an
// algorithm that has no registered JWKKey implementation.
func TestUnsupportedAlgorithm(t *testing.T) {
	info, err := jwtutil.NewED25519KeyInfo(testKeyUser, testKeyID)
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	info.WithExtra(jwtutil.KeyExtra{Algorithm: "RS256"})
	ctx := keys.ContextWithKey(context.Background(), info)

	_, err = jwtutil.NewSignerFromKeyInfo(ctx, info)
	if err == nil || !strings.Contains(err.Error(), `unsupported algorithm: "RS256"`) {
		t.Errorf("NewSignerFromKeyInfo: got %v, want an unsupported algorithm error", err)
	}
	if _, err := jwtutil.PublicKeyFromKeyInfo(ctx, info); err == nil {
		t.Error("PublicKeyFromKeyInfo: got nil error, want an unsupported algorithm error")
	}
	if _, err := jwtutil.SignerForKey(ctx, info.KeySpec()); err == nil {
		t.Error("SignerForKey: got nil error, want an unsupported algorithm error")
	}
}

// TestPublicKeyFromKeyInfoErrors covers the malformed public_key values
// rejected by PublicKeyFromKeyInfo (and hence by the ED25519 JWKKey
// implementation it dispatches to).
func TestPublicKeyFromKeyInfoErrors(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		extra any
	}{
		{"wrong extra type", map[string]any{"algorithm": ed25519Algorithm, "public_key": "x"}},
		{"public_key not base64", jwtutil.KeyExtra{Algorithm: ed25519Algorithm, PublicKey: "not base64!"}},
		{"public_key wrong length", jwtutil.KeyExtra{
			Algorithm: ed25519Algorithm,
			PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 16)),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := keys.NewInfo(testKeyUser, testKeyID, nil)
			info.WithExtra(tc.extra)
			if _, err := jwtutil.PublicKeyFromKeyInfo(ctx, info); err == nil {
				t.Error("PublicKeyFromKeyInfo: got nil error, want the key to be rejected")
			}
		})
	}
}

// TestPublicKeySetsKeyID verifies that PublicKeyFromKeyInfo sets the key ID
// on the returned jwk.Key if specified in info.KeySpec().ID.
func TestPublicKeySetsKeyID(t *testing.T) {
	ctx := context.Background()
	info, err := jwtutil.NewED25519KeyInfo(testKeyUser, testKeyID)
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	pub, err := jwtutil.PublicKeyFromKeyInfo(ctx, info)
	if err != nil {
		t.Fatalf("PublicKeyFromKeyInfo: %v", err)
	}
	kid, ok := pub.KeyID()
	if !ok || kid != testKeyID {
		t.Errorf("pub.KeyID() = %q (ok=%v), want %q", kid, ok, testKeyID)
	}
}

// TestPublicKeyFallbackFromPrivateToken verifies that PublicKeyFromKeyInfo
// can derive the public key from the private key token if extra.PublicKey is empty.
func TestPublicKeyFallbackFromPrivateToken(t *testing.T) {
	ctx := context.Background()
	info, err := jwtutil.NewED25519KeyInfo(testKeyUser, testKeyID)
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	// Omit public key from extra.
	info.WithExtra(jwtutil.KeyExtra{Algorithm: ed25519Algorithm})

	pub, err := jwtutil.PublicKeyFromKeyInfo(ctx, info)
	if err != nil {
		t.Fatalf("PublicKeyFromKeyInfo fallback failed: %v", err)
	}
	kid, ok := pub.KeyID()
	if !ok || kid != testKeyID {
		t.Errorf("pub.KeyID() = %q (ok=%v), want %q", kid, ok, testKeyID)
	}

	// Verify a token signed by the signer can be verified by the derived public key.
	signer, err := jwtutil.NewSignerFromKeyInfo(ctx, info)
	if err != nil {
		t.Fatalf("NewSignerFromKeyInfo: %v", err)
	}
	token, err := signerConfig().Builder(time.Hour).Subject("alice").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	signed, err := signer.Sign(ctx, token)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	validator := jwtutil.NewValidator(set)
	parsed, err := validator.ParseAndValidate(ctx, signed)
	if err != nil {
		t.Fatalf("ParseAndValidate failed: %v", err)
	}
	sub, _ := parsed.Subject()
	if sub != "alice" {
		t.Errorf("subject = %q, want alice", sub)
	}
}

// TestDecodeBase64Whitespace verifies that key material containing whitespace or
// newlines (e.g. from YAML block scalars) decodes properly.
func TestDecodeBase64Whitespace(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("failed to derive public key")
	}
	encodedPriv := base64.StdEncoding.EncodeToString(priv)
	wrappedPriv := encodedPriv[:len(encodedPriv)/2] + "\n" + encodedPriv[len(encodedPriv)/2:]
	info := keys.NewInfo(testKeyID, testKeyUser, []byte(" \n\t"+wrappedPriv+"\n\r "))
	info.WithExtra(jwtutil.KeyExtra{
		Algorithm: ed25519Algorithm,
		PublicKey: " \n" + base64.StdEncoding.EncodeToString(pub) + " \n",
	})
	ctx := keys.ContextWithKey(context.Background(), info)

	signer, err := jwtutil.SignerForKey(ctx, info.KeySpec())
	if err != nil {
		t.Fatalf("SignerForKey: %v", err)
	}
	signed, err := signer.Sign(ctx, newConfigToken(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	validator, err := jwtutil.ValidatorForKeys(ctx, info)
	if err != nil {
		t.Fatalf("ValidatorForKeys: %v", err)
	}
	if _, err := validator.ParseAndValidate(ctx, signed); err != nil {
		t.Errorf("ParseAndValidate: %v", err)
	}
}

// TestEdDSAAlgorithmAlias verifies that algorithm name "EdDSA" is recognized by
// algoRegistry as an alias for ED25519.
func TestEdDSAAlgorithmAlias(t *testing.T) {
	info, err := jwtutil.NewED25519KeyInfo(testKeyUser, testKeyID)
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	info.WithExtra(jwtutil.KeyExtra{
		Algorithm: "EdDSA",
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
	})
	ctx := keys.ContextWithKey(context.Background(), info)
	if _, err := jwtutil.PublicKeyFromKeyInfo(ctx, info); err != nil {
		t.Errorf("PublicKeyFromKeyInfo with EdDSA: %v", err)
	}
}

// TestKeySetForKeys covers KeySetForKeys directly: the returned jwk.Set
// contains exactly the public keys supplied, each keyed by its ID so that
// jwt.WithKeySet can select it when verifying a token, and invalid input (no
// keys, an empty ID, or a duplicate ID) is rejected.
func TestKeySetForKeys(t *testing.T) {
	ctx := context.Background()

	t.Run("no keys", func(t *testing.T) {
		if _, err := jwtutil.KeySetForKeys(ctx); err == nil {
			t.Error("KeySetForKeys: got nil error, want at least one key to be required")
		}
	})

	t.Run("empty key ID", func(t *testing.T) {
		info := newKeyInfo(keys.KeySpec{User: "user", ID: ""}, nil, jwtutil.KeyExtra{
			Algorithm: ed25519Algorithm,
			PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		})
		if _, err := jwtutil.KeySetForKeys(ctx, info); err == nil {
			t.Error("KeySetForKeys: got nil error, want empty key ID to be rejected")
		}
	})

	t.Run("duplicate key ID", func(t *testing.T) {
		mk := func(user string) keys.Info {
			info, err := jwtutil.NewED25519KeyInfo(user, "same-key-id")
			if err != nil {
				t.Fatalf("NewED25519KeyInfo: %v", err)
			}
			return jwtutil.CloneKeyInfoForPublicKey(info)
		}
		if _, err := jwtutil.KeySetForKeys(ctx, mk("user1"), mk("user2")); err == nil {
			t.Error("KeySetForKeys: got nil error, want duplicate key ID to be rejected")
		}
	})

	t.Run("single key", func(t *testing.T) {
		sctx, pubInfo := newED25519Key(t)
		set, err := jwtutil.KeySetForKeys(ctx, pubInfo)
		if err != nil {
			t.Fatalf("KeySetForKeys: %v", err)
		}
		if got, want := set.Len(), 1; got != want {
			t.Errorf("set length: got %v, want %v", got, want)
		}
		// The set verifies a token signed by the corresponding private key.
		signer, err := jwtutil.SignerForKey(sctx, testKeySpec)
		if err != nil {
			t.Fatalf("SignerForKey: %v", err)
		}
		signed, err := signer.Sign(sctx, newConfigToken(t))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, err := jwtutil.NewValidator(set).ParseAndValidate(ctx, signed); err != nil {
			t.Errorf("ParseAndValidate: %v", err)
		}
	})

	t.Run("multiple keys", func(t *testing.T) {
		infoA, err := jwtutil.NewED25519KeyInfo(testKeyUser, "key-a")
		if err != nil {
			t.Fatalf("NewED25519KeyInfo: %v", err)
		}
		infoB, err := jwtutil.NewED25519KeyInfo(testKeyUser, "key-b")
		if err != nil {
			t.Fatalf("NewED25519KeyInfo: %v", err)
		}
		set, err := jwtutil.KeySetForKeys(ctx,
			jwtutil.CloneKeyInfoForPublicKey(infoA), jwtutil.CloneKeyInfoForPublicKey(infoB))
		if err != nil {
			t.Fatalf("KeySetForKeys: %v", err)
		}
		if got, want := set.Len(), 2; got != want {
			t.Errorf("set length: got %v, want %v", got, want)
		}
	})
}
