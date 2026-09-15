// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"cloudeng.io/webapp/cookies"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ErrNoCookie is returned when a request does not carry the cookie named by a
// JWTCookieVerifierConfig.
var ErrNoCookie = errors.New("no such cookie")

// ErrReservedClaim is returned when a caller attempts to set a reserved JWT claim.
var ErrReservedClaim = errors.New("reserved claim")

func isReservedClaim(key string) bool {
	switch key {
	case jwt.AudienceKey, jwt.ExpirationKey, jwt.IssuedAtKey, jwt.IssuerKey,
		jwt.JwtIDKey, jwt.NotBeforeKey, jwt.SubjectKey:
		return true
	default:
		return false
	}
}

// CookieSigner issues JWTs carried in a named, secure, cookie as specified by a
// JWTCookieSignerConfig. It is also a Validator for the tokens that it issues,
// applying the same issuer, audience and clock skew checks as the
// CookieVerifier created from VerifierConfig.
type CookieSigner struct {
	Signer
	verifier *Verifier
	cfg      JWTCookieSignerConfig
}

// NewCookieSigner returns a CookieSigner for the signing key named by the
// configuration. The key is obtained as per JWTSignerConfig.NewSigner.
func (c JWTCookieSignerConfig) NewCookieSigner(ctx context.Context) (*CookieSigner, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	c.ScopeAndDuration = c.SetDefaults("", "/", 0)
	signer, err := c.NewSigner(ctx)
	if err != nil {
		return nil, err
	}
	pub, err := signer.PublicKey()
	if err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		return nil, err
	}
	opts := c.JWTSignerConfig.VerifierConfig().ValidateOptions()
	if c.ValidationTimeSkew > 0 {
		opts = append(opts, jwt.WithAcceptableSkew(c.ValidationTimeSkew))
	}
	return &CookieSigner{
		Signer:   signer,
		verifier: newVerifier(set, opts),
		cfg:      c,
	}, nil
}

// VerifierConfig returns the cookie verifier configuration implied by the
// cookie signer configuration, ie. the same cookie name, scope, duration,
// time skew, issuer and audience with the signing key as the sole verification
// key. It is intended for use by a service that both issues and verifies its
// own cookies.
func (c JWTCookieSignerConfig) VerifierConfig() JWTCookieVerifierConfig {
	return JWTCookieVerifierConfig{
		Name:               c.Name,
		ValidationTimeSkew: c.ValidationTimeSkew,
		ScopeAndDuration:   c.SetDefaults("", "/", 0),
		JWTVerifierConfig:  c.JWTSignerConfig.VerifierConfig(),
	}
}

// Name returns the name of the cookie that tokens are issued in.
func (cs *CookieSigner) Name() string {
	return cs.cfg.Name
}

// NewToken returns a token for subject with the issuer, audience and duration
// specified by the configuration along with any additional claims supplied.
// If claims contains any reserved standard JWT claims (iss, sub, aud, exp, nbf,
// iat, jti), ErrReservedClaim is returned.
func (cs *CookieSigner) NewToken(subject string, claims map[string]any) (jwt.Token, error) {
	for k := range claims {
		if isReservedClaim(k) {
			return nil, fmt.Errorf("%w: %q cannot be overridden", ErrReservedClaim, k)
		}
	}
	builder := cs.cfg.Builder(cs.cfg.Duration)
	if subject != "" {
		builder.Subject(subject)
	}
	for k, v := range claims {
		builder.Claim(k, v)
	}
	return builder.Build()
}

// Cookie signs token and returns a cookie containing it that is scoped and
// expires as specified by the configuration.
func (cs *CookieSigner) Cookie(ctx context.Context, token jwt.Token) (*http.Cookie, error) {
	signed, err := cs.Sign(ctx, token)
	if err != nil {
		return nil, err
	}
	ck := cs.cfg.Cookie(string(signed)) //nolint:gosec // G124: cookies.ScopeAndDuration.Cookie sets Secure, HttpOnly and SameSiteStrictMode.
	ck.Name = cs.cfg.Name
	if cs.cfg.Duration > 0 {
		ck.MaxAge = int(cs.cfg.Duration.Seconds())
	}
	return ck, nil
}

// SetCookie signs token and sets the resulting cookie on rw.
func (cs *CookieSigner) SetCookie(ctx context.Context, rw http.ResponseWriter, token jwt.Token) error {
	ck, err := cs.Cookie(ctx, token)
	if err != nil {
		return err
	}
	cookies.Secure(cs.cfg.Name).Set(rw, ck)
	return nil
}

// Issue creates, signs and sets a cookie containing a token for subject and
// claims as per NewToken and SetCookie.
func (cs *CookieSigner) Issue(ctx context.Context, rw http.ResponseWriter, subject string, claims map[string]any) error {
	token, err := cs.NewToken(subject, claims)
	if err != nil {
		return err
	}
	return cs.SetCookie(ctx, rw, token)
}

// Parse verifies the signature of token and returns it without validating any
// of its claims, as per Verifier.Parse.
func (cs *CookieSigner) Parse(ctx context.Context, token []byte) (jwt.Token, error) {
	return cs.verifier.Parse(ctx, token)
}

// Validate validates token using the issuer, audience and clock skew specified
// by the configuration followed by any additional validators supplied.
func (cs *CookieSigner) Validate(ctx context.Context, token jwt.Token, validators ...jwt.ValidateOption) error {
	return cs.verifier.Validate(ctx, token, validators...)
}

// ParseAndValidate parses and validates token as per Parse and Validate.
func (cs *CookieSigner) ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error) {
	return cs.verifier.ParseAndValidate(ctx, token, validators...)
}

// CookieVerifier verifies JWTs carried in a named cookie as specified by a
// JWTCookieVerifierConfig.
type CookieVerifier struct {
	*Verifier
	cfg JWTCookieVerifierConfig
}

// NewCookieVerifier returns a CookieVerifier for the verification keys named by
// the configuration. The keys are obtained as per JWTVerifierConfig.NewValidator.
func (c JWTCookieVerifierConfig) NewCookieVerifier(ctx context.Context) (*CookieVerifier, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	c.ScopeAndDuration = c.SetDefaults("", "/", 0)
	verifier, err := c.newVerifier(ctx, c.ValidationTimeSkew)
	if err != nil {
		return nil, err
	}
	return &CookieVerifier{
		Verifier: verifier,
		cfg:      c,
	}, nil
}

// Name returns the name of the cookie that tokens are read from.
func (cv *CookieVerifier) Name() string {
	return cv.cfg.Name
}

// ValidateRequest reads the configured cookie from r and parses and validates
// the token that it contains. ErrNoCookie is returned if the request does not
// carry the cookie.
func (cv *CookieVerifier) ValidateRequest(ctx context.Context, r *http.Request, validators ...jwt.ValidateOption) (jwt.Token, error) {
	value, ok := cookies.Secure(cv.cfg.Name).Read(r)
	if !ok {
		return nil, fmt.Errorf("%w: %v", ErrNoCookie, cv.cfg.Name)
	}
	return cv.ParseAndValidate(ctx, []byte(value), validators...)
}

// ClearCookie requests the removal of the cookie by the client.
func (cv *CookieVerifier) ClearCookie(rw http.ResponseWriter) {
	ck := cv.cfg.Cookie("") //nolint:gosec // G124: the cookie is being deleted.
	ck.Expires = time.Time{}
	ck.MaxAge = -1
	cookies.Secure(cv.cfg.Name).Set(rw, ck)
}
