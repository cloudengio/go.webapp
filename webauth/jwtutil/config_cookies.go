// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/webapp/cookies"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ErrNoCookie is returned when a request does not carry the cookie named by a
// JWTCookieValidatorConfig.
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

// setNamedCookie sets ck under name, honoring insecure: by default the cookie
// is set securely (HttpOnly, Secure, SameSiteStrictMode, matching
// cookies.ScopeAndDuration.Cookie's own defaults); when insecure is true,
// those attributes are cleared from ck first so that it is sent over plain
// HTTP too.
func setNamedCookie(rw http.ResponseWriter, name string, insecure bool, ck *http.Cookie) { //nolint:gosec // G124: insecure is an explicit, documented opt-in.
	if insecure {
		ck.Secure = false
		ck.HttpOnly = false
		ck.SameSite = http.SameSiteDefaultMode
		cookies.T(name).Set(rw, ck)
		return
	}
	cookies.Secure(name).Set(rw, ck)
}

// readNamedCookie reads the cookie named name from r; insecure only affects
// which cookies.T-like type is used, which does not itself change how a
// cookie is read.
func readNamedCookie(r *http.Request, name string, insecure bool) (string, bool) {
	if insecure {
		return cookies.T(name).Read(r)
	}
	return cookies.Secure(name).Read(r)
}

// CookieSigner issues JWTs carried in a named cookie as specified by a
// JWTCookieSignerConfig. It only signs; a service that also needs to verify
// the cookies it issues should build a separate CookieValidator from the
// matching JWTCookieValidatorConfig (see ValidatorConfig).
type CookieSigner struct {
	Signer
	cfg JWTCookieSignerConfig
}

// NewCookieSigner returns a CookieSigner that signs with the key identified
// by spec, obtained as per SignerForKey.
func (c JWTCookieSignerConfig) NewCookieSigner(ctx context.Context, spec keys.KeySpec) (*CookieSigner, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	c.ScopeAndDuration = c.SetDefaults("", "/", 0)
	if c.Duration == 0 {
		c.Duration = c.JWTCookieConfig.Duration
	}
	signer, err := SignerForKey(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &CookieSigner{
		Signer: signer,
		cfg:    c,
	}, nil
}

// ValidatorConfig returns the cookie validator configuration implied by the
// cookie signer configuration, ie. the same cookie name, scope, duration,
// insecure setting, issuer, audience, subject and claims. Its
// ValidationTimeSkew is left at zero: a signer validating tokens that it
// issued itself has no need to allow for clock drift between machines. It is
// intended for use by a service that both issues and verifies its own
// cookies; the verification key(s) must still be supplied separately when
// constructing the CookieValidator, since neither config carries key material.
func (c JWTCookieSignerConfig) ValidatorConfig() JWTCookieValidatorConfig {
	return JWTCookieValidatorConfig{
		JWTCookieConfig: c.JWTCookieConfig,
		JWTValidatorConfig: JWTValidatorConfig{
			Issuer:   c.Issuer,
			Audience: slices.Clone(c.Audience),
			Subject:  c.Subject,
			Claims:   maps.Clone(c.Claims),
		},
	}
}

// VerifierConfig is an alias for ValidatorConfig.
func (c JWTCookieSignerConfig) VerifierConfig() JWTCookieValidatorConfig {
	return c.ValidatorConfig()
}

// Name returns the name of the cookie that tokens are issued in.
func (cs *CookieSigner) Name() string {
	return cs.cfg.Name
}

// NewToken returns a token for subject with the issuer, audience, subject,
// claims and duration specified by the configuration (see
// JWTSignerConfig.Builder), along with any additional claims supplied here.
// subject and claims, if not empty, override the configured ones. If claims
// contains any reserved standard JWT claims (iss, sub, aud, exp, nbf, iat,
// jti), ErrReservedClaim is returned.
func (cs *CookieSigner) NewToken(subject string, claims map[string]any) (jwt.Token, error) {
	for k := range claims {
		if isReservedClaim(k) {
			return nil, fmt.Errorf("%w: %q cannot be overridden", ErrReservedClaim, k)
		}
	}
	// 0 lets Builder apply its own configured Duration as the expiration.
	builder := cs.cfg.Builder(0)
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
	// The cookie's own lifetime (JWTCookieConfig.Duration, via
	// ScopeAndDuration) is distinct from, and must be named explicitly to
	// avoid being shadowed by, the JWT's own validity duration
	// (JWTSignerConfig.Duration): JWTCookieSignerConfig embeds both, and the
	// latter is shallower so it wins any unqualified cs.cfg.Duration.
	if d := cs.cfg.JWTCookieConfig.Duration; d > 0 {
		ck.MaxAge = int(d.Seconds())
	}
	return ck, nil
}

// SetCookie signs token and sets the resulting cookie on rw.
func (cs *CookieSigner) SetCookie(ctx context.Context, rw http.ResponseWriter, token jwt.Token) error {
	ck, err := cs.Cookie(ctx, token)
	if err != nil {
		return err
	}
	setNamedCookie(rw, cs.cfg.Name, cs.cfg.Insecure, ck)
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

// CookieValidator validates JWTs carried in a named cookie as specified by a
// JWTCookieValidatorConfig.
type CookieValidator struct {
	set  jwk.Set
	opts []jwt.ValidateOption
	cfg  JWTCookieValidatorConfig
}

// CookieVerifier is an alias for CookieValidator.
type CookieVerifier = CookieValidator

// NewCookieValidator returns a CookieValidator that validates tokens against
// verificationKeys, obtained as per KeySetForKeys.
func (c JWTCookieValidatorConfig) NewCookieValidator(ctx context.Context, verificationKeys ...keys.Info) (*CookieValidator, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	c.ScopeAndDuration = c.SetDefaults("", "/", 0)
	set, err := KeySetForKeys(ctx, verificationKeys...)
	if err != nil {
		return nil, err
	}
	opts := c.ValidateOptions()
	if c.ValidationTimeSkew > 0 {
		opts = append(opts, jwt.WithAcceptableSkew(c.ValidationTimeSkew))
	}
	return &CookieValidator{
		set:  set,
		opts: opts,
		cfg:  c,
	}, nil
}

// NewCookieVerifier is an alias for NewCookieValidator.
func (c JWTCookieValidatorConfig) NewCookieVerifier(ctx context.Context, verificationKeys ...keys.Info) (*CookieVerifier, error) {
	return c.NewCookieValidator(ctx, verificationKeys...)
}

// Name returns the name of the cookie that tokens are read from.
func (cv *CookieValidator) Name() string {
	return cv.cfg.Name
}

// Parse verifies the signature of token and returns it without validating any
// of its claims, which is left to Validate so that the options implied by the
// configuration, including any allowance for clock skew, are applied.
func (cv *CookieValidator) Parse(_ context.Context, token []byte) (jwt.Token, error) {
	return jwt.Parse(token, jwt.WithKeySet(cv.set), jwt.WithValidate(false))
}

// Validate validates token using the configured issuer, audience and clock
// skew followed by any additional validators supplied.
func (cv *CookieValidator) Validate(_ context.Context, token jwt.Token, validators ...jwt.ValidateOption) error {
	return jwt.Validate(token, append(slices.Clone(cv.opts), validators...)...)
}

// ParseAndValidate parses and validates token as per Parse and Validate.
func (cv *CookieValidator) ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error) {
	parsed, err := cv.Parse(ctx, token)
	if err != nil {
		return nil, err
	}
	if err := cv.Validate(ctx, parsed, validators...); err != nil {
		return nil, err
	}
	return parsed, nil
}

// ValidateRequest reads the configured cookie from r and parses and validates
// the token that it contains. ErrNoCookie is returned if the request does not
// carry the cookie.
func (cv *CookieValidator) ValidateRequest(ctx context.Context, r *http.Request, validators ...jwt.ValidateOption) (jwt.Token, error) {
	value, ok := readNamedCookie(r, cv.cfg.Name, cv.cfg.Insecure)
	if !ok {
		return nil, fmt.Errorf("%w: %v", ErrNoCookie, cv.cfg.Name)
	}
	return cv.ParseAndValidate(ctx, []byte(value), validators...)
}

// ClearCookie requests the removal of the cookie by the client.
func (cv *CookieValidator) ClearCookie(rw http.ResponseWriter) {
	ck := cv.cfg.Cookie("") //nolint:gosec // G124: the cookie is being deleted.
	ck.Expires = time.Time{}
	ck.MaxAge = -1
	setNamedCookie(rw, cv.cfg.Name, cv.cfg.Insecure, ck)
}
