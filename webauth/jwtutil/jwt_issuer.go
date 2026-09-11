// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cloudeng.io/webapp/cookies"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// JWTIssuerOption configures a JWTIssuer handler.
type JWTIssuerOption func(*jwtIssuerOptions)

type jwtIssuerOptions struct {
	subject           string
	issuer            string
	audience          []string
	expiration        time.Duration
	notBeforeOffset   time.Duration
	notBeforeSet      bool
	claims            map[string]any
	cookieName        string
	cookieSecure      bool
	cookiePath        string
	cookieDomain      string
	cookieSameSite    http.SameSite
	hasSecureCookie   bool
	hasInsecureCookie bool
	cookieCount       int
	direct            bool
	directSet         bool
	json              bool
	redirectURL       string
	redirectParam     string
	allowedRedirects  []string
	logger            *slog.Logger
}

func defaultJWTIssuerOptions() jwtIssuerOptions {
	return jwtIssuerOptions{
		expiration:     time.Hour,
		cookieSecure:   true,
		cookiePath:     "/",
		cookieSameSite: http.SameSiteStrictMode,
		claims:         make(map[string]any),
		logger:         slog.New(slog.DiscardHandler),
	}
}

// WithSubject sets the "sub" claim of issued tokens.
func WithSubject(subject string) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.subject = subject
	}
}

// WithIssuer sets the "iss" claim of issued tokens.
func WithIssuer(issuer string) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.issuer = issuer
	}
}

// WithAudience sets the "aud" claim of issued tokens.
func WithAudience(audience ...string) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.audience = append([]string(nil), audience...)
	}
}

// WithExpiration sets the token validity duration relative to its issuance time.
// Defaults to 1 hour.
func WithExpiration(d time.Duration) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.expiration = d
	}
}

// WithExpiresIn is an alias for WithExpiration.
func WithExpiresIn(d time.Duration) JWTIssuerOption {
	return WithExpiration(d)
}

// WithNotBefore sets the "nbf" claim offset relative to token issuance time.
func WithNotBefore(offset time.Duration) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.notBeforeOffset = offset
		o.notBeforeSet = true
	}
}

// WithClaim adds or replaces a custom claim in issued tokens.
func WithClaim(key string, value any) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.claims[key] = value
	}
}

// WithClaims adds or replaces multiple custom claims in issued tokens.
func WithClaims(claims map[string]any) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		maps.Copy(o.claims, claims)
	}
}

// WithCookie configures the handler to set the token in a secure HTTP cookie
// with the given name (alias for WithSecureCookie).
func WithCookie(name string) JWTIssuerOption {
	return WithSecureCookie(name)
}

// WithSecureCookie configures the handler to set the token in a secure HTTP
// cookie with the given name. Only one cookie option may be specified.
func WithSecureCookie(name string) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.cookieName = name
		o.cookieSecure = true
		o.cookieSameSite = http.SameSiteStrictMode
		o.hasSecureCookie = true
		o.cookieCount++
	}
}

// WithInsecureCookie configures the handler to set the token in a plain HTTP cookie
// without forcing Secure and SameSiteStrictMode attributes. A subsequent
// WithCookieSameSite option can be used to set a specific SameSite mode.
// Only one cookie option may be specified.
func WithInsecureCookie(name string) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.cookieName = name
		o.cookieSecure = false
		o.cookieSameSite = 0
		o.hasInsecureCookie = true
		o.cookieCount++
	}
}

// WithCookiePath sets the Path attribute for issued cookies. Defaults to "/".
func WithCookiePath(path string) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.cookiePath = path
	}
}

// WithCookieDomain sets the Domain attribute for issued cookies.
func WithCookieDomain(domain string) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.cookieDomain = domain
	}
}

// WithCookieSameSite sets the SameSite attribute for issued cookies.
func WithCookieSameSite(sameSite http.SameSite) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.cookieSameSite = sameSite
	}
}

// WithDirect explicitly enables or disables writing the token in the HTTP response
// body. If no cookie is configured, direct issuance defaults to true.
func WithDirect(enable bool) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.direct = enable
		o.directSet = true
	}
}

// WithJSON configures direct token issuance to output JSON format ({"token": "..."}).
func WithJSON(enable bool) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.json = enable
	}
}

// WithRedirect configures an HTTP redirect destination after cookie issuance.
func WithRedirect(url string) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.redirectURL = url
	}
}

// WithRedirectQueryParam configures the name of a query parameter (e.g. "redirect")
// that specifies the redirect URL after cookie issuance. The destination is
// restricted to same-origin relative paths (e.g. "/dashboard") unless explicitly
// permitted by WithAllowedRedirects. If the parameter contains an untrusted or
// invalid redirect destination, it is ignored and the handler falls back to
// WithRedirect (if configured).
func WithRedirectQueryParam(paramName string) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.redirectParam = paramName
	}
}

// WithAllowedRedirects configures an allowlist of permitted redirect destinations
// (URLs or origins) for the redirect query parameter.
func WithAllowedRedirects(allowed ...string) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		o.allowedRedirects = append(o.allowedRedirects, allowed...)
	}
}

// WithRedirectAllowlist is an alias for WithAllowedRedirects.
func WithRedirectAllowlist(allowed ...string) JWTIssuerOption {
	return WithAllowedRedirects(allowed...)
}

// WithLogger sets the structured logger for issuance events and errors.
func WithLogger(logger *slog.Logger) JWTIssuerOption {
	return func(o *jwtIssuerOptions) {
		if logger != nil {
			o.logger = logger
		}
	}
}

type jwtIssuerHandler struct {
	signer Signer
	opts   jwtIssuerOptions
}

// JWTIssuer returns an http.Handler that issues JWTs using signer according to
// the configured options. It runs without authentication, issuing tokens to any
// client that accesses it.
func JWTIssuer(signer Signer, opts ...JWTIssuerOption) (http.Handler, error) {
	return NewJWTIssuer(signer, opts...)
}

// JWTIssuerMust creates a new JWTIssuer handler or panics on error.
func JWTIssuerMust(signer Signer, opts ...JWTIssuerOption) http.Handler {
	return NewJWTIssuerMust(signer, opts...)
}

// NewJWTIssuer creates a new http.Handler that issues JWTs using signer according
// to the configured options. It returns an error if signer is nil or if more than
// one cookie option is specified.
func NewJWTIssuer(signer Signer, opts ...JWTIssuerOption) (http.Handler, error) {
	if signer == nil {
		return nil, fmt.Errorf("jwtutil.NewJWTIssuer: signer cannot be nil")
	}
	o := defaultJWTIssuerOptions()
	for _, opt := range opts {
		opt(&o)
	}
	if o.cookieCount > 1 {
		if o.hasSecureCookie && o.hasInsecureCookie {
			return nil, fmt.Errorf("jwtutil.NewJWTIssuer: cannot specify both secure and insecure cookie options")
		}
		return nil, fmt.Errorf("jwtutil.NewJWTIssuer: only one cookie option may be specified (found %d)", o.cookieCount)
	}
	if !o.directSet && o.cookieName == "" {
		o.direct = true
	}
	return &jwtIssuerHandler{
		signer: signer,
		opts:   o,
	}, nil
}

// NewJWTIssuerMust creates a new http.Handler that issues JWTs using signer,
// and panics if an error occurs.
func NewJWTIssuerMust(signer Signer, opts ...JWTIssuerOption) http.Handler {
	h, err := NewJWTIssuer(signer, opts...)
	if err != nil {
		panic(err)
	}
	return h
}

func (h *jwtIssuerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if h.signer == nil {
		h.opts.logger.ErrorContext(r.Context(), "jwt issuer: signer is nil")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	tokenBytes, err := h.createToken(r)
	if err != nil {
		h.opts.logger.ErrorContext(r.Context(), "jwt issuer: failed to issue token", "error", err)
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	tokenStr := string(tokenBytes)

	if h.opts.cookieName != "" {
		h.setCookie(w, tokenStr)
	}

	if dest := h.getRedirectURL(r); dest != "" {
		http.Redirect(w, r, dest, http.StatusSeeOther) //nolint:gosec // G710: intentional redirect destination per handler configuration.
		return
	}

	if h.opts.direct {
		h.writeDirect(w, r, tokenStr)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *jwtIssuerHandler) createToken(r *http.Request) ([]byte, error) {
	now := time.Now()
	builder := jwt.NewBuilder().IssuedAt(now)

	if h.opts.subject != "" {
		builder.Subject(h.opts.subject)
	}
	if h.opts.issuer != "" {
		builder.Issuer(h.opts.issuer)
	}
	if len(h.opts.audience) > 0 {
		builder.Audience(h.opts.audience)
	}
	if h.opts.expiration > 0 {
		builder.Expiration(now.Add(h.opts.expiration))
	}
	if h.opts.notBeforeSet {
		builder.NotBefore(now.Add(h.opts.notBeforeOffset))
	}
	for k, v := range h.opts.claims {
		builder.Claim(k, v)
	}

	tok, err := builder.Build()
	if err != nil {
		return nil, err
	}
	return h.signer.Sign(r.Context(), tok)
}

func (h *jwtIssuerHandler) setCookie(w http.ResponseWriter, tokenStr string) {
	ck := &http.Cookie{ //nolint:gosec // G124: secure attributes managed by cookies.Secure or handler options.
		Path:     h.opts.cookiePath,
		Domain:   h.opts.cookieDomain,
		Value:    tokenStr,
		SameSite: h.opts.cookieSameSite,
	}
	if h.opts.expiration > 0 {
		ck.Expires = time.Now().Add(h.opts.expiration)
		ck.MaxAge = int(h.opts.expiration.Seconds())
	}
	if h.opts.cookieSecure {
		if h.opts.cookieSameSite == http.SameSiteStrictMode {
			cookies.Secure(h.opts.cookieName).Set(w, ck)
		} else {
			ck.Secure = true
			ck.HttpOnly = true
			cookies.T(h.opts.cookieName).Set(w, ck)
		}
	} else {
		cookies.T(h.opts.cookieName).Set(w, ck)
	}
}

func (h *jwtIssuerHandler) getRedirectURL(r *http.Request) string {
	if h.opts.redirectParam != "" {
		if dest := r.URL.Query().Get(h.opts.redirectParam); dest != "" {
			if h.isAllowedRedirect(dest) {
				return dest
			}
			h.opts.logger.WarnContext(r.Context(), "jwt issuer: rejected untrusted redirect URL", "redirect", dest)
		}
	}
	return h.opts.redirectURL
}

func (h *jwtIssuerHandler) isAllowedRedirect(dest string) bool {
	if isSameOriginRelative(dest) {
		return true
	}
	if len(h.opts.allowedRedirects) == 0 {
		return false
	}
	u, err := url.Parse(dest)
	if err != nil {
		return false
	}
	for _, allowed := range h.opts.allowedRedirects {
		if isAllowedURL(u, dest, allowed) {
			return true
		}
	}
	return false
}

func isSameOriginRelative(dest string) bool {
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		return false
	}
	if strings.Contains(dest, "\\") || strings.ContainsAny(dest, "\r\n\t") {
		return false
	}
	u, err := url.Parse(dest)
	if err != nil {
		return false
	}
	return u.Scheme == "" && u.Host == "" && strings.HasPrefix(u.Path, "/")
}

func isAllowedURL(u *url.URL, target, pattern string) bool {
	if target == pattern {
		return true
	}
	p, err := url.Parse(pattern)
	if err != nil || p.Scheme == "" || p.Host == "" {
		return false
	}
	if !strings.EqualFold(u.Scheme, p.Scheme) || !strings.EqualFold(u.Host, p.Host) {
		return false
	}
	if p.Path == "" || p.Path == "/" {
		return true
	}
	return u.Path == p.Path || strings.HasPrefix(u.Path, strings.TrimSuffix(p.Path, "/")+"/")
}

func (h *jwtIssuerHandler) writeDirect(w http.ResponseWriter, r *http.Request, tokenStr string) {
	if h.opts.json || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": tokenStr,
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(tokenStr)) //nolint:gosec // G705: token is a base64url-encoded JWT string.
}
