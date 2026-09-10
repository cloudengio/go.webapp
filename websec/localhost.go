// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

// Package websec provides HTTP security middleware for web applications.
package websec

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"cloudeng.io/webapp"
	"cloudeng.io/webapp/webauth/jwtutil"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Option configures the security handler.
type Option func(o *options)

type jwtConfig struct {
	cookieName          string
	validator           jwtutil.Validator
	claimKey            string
	claimValue          any
	bootstrapQueryParam string
}

type options struct {
	enforceLoopback       bool
	blockCrossSite        bool
	allowedHosts          []string
	allowedPorts          []int
	allowedOrigins        []string
	securityHeaders       bool
	customResponseHeaders map[string]string
	logger                *slog.Logger
	jwt                   *jwtConfig
	totalDeniedCounter    webapp.CounterInc
	nonLoopbackCounter    webapp.CounterInc
	invalidHostCounter    webapp.CounterInc
	crossSiteCounter      webapp.CounterInc
	invalidJWTCounter     webapp.CounterInc
}

func noopCounter(context.Context) {}

func defaultOptions() options {
	return options{
		enforceLoopback: true,
		blockCrossSite:  true,
		allowedHosts: []string{
			"127.0.0.1",
			"localhost",
			"::1",
		},
		securityHeaders: true,
		customResponseHeaders: map[string]string{
			"X-Frame-Options":              "DENY",
			"X-Content-Type-Options":       "nosniff",
			"Content-Security-Policy":      "frame-ancestors 'none';",
			"Cross-Origin-Resource-Policy": "same-origin",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cache-Control":                "no-store",
		},
		logger:             slog.New(slog.DiscardHandler),
		totalDeniedCounter: noopCounter,
		nonLoopbackCounter: noopCounter,
		invalidHostCounter: noopCounter,
		crossSiteCounter:   noopCounter,
		invalidJWTCounter:  noopCounter,
	}
}

// WithBlockCrossSiteRequests enables or disables blocking requests initiated
// cross-site by local web browsers (inspecting Sec-Fetch-Site, Origin, and Referer).
// Defaults to true.
func WithBlockCrossSiteRequests(block bool) Option {
	return func(o *options) {
		o.blockCrossSite = block
	}
}

// WithAllowedHosts configures the allowed Host header values for DNS rebinding
// defense. If not specified, defaults to "127.0.0.1", "localhost", and "::1".
func WithAllowedHosts(hosts ...string) Option {
	return func(o *options) {
		o.allowedHosts = append([]string(nil), hosts...)
	}
}

// WithAllowedPorts restricts the Host header and destination port to specific
// port numbers (e.g. 8080).
func WithAllowedPorts(ports ...int) Option {
	return func(o *options) {
		o.allowedPorts = append([]int(nil), ports...)
	}
}

// WithAllowedOrigins permits specific origins to make cross-origin requests
// (e.g. a local dev UI on http://localhost:3000 calling an API on :8080).
func WithAllowedOrigins(origins ...string) Option {
	return func(o *options) {
		o.allowedOrigins = append([]string(nil), origins...)
	}
}

// WithEnforceLoopback toggles raw socket RemoteAddr loopback verification.
// Defaults to true.
func WithEnforceLoopback(enforce bool) Option {
	return func(o *options) {
		o.enforceLoopback = enforce
	}
}

// WithSecurityHeaders toggles whether defensive HTTP response headers
// (X-Frame-Options, CSP, nosniff, no-store) are injected. Defaults to true.
func WithSecurityHeaders(enable bool) Option {
	return func(o *options) {
		o.securityHeaders = enable
	}
}

// WithCustomResponseHeaders overrides or extends default response security headers.
func WithCustomResponseHeaders(headers map[string]string) Option {
	return func(o *options) {
		o.customResponseHeaders = maps.Clone(headers)
	}
}

// WithLogger sets the structured logger for security event logging.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) {
		if logger != nil {
			o.logger = logger
		}
	}
}

// WithCounters configures metric counters for all rejection types:
// - total: incremented on any rejected request
// - nonLoopback: incremented when the client remote address is not loopback
// - invalidHost: incremented when the Host header is invalid (DNS rebinding)
// - crossSite: incremented when a cross-site browser request is blocked
func WithCounters(total, nonLoopback, invalidHost, crossSite webapp.CounterInc) Option {
	return func(o *options) {
		if total != nil {
			o.totalDeniedCounter = total
		}
		if nonLoopback != nil {
			o.nonLoopbackCounter = nonLoopback
		}
		if invalidHost != nil {
			o.invalidHostCounter = invalidHost
		}
		if crossSite != nil {
			o.crossSiteCounter = crossSite
		}
	}
}

// WithDeniedCounter configures a counter callback invoked when a request
// is rejected for any reason (total denials).
func WithDeniedCounter(counter webapp.CounterInc) Option {
	return func(o *options) {
		if counter != nil {
			o.totalDeniedCounter = counter
		}
	}
}

// WithNonLoopbackCounter configures a counter callback invoked when a request
// is rejected because the remote client address is not loopback.
func WithNonLoopbackCounter(counter webapp.CounterInc) Option {
	return func(o *options) {
		if counter != nil {
			o.nonLoopbackCounter = counter
		}
	}
}

// WithInvalidHostCounter configures a counter callback invoked when a request
// is rejected due to an invalid Host header.
func WithInvalidHostCounter(counter webapp.CounterInc) Option {
	return func(o *options) {
		if counter != nil {
			o.invalidHostCounter = counter
		}
	}
}

// WithCrossSiteCounter configures a counter callback invoked when a request
// is rejected because it was initiated cross-site by a browser.
func WithCrossSiteCounter(counter webapp.CounterInc) Option {
	return func(o *options) {
		if counter != nil {
			o.crossSiteCounter = counter
		}
	}
}

// WithJWTCookie enables JWT validation for requests presented in a cookie.
// It verifies that the cookie named cookieName contains a valid JWT verifiable
// by pubKey and containing claimKey == claimValue. If cookieName is empty,
// it defaults to "auth_token". By default, bootstrapping from a "?token=<jwt>"
// URL query parameter is enabled.
func WithJWTCookie(cookieName string, pubKey jwk.Key, claimKey string, claimValue any) Option {
	return func(o *options) {
		if cookieName == "" {
			cookieName = "auth_token"
		}
		set := jwk.NewSet()
		if pubKey != nil {
			_ = set.AddKey(pubKey)
		}
		o.jwt = &jwtConfig{
			cookieName:          cookieName,
			validator:           jwtutil.NewValidator(set),
			claimKey:            claimKey,
			claimValue:          claimValue,
			bootstrapQueryParam: "token",
		}
	}
}

// WithJWTBootstrapQueryParam configures the URL query parameter name used to bootstrap
// the JWT cookie into the client's browser (e.g. "?token=<jwt>"). If a request arrives
// without the cookie but with a valid token in this query parameter, the handler sets
// the secure HTTP cookie and issues an HTTP 303 redirect to the clean URL without the token.
// Pass an empty string to disable query parameter bootstrapping.
func WithJWTBootstrapQueryParam(param string) Option {
	return func(o *options) {
		if o.jwt != nil {
			o.jwt.bootstrapQueryParam = param
		}
	}
}

// WithInvalidJWTCounter configures a counter callback invoked when a request
// is rejected due to a missing, invalid, or expired JWT.
func WithInvalidJWTCounter(counter webapp.CounterInc) Option {
	return func(o *options) {
		if counter != nil {
			o.invalidJWTCounter = counter
		}
	}
}

type tokenContextKey struct{}

// TokenFromContext returns the validated jwt.Token from the request context,
// if one was validated by the handler.
func TokenFromContext(ctx context.Context) (jwt.Token, bool) {
	tok, ok := ctx.Value(tokenContextKey{}).(jwt.Token)
	return tok, ok
}

type handler struct {
	next http.Handler
	opts options
}

// NewLocalhostHandler wraps next with security controls designed for services
// bound to 127.0.0.1 or ::1. By default, it enforces loopback connections,
// validates Host headers against DNS rebinding, blocks cross-site browser
// requests, and sets defensive response headers.
func NewLocalhostHandler(next http.Handler, opts ...Option) http.Handler {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return &handler{
		next: next,
		opts: o,
	}
}

// NewHandler is an alias for NewLocalhostHandler.
func NewHandler(next http.Handler, opts ...Option) http.Handler {
	return NewLocalhostHandler(next, opts...)
}

// NewLocalHost is an alias for NewLocalhostHandler.
func NewLocalHost(next http.Handler, opts ...Option) http.Handler {
	return NewLocalhostHandler(next, opts...)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.opts.enforceLoopback && !h.verifyLoopback(r) {
		h.deny(w, r, "remote client address is not loopback", h.opts.nonLoopbackCounter)
		return
	}

	if !h.verifyHost(r) {
		h.deny(w, r, "invalid host header", h.opts.invalidHostCounter)
		return
	}

	if h.opts.blockCrossSite && !h.verifyCrossSite(r) {
		h.deny(w, r, "cross-site browser request blocked", h.opts.crossSiteCounter)
		return
	}

	if h.opts.jwt != nil {
		req, ok := h.verifyJWT(w, r)
		if !ok {
			return
		}
		r = req
	}

	if h.opts.securityHeaders {
		for k, v := range h.opts.customResponseHeaders {
			w.Header().Set(k, v)
		}
	}

	h.next.ServeHTTP(w, r)
}

func (h *handler) verifyJWT(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	cfg := h.opts.jwt

	// 1. Check cookie
	if cookie, err := r.Cookie(cfg.cookieName); err == nil && cookie.Value != "" {
		tok, err := h.validateToken(r.Context(), cookie.Value)
		if err == nil {
			ctx := context.WithValue(r.Context(), tokenContextKey{}, tok)
			return r.WithContext(ctx), true
		}
		h.denyWithStatus(w, r, http.StatusUnauthorized, "invalid jwt cookie: "+err.Error(), h.opts.invalidJWTCounter)
		return r, false
	}

	// 2. Check query parameter bootstrap (e.g. ?token=<jwt>)
	if cfg.bootstrapQueryParam != "" {
		if tokenStr := r.URL.Query().Get(cfg.bootstrapQueryParam); tokenStr != "" {
			if _, err := h.validateToken(r.Context(), tokenStr); err != nil {
				h.denyWithStatus(w, r, http.StatusUnauthorized, "invalid bootstrap token: "+err.Error(), h.opts.invalidJWTCounter)
				return r, false
			}

			// Valid token: set cookie and redirect to clean URL
			http.SetCookie(w, &http.Cookie{
				Name:     cfg.cookieName,
				Value:    tokenStr,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Secure:   r.TLS != nil,
			})

			q := r.URL.Query()
			q.Del(cfg.bootstrapQueryParam)
			u := *r.URL
			u.RawQuery = q.Encode()
			cleanURL := u.RequestURI()
			if cleanURL == "" {
				cleanURL = "/"
			}
			http.Redirect(w, r, cleanURL, http.StatusSeeOther)
			return r, false
		}
	}

	h.denyWithStatus(w, r, http.StatusUnauthorized, "missing authentication cookie", h.opts.invalidJWTCounter)
	return r, false
}

func (h *handler) validateToken(ctx context.Context, tokenStr string) (jwt.Token, error) {
	var validators []jwt.ValidateOption
	if h.opts.jwt.claimKey != "" {
		validators = append(validators, jwt.WithClaimValue(h.opts.jwt.claimKey, h.opts.jwt.claimValue))
	}
	return h.opts.jwt.validator.ParseAndValidate(ctx, []byte(tokenStr), validators...)
}

func (h *handler) deny(w http.ResponseWriter, r *http.Request, reason string, specificCounter webapp.CounterInc) {
	h.denyWithStatus(w, r, http.StatusForbidden, reason, specificCounter)
}

func (h *handler) denyWithStatus(w http.ResponseWriter, r *http.Request, status int, reason string, specificCounter webapp.CounterInc) {
	h.opts.totalDeniedCounter(r.Context())
	if specificCounter != nil {
		specificCounter(r.Context())
	}
	h.opts.logger.WarnContext(r.Context(), "request rejected by localhost security handler",
		"status", status,
		"reason", reason,
		"remote_addr", r.RemoteAddr,
		"host", r.Host,
		"origin", r.Header.Get("Origin"),
		"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"),
	)
	http.Error(w, reason, status)
}

func (h *handler) verifyLoopback(r *http.Request) bool {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().IsLoopback()
	}
	addr, err := netip.ParseAddr(r.RemoteAddr)
	return err == nil && addr.IsLoopback()
}

func (h *handler) verifyHost(r *http.Request) bool {
	if len(h.opts.allowedHosts) == 0 {
		return true
	}
	rawHost := strings.ToLower(r.Host)
	host, portStr, err := net.SplitHostPort(rawHost)
	if err != nil {
		host = rawHost
		portStr = ""
	}
	hostWithoutBrackets := strings.Trim(host, "[]")

	hostMatched := false
	for _, allowed := range h.opts.allowedHosts {
		allowedLower := strings.ToLower(allowed)
		if rawHost == allowedLower || host == allowedLower || hostWithoutBrackets == allowedLower || hostWithoutBrackets == strings.Trim(allowedLower, "[]") {
			hostMatched = true
			break
		}
	}
	if !hostMatched {
		return false
	}

	if len(h.opts.allowedPorts) > 0 && portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || !slices.Contains(h.opts.allowedPorts, port) {
			return false
		}
	}
	return true
}

func (h *handler) verifyCrossSite(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" && h.isOriginAllowed(origin) {
		return true
	}

	// Fetch Metadata inspection: Sec-Fetch-Site
	secFetchSite := strings.ToLower(r.Header.Get("Sec-Fetch-Site"))
	if secFetchSite == "cross-site" {
		return false
	}

	// Origin header check
	if origin != "" && !h.isLoopbackOrigin(origin) {
		return false
	}

	// Referer header check (if Origin was absent)
	if origin == "" {
		if referer := r.Header.Get("Referer"); referer != "" {
			if !h.isLoopbackOrigin(referer) && !h.isOriginAllowed(referer) {
				return false
			}
		}
	}

	return true
}

func (h *handler) isOriginAllowed(originStr string) bool {
	if slices.Contains(h.opts.allowedOrigins, originStr) {
		return true
	}
	u, err := url.Parse(originStr)
	if err != nil {
		return false
	}
	normalized := u.Scheme + "://" + u.Host
	return slices.Contains(h.opts.allowedOrigins, normalized) || slices.Contains(h.opts.allowedOrigins, u.Host)
}

func (h *handler) isLoopbackOrigin(originStr string) bool {
	u, err := url.Parse(originStr)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	return false
}
