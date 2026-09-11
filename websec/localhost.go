// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package websec

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"cloudeng.io/webapp"
	"cloudeng.io/webapp/cookies"
	"cloudeng.io/webapp/webauth/jwtutil"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Option configures the security handler.
type Option func(o *options)

type jwtConfig struct {
	cookie     cookies.Secure
	contextKey string
	validator  jwtutil.Validator
	claimKey   string
	claimValue any
}

// tokenKey returns the key that a validated token is stored under in the
// request context. It defaults to the name of the cookie the token arrived in,
// which is what WithJWTContextKey overrides.
func (c *jwtConfig) tokenKey() string {
	if c.contextKey != "" {
		return c.contextKey
	}
	return string(c.cookie)
}

// Denial reason constants used as label values for the denial metric.
const (
	DenialNonLoopback = "non-loopback"
	DenialInvalidHost = "invalid-host"
	DenialCrossSite   = "cross-site"
	DenialInvalidJWT  = "invalid-jwt"
)

// MetricsColumns returns the list of column/label names used for the denial metric.
func MetricsColumns() []string {
	return []string{"reason"}
}

// MetricsDenialValues returns the list of values used for the "reason" label of the denial metric.
func MetricsDenialValues() []string {
	return []string{
		DenialNonLoopback,
		DenialInvalidHost,
		DenialCrossSite,
		DenialInvalidJWT,
	}
}

// DenialMetricValues is an alias for MetricsDenialValues.
func DenialMetricValues() []string {
	return MetricsDenialValues()
}

var defaultCustomResponseHeaders = map[string]string{
	"X-Frame-Options":              "DENY",
	"X-Content-Type-Options":       "nosniff",
	"Content-Security-Policy":      "frame-ancestors 'none';",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cache-Control":                "no-store",
}

func noopCounter(context.Context, ...string) {}

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
	jwtCookieName         string
	jwtContextKey         string
	counterVec            webapp.CounterVecInc
	counterVecAdd         webapp.CounterVecAdd
}

func defaultOptions() options {
	return options{
		enforceLoopback: true,
		blockCrossSite:  true,
		allowedHosts: []string{
			"127.0.0.1",
			"localhost",
			"::1",
		},
		securityHeaders:       true,
		customResponseHeaders: defaultCustomResponseHeaders,
		logger:                slog.New(slog.DiscardHandler),
		counterVec:            noopCounter,
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

// WithAllowedOrigins permits specific external or non-loopback origins to
// make cross-origin requests (e.g. a dev UI on https://trusted-partner.local
// or an external web client).
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

// WithCounterVec configures a CounterVecInc metric that is incremented whenever
// a request is rejected, with the denial reason supplied as a label value
// (one of MetricsDenialValues).
func WithCounterVec(counter webapp.CounterVecInc) Option {
	return func(o *options) {
		if counter != nil {
			o.counterVec = counter
		}
	}
}

// WithMetrics is an alias for WithCounterVec.
func WithMetrics(metrics webapp.CounterVecInc) Option {
	return WithCounterVec(metrics)
}

// WithCounters is an alias for WithCounterVec.
func WithCounters(counter webapp.CounterVecInc) Option {
	return WithCounterVec(counter)
}

// WithCounterVecAdd configures a CounterVecAdd metric for request denials.
// At handler initialization, all denial reason labels from MetricsDenialValues
// are initialized with delta 0, and incremented by 1 on each denial.
func WithCounterVecAdd(counter webapp.CounterVecAdd) Option {
	return func(o *options) {
		if counter != nil {
			o.counterVecAdd = counter
		}
	}
}

// WithJWTCookie enables JWT validation for requests presented in a cookie.
// It verifies that the cookie named cookieName contains a JWT that validator
// accepts and that contains claimKey == claimValue. If cookieName is empty,
// it defaults to "auth_token".
//
// The validated token is stored in the request context under the name of the
// cookie unless WithJWTContextKey says otherwise. WithJWTCookieName can be
// used to set the cookie name separately from this option.
func WithJWTCookie(cookieName string, validator jwtutil.Validator, claimKey string, claimValue any) Option {
	return func(o *options) {
		if cookieName == "" {
			cookieName = "auth_token"
		}
		o.jwt = &jwtConfig{
			cookie:     cookies.Secure(cookieName),
			validator:  validator,
			claimKey:   claimKey,
			claimValue: claimValue,
		}
	}
}

// WithJWTCookieName sets the name of the cookie that carries the JWT,
// overriding the name given to WithJWTCookie. An empty name is ignored, since
// a cookie has to be named something.
func WithJWTCookieName(name string) Option {
	return func(o *options) {
		if name != "" {
			o.jwtCookieName = name
			if o.jwt != nil {
				o.jwt.cookie = cookies.Secure(name)
			}
		}
	}
}

// WithJWTContextKey sets the key that a validated token is stored under in the
// request context, for retrieval with jwtutil.TokenFromContext. It defaults to the
// name of the cookie, so this is needed where the two should differ, such as
// when the name of the cookie is not one the rest of the application should
// have to know.
func WithJWTContextKey(key string) Option {
	return func(o *options) {
		o.jwtContextKey = key
		if o.jwt != nil {
			o.jwt.contextKey = key
		}
	}
}

type handler struct {
	next           http.Handler
	opts           options
	allowedHosts   map[string]struct{}
	allowedPorts   map[int]struct{}
	allowedOrigins map[string]struct{}
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
	if o.jwt != nil {
		if o.jwtCookieName != "" {
			o.jwt.cookie = cookies.Secure(o.jwtCookieName)
		}
		if o.jwtContextKey != "" {
			o.jwt.contextKey = o.jwtContextKey
		}
	}
	if o.counterVec == nil {
		o.counterVec = noopCounter
	}
	if o.counterVecAdd != nil {
		for _, val := range MetricsDenialValues() {
			o.counterVecAdd(context.Background(), 0, val)
		}
	}

	return &handler{
		next:           next,
		opts:           o,
		allowedHosts:   newAllowedHosts(o.allowedHosts),
		allowedPorts:   newAllowedPorts(o.allowedPorts),
		allowedOrigins: newAllowedOrigins(o.allowedOrigins),
	}
}

func newAllowedHosts(hosts []string) map[string]struct{} {
	if len(hosts) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(hosts)*2)
	for _, allowed := range hosts {
		lower := strings.ToLower(allowed)
		m[lower] = struct{}{}
		m[strings.Trim(lower, "[]")] = struct{}{}
	}
	return m
}

func newAllowedPorts(ports []int) map[int]struct{} {
	if len(ports) == 0 {
		return nil
	}
	m := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		m[port] = struct{}{}
	}
	return m
}

func newAllowedOrigins(origins []string) map[string]struct{} {
	if len(origins) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(origins)*3)
	for _, orig := range origins {
		m[orig] = struct{}{}
		if u, err := url.Parse(orig); err == nil {
			if u.Scheme != "" && u.Host != "" {
				m[u.Scheme+"://"+u.Host] = struct{}{}
			}
			if u.Host != "" {
				m[u.Host] = struct{}{}
			}
		}
	}
	return m
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
		h.deny(w, r, "remote client address is not loopback", DenialNonLoopback)
		return
	}

	if !h.verifyHost(r) {
		h.deny(w, r, "invalid host header", DenialInvalidHost)
		return
	}

	if h.opts.blockCrossSite && !h.verifyCrossSite(r) {
		h.deny(w, r, "cross-site browser request blocked", DenialCrossSite)
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

	if value, ok := cfg.cookie.Read(r); ok && value != "" {
		tok, err := h.validateToken(r.Context(), value)
		if err == nil {
			ctx := jwtutil.ContextWithToken(r.Context(), cfg.tokenKey(), tok)
			return r.WithContext(ctx), true
		}
		h.opts.logger.WarnContext(r.Context(), "invalid jwt token in cookie", "error", err)
		h.denyWithStatus(w, r, http.StatusUnauthorized, "invalid or expired authentication token", DenialInvalidJWT)
		return r, false
	}

	h.denyWithStatus(w, r, http.StatusUnauthorized, "missing authentication cookie", DenialInvalidJWT)
	return r, false
}

func (h *handler) validateToken(ctx context.Context, tokenStr string) (jwt.Token, error) {
	var validators []jwt.ValidateOption
	if h.opts.jwt.claimKey != "" {
		validators = append(validators, jwt.WithClaimValue(h.opts.jwt.claimKey, h.opts.jwt.claimValue))
	}
	return h.opts.jwt.validator.ParseAndValidate(ctx, []byte(tokenStr), validators...)
}

func (h *handler) deny(w http.ResponseWriter, r *http.Request, reason string, denialType string) {
	h.denyWithStatus(w, r, http.StatusForbidden, reason, denialType)
}

func (h *handler) denyWithStatus(w http.ResponseWriter, r *http.Request, status int, reason string, denialType string) {
	h.opts.counterVec(r.Context(), denialType)
	if h.opts.counterVecAdd != nil {
		h.opts.counterVecAdd(r.Context(), 1, denialType)
	}
	h.opts.logger.WarnContext(r.Context(), "request rejected by localhost security handler",
		"status", status,
		"reason", reason,
		"denial_type", denialType,
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
	if len(h.allowedHosts) == 0 {
		return true
	}
	rawHost := strings.ToLower(r.Host)
	host, portStr, err := net.SplitHostPort(rawHost)
	if err != nil {
		host = rawHost
		portStr = ""
	}
	hostWithoutBrackets := strings.Trim(host, "[]")

	matched := false
	if _, ok := h.allowedHosts[rawHost]; ok {
		matched = true
	} else if _, ok := h.allowedHosts[host]; ok {
		matched = true
	} else if _, ok := h.allowedHosts[hostWithoutBrackets]; ok {
		matched = true
	}
	if !matched {
		return false
	}

	if len(h.allowedPorts) > 0 {
		if portStr != "" {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return false
			}
			if _, ok := h.allowedPorts[port]; !ok {
				return false
			}
		} else {
			defaultPort := 80
			if r.TLS != nil {
				defaultPort = 443
			}
			if _, ok := h.allowedPorts[defaultPort]; !ok {
				return false
			}
		}
	}
	return true
}

func parseURL(raw string) *url.URL {
	if raw == "" {
		return nil
	}
	u, _ := url.Parse(raw)
	return u
}

func (h *handler) verifyCrossSite(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	originURL := parseURL(origin)
	if originURL != nil && h.isURLOriginAllowed(origin, originURL) {
		return true
	}

	referer := r.Header.Get("Referer")
	refererURL := parseURL(referer)
	if origin == "" && refererURL != nil && h.isURLOriginAllowed(referer, refererURL) {
		return true
	}

	secFetchSite := strings.ToLower(r.Header.Get("Sec-Fetch-Site"))
	if secFetchSite == "cross-site" {
		return false
	}

	if origin != "" {
		return isLoopbackURL(originURL)
	}
	if referer != "" {
		return isLoopbackURL(refererURL)
	}
	return true
}

func (h *handler) isURLOriginAllowed(raw string, u *url.URL) bool {
	if len(h.allowedOrigins) == 0 || u == nil {
		return false
	}
	if _, ok := h.allowedOrigins[raw]; ok {
		return true
	}
	if u.Scheme != "" && u.Host != "" {
		if _, ok := h.allowedOrigins[u.Scheme+"://"+u.Host]; ok {
			return true
		}
	}
	if u.Host != "" {
		if _, ok := h.allowedOrigins[u.Host]; ok {
			return true
		}
	}
	return false
}

func isLoopbackURL(u *url.URL) bool {
	if u == nil {
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
