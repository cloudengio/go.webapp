// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package websec_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"cloudeng.io/webapp/webauth/jwtutil"
	"cloudeng.io/webapp/websec"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestEnforceLoopback(t *testing.T) {
	tests := []struct {
		remoteAddr string
		enforce    bool
		wantStatus int
	}{
		{"127.0.0.1:1234", true, http.StatusOK},
		{"127.0.0.2:5678", true, http.StatusOK},
		{"[::1]:1234", true, http.StatusOK},
		{"::1", true, http.StatusOK},
		{"192.168.1.100:1234", true, http.StatusForbidden},
		{"8.8.8.8:1234", true, http.StatusForbidden},
		{"invalid-ip", true, http.StatusForbidden},
		{"192.168.1.100:1234", false, http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.remoteAddr, func(t *testing.T) {
			handler := websec.NewLocalhostHandler(okHandler(),
				websec.WithEnforceLoopback(tc.enforce),
			)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			req.Host = "localhost"
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)
			if got := w.Code; got != tc.wantStatus {
				t.Errorf("remoteAddr %q (enforce=%v): got status %d, want %d", tc.remoteAddr, tc.enforce, got, tc.wantStatus)
			}
		})
	}
}

func TestHostValidation(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		opts       []websec.Option
		wantStatus int
	}{
		{"default localhost:8080", "localhost:8080", nil, http.StatusOK},
		{"default 127.0.0.1:8080", "127.0.0.1:8080", nil, http.StatusOK},
		{"default localhost without port", "localhost", nil, http.StatusOK},
		{"default ipv6 [::1]:8080", "[::1]:8080", nil, http.StatusOK},
		{"dns rebinding attacker.com", "attacker.com:8080", nil, http.StatusForbidden},
		{"dns rebinding rebind.attacker.com", "rebind.attacker.com", nil, http.StatusForbidden},
		{"dns rebinding external ip", "192.168.1.5:8080", nil, http.StatusForbidden},
		{
			"custom allowed host match",
			"my-service.local:8080",
			[]websec.Option{websec.WithAllowedHosts("my-service.local")},
			http.StatusOK,
		},
		{
			"custom allowed host mismatch",
			"localhost:8080",
			[]websec.Option{websec.WithAllowedHosts("my-service.local")},
			http.StatusForbidden,
		},
		{
			"allowed port match",
			"localhost:8080",
			[]websec.Option{websec.WithAllowedPorts(8080, 8443)},
			http.StatusOK,
		},
		{
			"allowed port mismatch",
			"localhost:9090",
			[]websec.Option{websec.WithAllowedPorts(8080, 8443)},
			http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := websec.NewLocalhostHandler(okHandler(), tc.opts...)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Host = tc.host
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)
			if got := w.Code; got != tc.wantStatus {
				t.Errorf("Host %q: got status %d, want %d", tc.host, got, tc.wantStatus)
			}
		})
	}
}

func TestCrossSiteRequests(t *testing.T) {
	tests := []struct {
		name         string
		secFetchSite string
		origin       string
		referer      string
		opts         []websec.Option
		wantStatus   int
	}{
		{
			name:         "sec-fetch-site same-origin",
			secFetchSite: "same-origin",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "sec-fetch-site same-site",
			secFetchSite: "same-site",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "sec-fetch-site none (direct browser nav)",
			secFetchSite: "none",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "sec-fetch-site cross-site blocked",
			secFetchSite: "cross-site",
			wantStatus:   http.StatusForbidden,
		},
		{
			name:       "cli client without browser headers",
			wantStatus: http.StatusOK,
		},
		{
			name:       "origin evil.com blocked",
			origin:     "http://evil.com",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "origin localhost allowed",
			origin:     "http://localhost:3000",
			wantStatus: http.StatusOK,
		},
		{
			name:       "origin 127.0.0.1 allowed",
			origin:     "http://127.0.0.1:8080",
			wantStatus: http.StatusOK,
		},
		{
			name:       "referer evil.com blocked",
			referer:    "http://evil.com/attack",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "referer localhost allowed",
			referer:    "http://localhost:8080/page",
			wantStatus: http.StatusOK,
		},
		{
			name:         "explicit allowed origin with cross-site fetch site",
			secFetchSite: "cross-site",
			origin:       "https://trusted-partner.com",
			opts:         []websec.Option{websec.WithAllowedOrigins("https://trusted-partner.com")},
			wantStatus:   http.StatusOK,
		},
		{
			name:         "cross-site blocking disabled",
			secFetchSite: "cross-site",
			origin:       "http://evil.com",
			opts:         []websec.Option{websec.WithBlockCrossSiteRequests(false)},
			wantStatus:   http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := websec.NewLocalhostHandler(okHandler(), tc.opts...)
			req := httptest.NewRequest(http.MethodPost, "/api", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Host = "localhost:8080"
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)
			if got := w.Code; got != tc.wantStatus {
				t.Errorf("got status %d, want %d", got, tc.wantStatus)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Run("default security headers", func(t *testing.T) {
		handler := websec.NewLocalhostHandler(okHandler())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Host = "localhost"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		expectedHeaders := map[string]string{
			"X-Frame-Options":              "DENY",
			"X-Content-Type-Options":       "nosniff",
			"Content-Security-Policy":      "frame-ancestors 'none';",
			"Cross-Origin-Resource-Policy": "same-origin",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cache-Control":                "no-store",
		}

		for k, want := range expectedHeaders {
			if got := w.Header().Get(k); got != want {
				t.Errorf("header %q = %q, want %q", k, got, want)
			}
		}
	})

	t.Run("disabled security headers", func(t *testing.T) {
		handler := websec.NewLocalhostHandler(okHandler(),
			websec.WithSecurityHeaders(false),
		)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Host = "localhost"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if got := w.Header().Get("X-Frame-Options"); got != "" {
			t.Errorf("expected no X-Frame-Options, got %q", got)
		}
	})

	t.Run("custom response headers", func(t *testing.T) {
		handler := websec.NewLocalhostHandler(okHandler(),
			websec.WithCustomResponseHeaders(map[string]string{
				"X-Custom-Sec": "enabled",
			}),
		)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Host = "localhost"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if got := w.Header().Get("X-Custom-Sec"); got != "enabled" {
			t.Errorf("expected X-Custom-Sec: enabled, got %q", got)
		}
		if got := w.Header().Get("X-Frame-Options"); got != "" {
			t.Errorf("expected overridden headers to not include default X-Frame-Options, got %q", got)
		}
	})
}

type fakeCounterVec struct {
	mu     sync.Mutex
	counts map[string]int
}

func newFakeCounterVec() *fakeCounterVec {
	f := &fakeCounterVec{
		counts: make(map[string]int),
	}
	// Initialized for each denial label value.
	for _, val := range websec.MetricsDenialValues() {
		f.counts[val] = 0
	}
	return f
}

func (f *fakeCounterVec) Inc(_ context.Context, labels ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(labels) > 0 {
		f.counts[labels[0]]++
	}
}

func (f *fakeCounterVec) Count(val string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[val]
}

func TestMetricsColumnsAndDenialValues(t *testing.T) {
	if got, want := websec.MetricsColumns(), []string{"reason"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	wantValues := []string{
		websec.DenialNonLoopback,
		websec.DenialInvalidHost,
		websec.DenialCrossSite,
		websec.DenialInvalidJWT,
	}
	if got := websec.MetricsDenialValues(); !slices.Equal(got, wantValues) {
		t.Errorf("got %v, want %v", got, wantValues)
	}
}

func TestCounterVec(t *testing.T) {
	vec := newFakeCounterVec()

	handler := websec.NewHandler(okHandler(),
		websec.WithCounterVec(vec.Inc),
	)

	// Verify all labels initialized to 0.
	for _, reason := range websec.MetricsDenialValues() {
		if got := vec.Count(reason); got != 0 {
			t.Errorf("initially expected 0 for %q, got %d", reason, got)
		}
	}

	// Valid request -> no counter increments
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "127.0.0.1:1234"
	req1.Host = "localhost"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	for _, reason := range websec.MetricsDenialValues() {
		if got := vec.Count(reason); got != 0 {
			t.Errorf("after valid request: expected 0 for %q, got %d", reason, got)
		}
	}

	// 1. Non-loopback rejection
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "192.168.1.1:1234"
	req2.Host = "localhost"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if got := vec.Count(websec.DenialNonLoopback); got != 1 {
		t.Errorf("after non-loopback: got %d (want 1)", got)
	}

	// 2. Invalid host rejection
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.RemoteAddr = "127.0.0.1:1234"
	req3.Host = "evil.com"
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if got := vec.Count(websec.DenialInvalidHost); got != 1 {
		t.Errorf("after invalid host: got %d (want 1)", got)
	}

	// 3. Cross-site rejection
	req4 := httptest.NewRequest(http.MethodGet, "/", nil)
	req4.RemoteAddr = "127.0.0.1:1234"
	req4.Host = "localhost"
	req4.Header.Set("Sec-Fetch-Site", "cross-site")
	w4 := httptest.NewRecorder()
	handler.ServeHTTP(w4, req4)
	if got := vec.Count(websec.DenialCrossSite); got != 1 {
		t.Errorf("after cross-site: got %d (want 1)", got)
	}
}

func TestCounterVecAdd_Initialization(t *testing.T) {
	var mu sync.Mutex
	initialDeltas := make(map[string]float64)
	addCounts := make(map[string]float64)

	addFn := func(_ context.Context, delta float64, labels ...string) {
		mu.Lock()
		defer mu.Unlock()
		if len(labels) > 0 {
			if delta == 0 {
				initialDeltas[labels[0]] = delta
			} else {
				addCounts[labels[0]] += delta
			}
		}
	}

	handler := websec.NewLocalhostHandler(okHandler(),
		websec.WithCounterVecAdd(addFn),
	)

	// Verify that NewLocalhostHandler initialized every denial label with delta 0.
	mu.Lock()
	for _, val := range websec.MetricsDenialValues() {
		if _, ok := initialDeltas[val]; !ok {
			t.Errorf("expected initial delta 0 for label %q, but was not called", val)
		}
	}
	mu.Unlock()

	// Trigger non-loopback denial
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	req.Host = "localhost"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	mu.Lock()
	defer mu.Unlock()
	if got := addCounts[websec.DenialNonLoopback]; got != 1 {
		t.Errorf("got non-loopback delta %v, want 1", got)
	}
}

func setupSigner(t *testing.T) jwtutil.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	signer, err := jwtutil.NewED25519Signer(priv, "test-key-id")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return signer
}

func TestJWTCookieValidation(t *testing.T) {
	ctx := t.Context()
	signer := setupSigner(t)
	pubKey, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	claimKey := "role"
	claimValue := "admin"

	// Create valid token
	validToken, err := jwtutil.CreateVerificationToken(ctx, signer, "user-1", claimKey, claimValue, time.Hour, "", "")
	if err != nil {
		t.Fatalf("failed to create verification token: %v", err)
	}

	// Create expired token
	expiredToken, err := jwtutil.CreateVerificationToken(ctx, signer, "user-1", claimKey, claimValue, -time.Minute, "", "")
	if err != nil {
		t.Fatalf("failed to create expired token: %v", err)
	}

	// Create token with wrong claim value
	wrongClaimToken, err := jwtutil.CreateVerificationToken(ctx, signer, "user-1", claimKey, "guest", time.Hour, "", "")
	if err != nil {
		t.Fatalf("failed to create wrong claim token: %v", err)
	}

	// Signer with different key
	otherSigner := setupSigner(t)
	otherKeyToken, err := jwtutil.CreateVerificationToken(ctx, otherSigner, "user-1", claimKey, claimValue, time.Hour, "", "")
	if err != nil {
		t.Fatalf("failed to create other key token: %v", err)
	}

	var contextSubject string
	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok, ok := jwtutil.TokenFromContext(r.Context(), "auth_cookie"); ok {
			sub, _ := tok.Subject()
			contextSubject = sub
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := websec.NewLocalhostHandler(echoHandler,
		websec.WithJWTCookie("auth_cookie", pubKey, claimKey, claimValue),
		websec.WithJWTBootstrapQueryParam(""), // disable bootstrap for this test
	)

	tests := []struct {
		name       string
		cookieVal  string
		wantStatus int
		wantSub    string
	}{
		{
			name:       "valid token in cookie",
			cookieVal:  string(validToken),
			wantStatus: http.StatusOK,
			wantSub:    "user-1",
		},
		{
			name:       "missing cookie",
			cookieVal:  "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "corrupted token",
			cookieVal:  "invalid.token.string",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "expired token",
			cookieVal:  string(expiredToken),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong claim value",
			cookieVal:  string(wrongClaimToken),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "different signing key",
			cookieVal:  string(otherKeyToken),
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			contextSubject = ""
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Host = "localhost"
			if tc.cookieVal != "" {
				// G124 concerns response cookies; Secure, HttpOnly and
				// SameSite have no meaning on one a client sends.
				req.AddCookie(&http.Cookie{ //nolint:gosec // G124: a request cookie.
					Name:  "auth_cookie",
					Value: tc.cookieVal,
				})
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)
			if got := w.Code; got != tc.wantStatus {
				t.Errorf("got status %d, want %d", got, tc.wantStatus)
			}
			if tc.wantSub != "" && contextSubject != tc.wantSub {
				t.Errorf("got context subject %q, want %q", contextSubject, tc.wantSub)
			}
		})
	}
}

func TestJWTBootstrapQueryParam(t *testing.T) {
	ctx := t.Context()
	signer := setupSigner(t)
	pubKey, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	validToken, err := jwtutil.CreateVerificationToken(ctx, signer, "user-2", "access", "granted", time.Hour, "", "")
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	handler := websec.NewLocalhostHandler(okHandler(),
		websec.WithJWTCookie("session_token", pubKey, "access", "granted"),
		websec.WithJWTBootstrapQueryParam("token"),
	)

	t.Run("successful bootstrap with redirect and cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/dashboard?source=email&token="+string(validToken), nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Host = "localhost"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusSeeOther; got != want {
			t.Fatalf("got status %d, want %d", got, want)
		}

		// Verify redirect Location strips token query param
		location := w.Header().Get("Location")
		if location != "/dashboard?source=email" {
			t.Errorf("got Location %q, want %q", location, "/dashboard?source=email")
		}

		// Verify cookie was set
		cookies := w.Result().Cookies()
		var sessionCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "session_token" {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Fatal("session_token cookie was not set in response")
		}
		if sessionCookie.Value != string(validToken) {
			t.Errorf("got cookie value %q, want %q", sessionCookie.Value, string(validToken))
		}
		if !sessionCookie.HttpOnly {
			t.Error("cookie should be HttpOnly")
		}
		if sessionCookie.SameSite != http.SameSiteStrictMode {
			t.Errorf("got SameSite %v, want %v", sessionCookie.SameSite, http.SameSiteStrictMode)
		}

		// Follow-up request using the newly issued cookie
		req2 := httptest.NewRequest(http.MethodGet, "/dashboard?source=email", nil)
		req2.RemoteAddr = "127.0.0.1:1234"
		req2.Host = "localhost"
		req2.AddCookie(sessionCookie)
		w2 := httptest.NewRecorder()

		handler.ServeHTTP(w2, req2)
		if got, want := w2.Code, http.StatusOK; got != want {
			t.Errorf("follow up with cookie: got status %d, want %d", got, want)
		}
	})

	t.Run("invalid bootstrap token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/dashboard?token=bad.token", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Host = "localhost"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		if got, want := w.Code, http.StatusUnauthorized; got != want {
			t.Errorf("got status %d, want %d", got, want)
		}
	})
}

func TestInvalidJWTCounter(t *testing.T) {
	vec := newFakeCounterVec()
	signer := setupSigner(t)
	pubKey, _ := signer.PublicKey()

	handler := websec.NewLocalhostHandler(okHandler(),
		websec.WithJWTCookie("test_cookie", pubKey, "perm", "read"),
		websec.WithJWTBootstrapQueryParam(""),
		websec.WithCounterVec(vec.Inc),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "localhost"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if got := vec.Count(websec.DenialInvalidJWT); got != 1 {
		t.Errorf("got invalid-jwt count %d, want 1", got)
	}
}

// TestJWTCookieNameAndContextKey covers the options that separate the name of
// the cookie carrying the token from the key the token is stored under in the
// request context. Without them the two are necessarily the same, so each case
// here also fails if the option is ignored: the cookie the client sends is the
// one the option names, so a handler still looking for the original name finds
// no cookie at all.
func TestJWTCookieNameAndContextKey(t *testing.T) {
	ctx := t.Context()
	signer := setupSigner(t)
	pubKey, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}
	token, err := jwtutil.CreateVerificationToken(ctx, signer, "user-3", "role", "admin", time.Hour, "", "")
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	for _, tc := range []struct {
		name string
		opts []websec.Option
		// sends is the cookie the client presents, wantKey the context key the
		// token must then be retrievable under.
		sends   string
		wantKey string
	}{
		{"defaults to the cookie name", nil, "auth_cookie", "auth_cookie"},
		{"renamed cookie", []websec.Option{websec.WithJWTCookieName("renamed")}, "renamed", "renamed"},
		{"separate context key", []websec.Option{websec.WithJWTContextKey("session")}, "auth_cookie", "session"},
		{"both", []websec.Option{
			websec.WithJWTCookieName("renamed"),
			websec.WithJWTContextKey("session"),
		}, "renamed", "session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotKeys []string
			var gotSubject string
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k := range jwtutil.TokensFromContext(r.Context()) {
					gotKeys = append(gotKeys, k)
				}
				slices.Sort(gotKeys)
				if tok, ok := jwtutil.TokenFromContext(r.Context(), tc.wantKey); ok {
					gotSubject, _ = tok.Subject()
				}
				w.WriteHeader(http.StatusOK)
			})

			opts := append([]websec.Option{
				websec.WithJWTCookie("auth_cookie", pubKey, "role", "admin"),
			}, tc.opts...)
			handler := websec.NewLocalhostHandler(inner, opts...)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Host = "localhost"
			// G124 concerns response cookies; Secure, HttpOnly and SameSite
			// have no meaning on one a client sends.
			req.AddCookie(&http.Cookie{Name: tc.sends, Value: string(token)}) //nolint:gosec // G124: a request cookie.
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if got, want := w.Code, http.StatusOK; got != want {
				t.Fatalf("got status %d, want %d (body %q)", got, want, w.Body.String())
			}
			// The token is stored once, under the expected key and no other.
			if got, want := gotKeys, []string{tc.wantKey}; !slices.Equal(got, want) {
				t.Errorf("token stored under %v, want %v", got, want)
			}
			if got, want := gotSubject, "user-3"; got != want {
				t.Errorf("subject: got %v, want %v", got, want)
			}
		})
	}
}

// TestJWTBootstrapCookieName verifies that the cookie written when
// bootstrapping from a query parameter carries the configured name, and the
// attributes that make it usable for the subsequent request.
func TestJWTBootstrapCookieName(t *testing.T) {
	ctx := t.Context()
	signer := setupSigner(t)
	pubKey, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}
	token, err := jwtutil.CreateVerificationToken(ctx, signer, "user-4", "role", "admin", time.Hour, "", "")
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	handler := websec.NewLocalhostHandler(okHandler(),
		websec.WithJWTCookie("auth_cookie", pubKey, "role", "admin"),
		websec.WithJWTCookieName("renamed"),
	)

	req := httptest.NewRequest(http.MethodGet, "/?token="+string(token), nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "localhost"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got, want := w.Code, http.StatusSeeOther; got != want {
		t.Fatalf("got status %d, want %d (body %q)", got, want, w.Body.String())
	}
	set := w.Result().Cookies()
	if len(set) != 1 {
		t.Fatalf("got %d cookies, want 1: %v", len(set), set)
	}
	ck := set[0]
	if got, want := ck.Name, "renamed"; got != want {
		t.Errorf("cookie name: got %v, want %v", got, want)
	}
	if got, want := ck.Value, string(token); got != want {
		t.Errorf("cookie value: got %v, want %v", got, want)
	}
	if !ck.HttpOnly {
		t.Error("cookie is not HttpOnly")
	}
	if !ck.Secure {
		t.Error("cookie is not Secure")
	}
	if got, want := ck.SameSite, http.SameSiteStrictMode; got != want {
		t.Errorf("cookie SameSite: got %v, want %v", got, want)
	}
	if got, want := ck.Path, "/"; got != want {
		t.Errorf("cookie path: got %v, want %v", got, want)
	}
}
