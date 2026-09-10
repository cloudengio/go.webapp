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
	"sync/atomic"
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
		name          string
		secFetchSite  string
		origin        string
		referer       string
		opts          []websec.Option
		wantStatus    int
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

func TestCounters(t *testing.T) {
	var totalCount, nonLoopbackCount, invalidHostCount, crossSiteCount atomic.Int32
	incTotal := func(context.Context) { totalCount.Add(1) }
	incNonLoopback := func(context.Context) { nonLoopbackCount.Add(1) }
	incInvalidHost := func(context.Context) { invalidHostCount.Add(1) }
	incCrossSite := func(context.Context) { crossSiteCount.Add(1) }

	handler := websec.NewHandler(okHandler(),
		websec.WithCounters(incTotal, incNonLoopback, incInvalidHost, incCrossSite),
	)

	// Valid request -> no counter increments
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "127.0.0.1:1234"
	req1.Host = "localhost"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if totalCount.Load() != 0 || nonLoopbackCount.Load() != 0 || invalidHostCount.Load() != 0 || crossSiteCount.Load() != 0 {
		t.Errorf("expected 0 for all counters, got total=%d, nonLoopback=%d, invalidHost=%d, crossSite=%d",
			totalCount.Load(), nonLoopbackCount.Load(), invalidHostCount.Load(), crossSiteCount.Load())
	}

	// 1. Non-loopback rejection
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "192.168.1.1:1234"
	req2.Host = "localhost"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if totalCount.Load() != 1 || nonLoopbackCount.Load() != 1 || invalidHostCount.Load() != 0 || crossSiteCount.Load() != 0 {
		t.Errorf("after non-loopback: got total=%d (want 1), nonLoopback=%d (want 1)", totalCount.Load(), nonLoopbackCount.Load())
	}

	// 2. Invalid host rejection
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.RemoteAddr = "127.0.0.1:1234"
	req3.Host = "evil.com"
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if totalCount.Load() != 2 || nonLoopbackCount.Load() != 1 || invalidHostCount.Load() != 1 || crossSiteCount.Load() != 0 {
		t.Errorf("after invalid host: got total=%d (want 2), invalidHost=%d (want 1)", totalCount.Load(), invalidHostCount.Load())
	}

	// 3. Cross-site rejection
	req4 := httptest.NewRequest(http.MethodGet, "/", nil)
	req4.RemoteAddr = "127.0.0.1:1234"
	req4.Host = "localhost"
	req4.Header.Set("Sec-Fetch-Site", "cross-site")
	w4 := httptest.NewRecorder()
	handler.ServeHTTP(w4, req4)
	if totalCount.Load() != 3 || nonLoopbackCount.Load() != 1 || invalidHostCount.Load() != 1 || crossSiteCount.Load() != 1 {
		t.Errorf("after cross-site: got total=%d (want 3), crossSite=%d (want 1)", totalCount.Load(), crossSiteCount.Load())
	}
}

func TestIndividualCounters(t *testing.T) {
	var nonLoopbackCount atomic.Int32
	handler := websec.NewHandler(okHandler(),
		websec.WithNonLoopbackCounter(func(context.Context) { nonLoopbackCount.Add(1) }),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	req.Host = "localhost"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if nonLoopbackCount.Load() != 1 {
		t.Errorf("expected nonLoopbackCount=1, got %d", nonLoopbackCount.Load())
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
		if tok, ok := websec.TokenFromContext(r.Context()); ok {
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
				req.AddCookie(&http.Cookie{
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
	var invalidJWTCnt, totalCnt atomic.Int32
	signer := setupSigner(t)
	pubKey, _ := signer.PublicKey()

	handler := websec.NewLocalhostHandler(okHandler(),
		websec.WithJWTCookie("test_cookie", pubKey, "perm", "read"),
		websec.WithJWTBootstrapQueryParam(""),
		websec.WithInvalidJWTCounter(func(context.Context) { invalidJWTCnt.Add(1) }),
		websec.WithDeniedCounter(func(context.Context) { totalCnt.Add(1) }),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "localhost"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if invalidJWTCnt.Load() != 1 {
		t.Errorf("got invalidJWTCnt %d, want 1", invalidJWTCnt.Load())
	}
	if totalCnt.Load() != 1 {
		t.Errorf("got totalCnt %d, want 1", totalCnt.Load())
	}
}
