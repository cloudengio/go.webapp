// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package websec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

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
