// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cloudeng.io/webapp/cookies"
	"cloudeng.io/webapp/webauth/jwtutil"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func newTestSigner(t *testing.T) jwtutil.Signer {
	t.Helper()
	info, err := jwtutil.NewED25519KeyInfo("", "test-issuer-key")
	if err != nil {
		t.Fatalf("NewED25519KeyInfo: %v", err)
	}
	signer, err := jwtutil.NewSignerFromKeyInfo(context.Background(), info)
	if err != nil {
		t.Fatalf("NewSignerFromKeyInfo: %v", err)
	}
	return signer
}

func TestJWTIssuerDirectText(t *testing.T) {
	signer := newTestSigner(t)
	handler := jwtutil.NewJWTIssuerMust(signer,
		jwtutil.WithSubject("user-123"),
		jwtutil.WithIssuer("test-service"),
		jwtutil.WithAudience("api", "web"),
		jwtutil.WithExpiration(30*time.Minute),
		jwtutil.WithClaims(map[string]any{"role": "admin"}),
	)

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got, want := w.Code, http.StatusOK; got != want {
		t.Fatalf("got status %d, want %d", got, want)
	}
	if got, want := w.Header().Get("Cache-Control"), "no-store"; got != want {
		t.Errorf("got Cache-Control %q, want %q", got, want)
	}

	tokenStr := w.Body.String()
	if tokenStr == "" {
		t.Fatal("expected non-empty token string in response body")
	}

	tok, err := signer.ParseAndValidate(req.Context(), []byte(tokenStr))
	if err != nil {
		t.Fatalf("failed to validate issued token: %v", err)
	}

	sub, _ := tok.Subject()
	if got, want := sub, "user-123"; got != want {
		t.Errorf("got subject %q, want %q", got, want)
	}
	iss, _ := tok.Issuer()
	if got, want := iss, "test-service"; got != want {
		t.Errorf("got issuer %q, want %q", got, want)
	}
	aud, _ := tok.Audience()
	if len(aud) != 2 || aud[0] != "api" || aud[1] != "web" {
		t.Errorf("got audience %v, want [api web]", aud)
	}
	var role string
	if err := tok.Get("role", &role); err != nil || role != "admin" {
		t.Errorf("got role claim %q, want admin (err=%v)", role, err)
	}
}

func TestJWTIssuerDirectJSON(t *testing.T) {
	signer := newTestSigner(t)

	t.Run("WithJSON option", func(t *testing.T) {
		handler := jwtutil.JWTIssuerMust(signer,
			jwtutil.WithSubject("json-user"),
			jwtutil.WithJSON(true),
		)

		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusOK; got != want {
			t.Fatalf("got status %d, want %d", got, want)
		}
		if got, want := w.Header().Get("Content-Type"), "application/json"; got != want {
			t.Errorf("got content-type %q, want %q", got, want)
		}

		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode JSON response: %v", err)
		}
		tokenStr, ok := resp["token"]
		if !ok || tokenStr == "" {
			t.Fatalf("expected token field in JSON: %v", resp)
		}

		tok, err := signer.ParseAndValidate(req.Context(), []byte(tokenStr))
		if err != nil {
			t.Fatalf("failed to validate issued token: %v", err)
		}
		sub, _ := tok.Subject()
		if got, want := sub, "json-user"; got != want {
			t.Errorf("got subject %q, want %q", got, want)
		}
	})

	t.Run("Accept application/json header", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSubject("header-user"),
		)

		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusOK; got != want {
			t.Fatalf("got status %d, want %d", got, want)
		}
		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode JSON response: %v", err)
		}
		if resp["token"] == "" {
			t.Fatal("expected token in JSON response")
		}
	})
}

func TestJWTIssuerSecureCookie(t *testing.T) {
	signer := newTestSigner(t)

	t.Run("default attributes", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSubject("cookie-user"),
			jwtutil.WithSecureCookie("session_token", cookies.ScopeAndDuration{}),
			jwtutil.WithExpiration(2*time.Hour),
		)

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusOK; got != want {
			t.Fatalf("got status %d, want %d", got, want)
		}

		respCookies := w.Result().Cookies()
		var sessionCookie *http.Cookie
		for _, c := range respCookies {
			if c.Name == "session_token" {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Fatalf("expected cookie session_token in response, got %v", respCookies)
		}
		if !sessionCookie.Secure || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie missing secure flags: Secure=%v, HttpOnly=%v, SameSite=%v",
				sessionCookie.Secure, sessionCookie.HttpOnly, sessionCookie.SameSite)
		}
		if sessionCookie.Path != "/" {
			t.Errorf(`got cookie path %q, want default "/"`, sessionCookie.Path)
		}
		// The cookie's own duration was left unset, so it defaults to the
		// token's own expiration.
		if want := int((2 * time.Hour).Seconds()); sessionCookie.MaxAge != want {
			t.Errorf("got cookie MaxAge %d, want %d", sessionCookie.MaxAge, want)
		}

		tok, err := signer.ParseAndValidate(req.Context(), []byte(sessionCookie.Value))
		if err != nil {
			t.Fatalf("failed to validate token in cookie: %v", err)
		}
		sub, _ := tok.Subject()
		if got, want := sub, "cookie-user"; got != want {
			t.Errorf("got subject %q, want %q", got, want)
		}
	})

	t.Run("explicit scope overrides defaults", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSubject("secure-scoped-user"),
			jwtutil.WithSecureCookie("scoped_cookie", cookies.ScopeAndDuration{
				Domain:   "app.example.com",
				Path:     "/account",
				Duration: 10 * time.Minute,
			}),
			jwtutil.WithExpiration(2*time.Hour),
		)

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		respCookies := w.Result().Cookies()
		if len(respCookies) == 0 || respCookies[0].Name != "scoped_cookie" {
			t.Fatalf("expected scoped_cookie, got %v", respCookies)
		}
		got := respCookies[0]
		if got.Domain != "app.example.com" || got.Path != "/account" {
			t.Errorf("got domain=%q path=%q, want domain=%q path=%q", got.Domain, got.Path, "app.example.com", "/account")
		}
		// The cookie's own (shorter) duration, not the token's expiration,
		// governs its Max-Age.
		if want := int((10 * time.Minute).Seconds()); got.MaxAge != want {
			t.Errorf("got cookie MaxAge %d, want %d", got.MaxAge, want)
		}
	})
}

func TestJWTIssuerInsecureCookie(t *testing.T) {
	signer := newTestSigner(t)

	t.Run("default attributes", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSubject("insecure-user"),
			jwtutil.WithInsecureCookie("plain_cookie", cookies.ScopeAndDuration{Path: "/api"}),
		)

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		respCookies := w.Result().Cookies()
		if len(respCookies) == 0 || respCookies[0].Name != "plain_cookie" {
			t.Fatalf("expected plain_cookie, got %v", respCookies)
		}
		if respCookies[0].Path != "/api" {
			t.Errorf("got cookie path %q, want /api", respCookies[0].Path)
		}
		if respCookies[0].Secure || respCookies[0].HttpOnly {
			t.Errorf("expected Secure=false and HttpOnly=false for insecure cookie, got Secure=%v HttpOnly=%v",
				respCookies[0].Secure, respCookies[0].HttpOnly)
		}
		// SameSiteDefaultMode is set internally, but http.Cookie.String omits
		// the attribute entirely for it, so it round-trips back as the zero
		// value (unset), letting the browser apply its own default.
		if respCookies[0].SameSite != 0 {
			t.Errorf("got SameSite %v, want 0 (unset)", respCookies[0].SameSite)
		}
	})

	t.Run("cookie duration independent of token expiration", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSubject("insecure-scoped-user"),
			jwtutil.WithInsecureCookie("plain_scoped", cookies.ScopeAndDuration{Duration: 5 * time.Minute}),
			jwtutil.WithExpiration(time.Hour),
		)

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		respCookies := w.Result().Cookies()
		if len(respCookies) == 0 || respCookies[0].Name != "plain_scoped" {
			t.Fatalf("expected plain_scoped cookie, got %v", respCookies)
		}
		if respCookies[0].Secure {
			t.Errorf("expected Secure=false for insecure cookie")
		}
		if want := int((5 * time.Minute).Seconds()); respCookies[0].MaxAge != want {
			t.Errorf("got cookie MaxAge %d, want %d", respCookies[0].MaxAge, want)
		}
	})
}

func TestJWTIssuerRedirect(t *testing.T) {
	signer := newTestSigner(t)

	t.Run("Static redirect", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSecureCookie("session_token", cookies.ScopeAndDuration{}),
			jwtutil.WithRedirect("/dashboard"),
		)

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusSeeOther; got != want {
			t.Fatalf("got status %d, want %d", got, want)
		}
		if got, want := w.Header().Get("Location"), "/dashboard"; got != want {
			t.Errorf("got location %q, want %q", got, want)
		}
	})

	t.Run("Dynamic redirect from query parameter", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSecureCookie("session_token", cookies.ScopeAndDuration{}),
			jwtutil.WithRedirect("/default"),
			jwtutil.WithRedirectQueryParam("redirect"),
		)

		req := httptest.NewRequest(http.MethodGet, "/login?redirect=/custom-target", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusSeeOther; got != want {
			t.Fatalf("got status %d, want %d", got, want)
		}
		if got, want := w.Header().Get("Location"), "/custom-target"; got != want {
			t.Errorf("got location %q, want %q", got, want)
		}
	})
}

func TestJWTIssuerOpenRedirectPrevention(t *testing.T) {
	signer := newTestSigner(t)

	untrusted := []string{
		"https://attacker.example",
		"http://attacker.example/steal",
		"//attacker.example",
		"///attacker.example",
		"/\\attacker.example",
		"\\attacker.example",
		"/evil\\test",
		"javascript:alert(1)",
		"data:text/html,evil",
	}

	for _, target := range untrusted {
		t.Run(target, func(t *testing.T) {
			handler := jwtutil.NewJWTIssuerMust(signer,
				jwtutil.WithSecureCookie("session_token", cookies.ScopeAndDuration{}),
				jwtutil.WithRedirect("/safe-fallback"),
				jwtutil.WithRedirectQueryParam("redirect"),
			)

			req := httptest.NewRequest(http.MethodGet, "/login?redirect="+target, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if got, want := w.Code, http.StatusSeeOther; got != want {
				t.Fatalf("got status %d, want %d", got, want)
			}
			if got, want := w.Header().Get("Location"), "/safe-fallback"; got != want {
				t.Errorf("untrusted destination %q redirected to %q, want safe fallback %q", target, got, want)
			}
		})
	}

	t.Run("untrusted redirect without fallback does not redirect", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSecureCookie("session_token", cookies.ScopeAndDuration{}),
			jwtutil.WithRedirectQueryParam("redirect"),
		)
		req := httptest.NewRequest(http.MethodGet, "/login?redirect=https://attacker.example", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusOK; got != want {
			t.Fatalf("got status %d, want %d", got, want)
		}
		if loc := w.Header().Get("Location"); loc != "" {
			t.Errorf("unexpected Location header %q", loc)
		}
	})
}

func TestJWTIssuerAllowedRedirects(t *testing.T) {
	signer := newTestSigner(t)

	handler := jwtutil.NewJWTIssuerMust(signer,
		jwtutil.WithSecureCookie("session_token", cookies.ScopeAndDuration{}),
		jwtutil.WithRedirect("/safe-fallback"),
		jwtutil.WithRedirectQueryParam("redirect"),
		jwtutil.WithAllowedRedirects(
			"https://trusted.example.com",
			"https://partner.example.com/callback",
		),
	)

	t.Run("allowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/login?redirect=https://trusted.example.com/welcome", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Header().Get("Location"), "https://trusted.example.com/welcome"; got != want {
			t.Errorf("got location %q, want %q", got, want)
		}
	})

	t.Run("allowed path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/login?redirect=https://partner.example.com/callback", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Header().Get("Location"), "https://partner.example.com/callback"; got != want {
			t.Errorf("got location %q, want %q", got, want)
		}
	})

	t.Run("disallowed path on partner origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/login?redirect=https://partner.example.com/other", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Header().Get("Location"), "/safe-fallback"; got != want {
			t.Errorf("got location %q, want safe fallback %q", got, want)
		}
	})

	t.Run("disallowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/login?redirect=https://evil.example.com", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Header().Get("Location"), "/safe-fallback"; got != want {
			t.Errorf("got location %q, want safe fallback %q", got, want)
		}
	})
}

func TestJWTIssuerBothCookieAndDirect(t *testing.T) {
	signer := newTestSigner(t)
	handler := jwtutil.NewJWTIssuerMust(signer,
		jwtutil.WithSubject("both-user"),
		jwtutil.WithSecureCookie("session_token", cookies.ScopeAndDuration{}),
		jwtutil.WithDirect(true),
	)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got, want := w.Code, http.StatusOK; got != want {
		t.Fatalf("got status %d, want %d", got, want)
	}

	// Verify cookie was set
	cookies := w.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != "session_token" {
		t.Fatalf("expected cookie session_token, got %v", cookies)
	}

	// Verify body also contains token
	tokenStr := w.Body.String()
	if tokenStr != cookies[0].Value {
		t.Errorf("body token %q does not match cookie token %q", tokenStr, cookies[0].Value)
	}
}

func TestJWTIssuerNilSigner(t *testing.T) {
	_, err := jwtutil.NewJWTIssuer(nil)
	if err == nil {
		t.Fatal("expected error when signer is nil")
	}
}

func TestJWTIssuerMust(t *testing.T) {
	signer := newTestSigner(t)
	// Valid configuration should not panic
	_ = jwtutil.NewJWTIssuerMust(signer)

	t.Run("panic on nil signer", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for nil signer")
			}
		}()
		jwtutil.NewJWTIssuerMust(nil)
	})

	t.Run("panic on conflicting cookies", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for conflicting cookies")
			}
		}()
		jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSecureCookie("c1", cookies.ScopeAndDuration{}),
			jwtutil.WithInsecureCookie("c2", cookies.ScopeAndDuration{}),
		)
	})
}

func TestJWTIssuerCookieConflicts(t *testing.T) {
	signer := newTestSigner(t)
	tests := []struct {
		name string
		opts []jwtutil.JWTIssuerOption
	}{
		{
			name: "both secure and insecure",
			opts: []jwtutil.JWTIssuerOption{
				jwtutil.WithSecureCookie("c1", cookies.ScopeAndDuration{}),
				jwtutil.WithInsecureCookie("c2", cookies.ScopeAndDuration{}),
			},
		},
		{
			name: "insecure then secure",
			opts: []jwtutil.JWTIssuerOption{
				jwtutil.WithInsecureCookie("c1", cookies.ScopeAndDuration{}),
				jwtutil.WithSecureCookie("c2", cookies.ScopeAndDuration{}),
			},
		},
		{
			name: "multiple secure",
			opts: []jwtutil.JWTIssuerOption{
				jwtutil.WithSecureCookie("c1", cookies.ScopeAndDuration{}),
				jwtutil.WithSecureCookie("c2", cookies.ScopeAndDuration{}),
			},
		},
		{
			name: "multiple insecure",
			opts: []jwtutil.JWTIssuerOption{
				jwtutil.WithInsecureCookie("c1", cookies.ScopeAndDuration{}),
				jwtutil.WithInsecureCookie("c2", cookies.ScopeAndDuration{}),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwtutil.NewJWTIssuer(signer, tc.opts...)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestJWTIssuerClaimsWithOptions(t *testing.T) {
	signer := newTestSigner(t)
	claims := map[string]any{
		"org":  "cloudeng",
		"tier": "enterprise",
	}

	handler := jwtutil.NewJWTIssuerMust(signer,
		jwtutil.WithSubject("claims-user"),
		jwtutil.WithClaims(claims),
		jwtutil.WithNotBefore(-time.Second),
		jwtutil.WithExpiresIn(10*time.Minute),
	)

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	tokenStr := w.Body.String()
	tok, err := signer.ParseAndValidate(req.Context(), []byte(tokenStr),
		jwt.WithAcceptableSkew(time.Second),
	)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	var org, tier string
	if err := tok.Get("org", &org); err != nil || org != "cloudeng" {
		t.Errorf("expected org=cloudeng, got %q (err=%v)", org, err)
	}
	if err := tok.Get("tier", &tier); err != nil || tier != "enterprise" {
		t.Errorf("expected tier=enterprise, got %q (err=%v)", tier, err)
	}
}

func TestJWTIssuerCacheControl(t *testing.T) {
	signer := newTestSigner(t)

	cases := []struct {
		name string
		opts []jwtutil.JWTIssuerOption
	}{
		{"direct text", []jwtutil.JWTIssuerOption{jwtutil.WithSubject("u1")}},
		{"direct json", []jwtutil.JWTIssuerOption{jwtutil.WithSubject("u2"), jwtutil.WithJSON(true)}},
		{"cookie only", []jwtutil.JWTIssuerOption{jwtutil.WithSubject("u3"), jwtutil.WithSecureCookie("c", cookies.ScopeAndDuration{})}},
		{"cookie redirect", []jwtutil.JWTIssuerOption{jwtutil.WithSubject("u4"), jwtutil.WithSecureCookie("c", cookies.ScopeAndDuration{}), jwtutil.WithRedirect("/dash")}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := jwtutil.NewJWTIssuerMust(signer, tc.opts...)
			req := httptest.NewRequest(http.MethodGet, "/token", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if got, want := w.Header().Get("Cache-Control"), "no-store"; got != want {
				t.Errorf("got Cache-Control %q, want %q", got, want)
			}
		})
	}
}

func TestJWTIssuerReservedClaims(t *testing.T) {
	signer := newTestSigner(t)

	reservedKeys := []string{
		jwt.IssuerKey,
		jwt.SubjectKey,
		jwt.AudienceKey,
		jwt.ExpirationKey,
		jwt.NotBeforeKey,
		jwt.IssuedAtKey,
		jwt.JwtIDKey,
	}

	for _, key := range reservedKeys {
		t.Run("WithClaims/"+key, func(t *testing.T) {
			_, err := jwtutil.NewJWTIssuer(signer, jwtutil.WithClaims(map[string]any{key: "val"}))
			if err == nil {
				t.Fatalf("expected error for reserved claim in WithClaims %q, got nil", key)
			}
			if !errors.Is(err, jwtutil.ErrReservedClaim) {
				t.Errorf("expected ErrReservedClaim, got %v", err)
			}
			defer func() {
				r := recover()
				if r == nil {
					t.Errorf("expected panic for WithClaims with reserved key %q", key)
				}
			}()
			_ = jwtutil.NewJWTIssuerMust(signer, jwtutil.WithClaims(map[string]any{key: "val"}))
		})
	}
}
