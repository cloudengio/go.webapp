// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cloudeng.io/webapp/webauth/jwtutil"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func newTestSigner(t *testing.T) jwtutil.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	signer, err := jwtutil.NewED25519Signer(priv, "test-issuer-key")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
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
		jwtutil.WithClaim("role", "admin"),
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
			jwtutil.WithCookie("session_token"),
			jwtutil.WithExpiration(2*time.Hour),
		)

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusOK; got != want {
			t.Fatalf("got status %d, want %d", got, want)
		}

		cookies := w.Result().Cookies()
		var sessionCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "session_token" {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Fatalf("expected cookie session_token in response, got %v", cookies)
		}
		if !sessionCookie.Secure || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie missing secure flags: Secure=%v, HttpOnly=%v, SameSite=%v",
				sessionCookie.Secure, sessionCookie.HttpOnly, sessionCookie.SameSite)
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

	t.Run("with SameSite override", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSubject("secure-lax-user"),
			jwtutil.WithSecureCookie("secure_lax"),
			jwtutil.WithCookieSameSite(http.SameSiteLaxMode),
		)

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		cookies := w.Result().Cookies()
		if len(cookies) == 0 || cookies[0].Name != "secure_lax" {
			t.Fatalf("expected secure_lax cookie, got %v", cookies)
		}
		if !cookies[0].Secure {
			t.Errorf("expected Secure=true for secure cookie")
		}
		if cookies[0].SameSite != http.SameSiteLaxMode {
			t.Errorf("got SameSite %v, want SameSiteLaxMode (%v)", cookies[0].SameSite, http.SameSiteLaxMode)
		}
	})
}

func TestJWTIssuerInsecureCookie(t *testing.T) {
	signer := newTestSigner(t)

	t.Run("default attributes", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSubject("insecure-user"),
			jwtutil.WithInsecureCookie("plain_cookie"),
			jwtutil.WithCookiePath("/api"),
		)

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		cookies := w.Result().Cookies()
		if len(cookies) == 0 || cookies[0].Name != "plain_cookie" {
			t.Fatalf("expected plain_cookie, got %v", cookies)
		}
		if cookies[0].Path != "/api" {
			t.Errorf("got cookie path %q, want /api", cookies[0].Path)
		}
		if cookies[0].Secure {
			t.Errorf("expected Secure=false for insecure cookie")
		}
		if cookies[0].SameSite != 0 {
			t.Errorf("got SameSite %v, want 0 (unset)", cookies[0].SameSite)
		}
	})

	t.Run("with SameSite override", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithSubject("insecure-lax-user"),
			jwtutil.WithInsecureCookie("plain_lax"),
			jwtutil.WithCookieSameSite(http.SameSiteLaxMode),
		)

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		cookies := w.Result().Cookies()
		if len(cookies) == 0 || cookies[0].Name != "plain_lax" {
			t.Fatalf("expected plain_lax cookie, got %v", cookies)
		}
		if cookies[0].Secure {
			t.Errorf("expected Secure=false for insecure cookie")
		}
		if cookies[0].SameSite != http.SameSiteLaxMode {
			t.Errorf("got SameSite %v, want SameSiteLaxMode (%v)", cookies[0].SameSite, http.SameSiteLaxMode)
		}
	})
}

func TestJWTIssuerRedirect(t *testing.T) {
	signer := newTestSigner(t)

	t.Run("Static redirect", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuerMust(signer,
			jwtutil.WithCookie("session_token"),
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
			jwtutil.WithCookie("session_token"),
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
				jwtutil.WithCookie("session_token"),
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
			jwtutil.WithCookie("session_token"),
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
		jwtutil.WithCookie("session_token"),
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
		jwtutil.WithCookie("session_token"),
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
			jwtutil.WithSecureCookie("c1"),
			jwtutil.WithInsecureCookie("c2"),
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
				jwtutil.WithSecureCookie("c1"),
				jwtutil.WithInsecureCookie("c2"),
			},
		},
		{
			name: "insecure then secure",
			opts: []jwtutil.JWTIssuerOption{
				jwtutil.WithInsecureCookie("c1"),
				jwtutil.WithSecureCookie("c2"),
			},
		},
		{
			name: "multiple secure",
			opts: []jwtutil.JWTIssuerOption{
				jwtutil.WithSecureCookie("c1"),
				jwtutil.WithSecureCookie("c2"),
			},
		},
		{
			name: "multiple insecure",
			opts: []jwtutil.JWTIssuerOption{
				jwtutil.WithInsecureCookie("c1"),
				jwtutil.WithInsecureCookie("c2"),
			},
		},
		{
			name: "WithCookie then WithInsecureCookie",
			opts: []jwtutil.JWTIssuerOption{
				jwtutil.WithCookie("c1"),
				jwtutil.WithInsecureCookie("c2"),
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
		{"cookie only", []jwtutil.JWTIssuerOption{jwtutil.WithSubject("u3"), jwtutil.WithCookie("c")}},
		{"cookie redirect", []jwtutil.JWTIssuerOption{jwtutil.WithSubject("u4"), jwtutil.WithCookie("c"), jwtutil.WithRedirect("/dash")}},
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
