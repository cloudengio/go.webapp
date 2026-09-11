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
	handler := jwtutil.NewJWTIssuer(signer,
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
		handler := jwtutil.JWTIssuer(signer,
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
		handler := jwtutil.NewJWTIssuer(signer,
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

func TestJWTIssuerCookie(t *testing.T) {
	signer := newTestSigner(t)

	t.Run("Secure cookie default", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuer(signer,
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

	t.Run("Insecure cookie", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuer(signer,
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
	})
}

func TestJWTIssuerRedirect(t *testing.T) {
	signer := newTestSigner(t)

	t.Run("Static redirect", func(t *testing.T) {
		handler := jwtutil.NewJWTIssuer(signer,
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
		handler := jwtutil.NewJWTIssuer(signer,
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

func TestJWTIssuerBothCookieAndDirect(t *testing.T) {
	signer := newTestSigner(t)
	handler := jwtutil.NewJWTIssuer(signer,
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
	handler := jwtutil.NewJWTIssuer(nil)

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got, want := w.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("got status %d, want %d", got, want)
	}
}

func TestJWTIssuerClaimsWithOptions(t *testing.T) {
	signer := newTestSigner(t)
	claims := map[string]any{
		"org":  "cloudeng",
		"tier": "enterprise",
	}

	handler := jwtutil.NewJWTIssuer(signer,
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
