// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil_test

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"time"

	"cloudeng.io/webapp/webauth/jwtutil"
)

func ExampleJWTIssuer() {
	// 1. Setup signing keys.
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := jwtutil.NewED25519Signer(priv, "key-1")

	mux := http.NewServeMux()

	// 2. Direct issuance (e.g. for API clients or curl):
	// Returns a JSON payload {"token": "..."} to any visitor.
	apiIssuer := jwtutil.JWTIssuerMust(signer,
		jwtutil.WithSubject("service-account"),
		jwtutil.WithIssuer("auth-service"),
		jwtutil.WithAudience("api.example.com"),
		jwtutil.WithClaim("role", "reader"),
		jwtutil.WithExpiration(time.Hour),
		jwtutil.WithJSON(true),
	)
	mux.Handle("/api/token", apiIssuer)

	// 3. Cookie issuance with redirect (e.g. for browser login into a localhost app):
	// Sets a secure HTTP cookie and redirects the browser to the dashboard.
	loginIssuer := jwtutil.JWTIssuerMust(signer,
		jwtutil.WithSubject("local-user"),
		jwtutil.WithClaim("role", "admin"),
		jwtutil.WithExpiration(8*time.Hour),
		jwtutil.WithCookie("session_token"),
		jwtutil.WithRedirect("/dashboard"),
	)
	mux.Handle("/login", loginIssuer)

	fmt.Println("Auth endpoints registered at /api/token and /login")

	_ = http.ListenAndServe("127.0.0.1:8080", mux) //nolint:gosec // G114: example code, not meant to be run.
}
