// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package websec_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"time"

	"cloudeng.io/webapp/webauth/jwtutil"
	"cloudeng.io/webapp/websec"
)

func ExampleNewLocalhostHandler() {
	// 1. Setup signing & verification keys
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := jwtutil.NewED25519Signer(priv, "key-1")
	pubKey, _ := signer.PublicKey()

	// 2. Wrap app with websec middleware
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := websec.TokenFromContext(r.Context())
		sub, _ := tok.Subject()
		w.Write([]byte("Hello, " + sub))
	})

	secured := websec.NewLocalhostHandler(appHandler,
		websec.WithAllowedPorts(8080),
		websec.WithJWTCookie("session_token", pubKey, "role", "admin"),
	)

	// 3. Generate bootstrap URL to open in browser
	tokenBytes, _ := jwtutil.CreateVerificationToken(context.Background(),
		signer, "local-user", "role", "admin", time.Hour, "", "")
	bootstrapURL, _ := jwtutil.VerificationURL("http://127.0.0.1:8080/dashboard", tokenBytes)

	// Prints: http://127.0.0.1:8080/dashboard?token=eyJhbGci...
	// When clicked, sets the cookie and redirects cleanly to /dashboard
	println("Open in browser:", bootstrapURL)

	http.ListenAndServe("127.0.0.1:8080", secured)
}
