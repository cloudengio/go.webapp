// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package websec_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"time"

	"cloudeng.io/webapp/cookies"
	"cloudeng.io/webapp/webauth/jwtutil"
	"cloudeng.io/webapp/websec"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func ExampleNewLocalhostHandler() {
	// 1. Setup signing & verification keys
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := jwtutil.NewED25519Signer(priv, "key-1")
	pubKey, _ := signer.PublicKey()
	keys := jwk.NewSet()
	_ = keys.AddKey(pubKey)
	validator := jwtutil.NewValidator(keys)

	// 2. Wrap app with websec middleware
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := jwtutil.TokenFromContext(r.Context(), "session_token")
		sub, _ := tok.Subject()
		_, _ = w.Write([]byte("Hello, " + sub))
	})

	secured := websec.NewLocalhostHandler(appHandler,
		websec.WithAllowedPorts(8080),
		websec.WithJWTCookie("session_token", validator, "role", "admin"),
	)

	// 3. Deliver a token to the browser as the cookie the middleware reads.
	// The middleware only reads that cookie; setting it is the application's
	// responsibility.
	tokenBytes, _ := jwtutil.CreateVerificationToken(context.Background(),
		signer, "local-user", "role", "admin", time.Hour, "", "")

	mux := http.NewServeMux()
	mux.Handle("/", secured)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// cookies.Secure supplies the name, and the Secure, HttpOnly and
		// SameSite attributes.
		cookies.Secure("session_token").Set(w, &http.Cookie{ //nolint:gosec // G124: set by cookies.Secure, not here.
			Value: string(tokenBytes),
			Path:  "/",
		})
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	})

	fmt.Println("Open in browser: http://127.0.0.1:8080/login")

	_ = http.ListenAndServe("127.0.0.1:8080", mux) //nolint:gosec // G114: an example, not a server to be run.
}
