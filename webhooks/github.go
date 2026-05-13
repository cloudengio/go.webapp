// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"

	"cloudeng.io/cmdutil/keys"
)

// GitHubValidator returns a Validator that verifies GitHub webhook payloads
// using one of possibly multiple Tokens returned by the getTokens function.
// The tokens are expected to be provided as byte slices, and the validator
// will compute the HMAC SHA256 signature of the payload using each token and
// compare it to the signature provided in the "X-Hub-Signature-256" header
// of the request. If a match is found, the payload is considered valid and
// returned; otherwise, an appropriate HTTP status code is returned to indicate
// the error.
// It is the responsibility of the getTokens function to retrieve the tokens
// from the appropriate source, such as a file or a key store, and to handle
// any necessary parsing or error handling related to that retrieval.
// Similarly getTokens is responsible for handling key rotation or replacement.
func GitHubValidator(ctx context.Context, getTokens func(ctx context.Context) ([]keys.Token, error)) (Validator, error) {
	return func(req *http.Request) ([]byte, int) {
		payload, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, http.StatusBadRequest
		}
		defer req.Body.Close()

		signatureHeader := req.Header.Get("X-Hub-Signature-256")
		if signatureHeader == "" {
			return nil, http.StatusUnauthorized
		}

		parts := strings.SplitN(signatureHeader, "=", 2)
		if len(parts) != 2 || parts[0] != "sha256" {
			return nil, http.StatusUnauthorized
		}

		sig, err := hex.DecodeString(parts[1])
		if err != nil {
			return nil, http.StatusUnauthorized
		}

		tokens, err := getTokens(req.Context())
		if err != nil {
			return nil, http.StatusInternalServerError
		}
		for _, token := range tokens {
			mac := hmac.New(sha256.New, token.Value())
			defer token.Clear() // Clear the token value from memory after use
			_, _ = mac.Write(payload)
			if hmac.Equal(sig, mac.Sum(nil)) {
				return payload, http.StatusOK
			}
		}
		return nil, http.StatusUnauthorized
	}, nil
}
