// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"cloudeng.io/cmdutil/keys"
)

// SHA256SignatureFromHeader returns a function that extracts and decodes the
// HMAC SHA256 signature from the specified header in the HTTP request.
func SHA256SignatureFromHeader(headerName string) func(req *http.Request) ([]byte, int) {
	return func(req *http.Request) ([]byte, int) {
		signatureHeader := req.Header.Get(headerName)
		if signatureHeader == "" {
			return nil, http.StatusBadRequest
		}

		parts := strings.SplitN(signatureHeader, "=", 2)
		if len(parts) != 2 || parts[0] != "sha256" {
			return nil, http.StatusBadRequest
		}

		sig, err := hex.DecodeString(parts[1])
		if err != nil {
			return nil, http.StatusBadRequest
		}

		return sig, http.StatusOK
	}
}

// SignatureValidator returns a Validator that verifies webhook payloads
// using one of possibly multiple Tokens returned by the getTokens function.
// The token value is a byte slice that the validator uses to compute the HMAC
// SHA256 signature of the payload and compare it to the signature provided in
// the request header as returned by the getSignature function.
// If a match is found, the payload is considered valid and returned; if none
// of the returned tokens' secrets match the signature, the payload is rejected
// and an appropriate HTTP status code is returned to indicate the error.
// It is the responsibility of the getTokens function to retrieve the tokens
// from the appropriate source, such as a file or a key store.
func SignatureValidator(getSignature func(req *http.Request) ([]byte, int), getTokens func(ctx context.Context) ([]keys.Token, error)) (Validator, error) {
	return func(req *http.Request) ([]byte, int) {
		payload, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, http.StatusBadRequest
		}
		defer req.Body.Close()

		sig, code := getSignature(req)
		if code != http.StatusOK {
			return nil, code
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

// SignHTTPRequest signs the given payload using the provided secret and sets
// the signature in the specified header of the HTTP request.
func SignHTTPRequest(header http.Header, payload []byte, secret []byte, headerName string) error {
	mac := hmac.New(sha256.New, secret)
	_, err := mac.Write(payload)
	if err != nil {
		return fmt.Errorf("error computing HMAC signature: %v", err)
	}
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	header.Set(headerName, signature)
	header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	return nil
}
