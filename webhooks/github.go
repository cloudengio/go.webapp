// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"

	"cloudeng.io/file"
)

// GitHubValidator returns a Validator that verifies GitHub webhook payloads
// using the secret stored at the provided path and the X-Hub-Signature-256 header.
// Ideally, the file.ReadFileFS instannce should be an in-memory or
// caching implementation to avoid the overhead of reading the secret from disk on
// every request but that also allows for the secret to be refreshed.
func GitHubValidator(fs file.ReadFileFS, secretPath string) Validator {
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

		secret, err := fs.ReadFileCtx(req.Context(), secretPath)
		if err != nil {
			return nil, http.StatusInternalServerError
		}
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(payload)
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return nil, http.StatusUnauthorized
		}

		return payload, http.StatusOK
	}
}
