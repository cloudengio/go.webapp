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
// using one of possibly multiple secrets stored in the provided file.ReadFileFS
// instance at the provided path(s). Multiple secrets allow for rotation since
// GitHub does not currently directly support rotation the only way to change
// the secret used by GitHub is to create a new one, wait for it be picked up
// by the validator (allowing for any caching in the file.ReadFileFS
// implementation to expire), then change the secret used by GitHub to the new
// one and remove the old secret from the file.ReadFileFS.
// Ideally, the file.ReadFileFS instannce should be an in-memory or
// caching implementation to avoid the overhead of reading the secret from disk on
// every request but that also allows for the secret to be refreshed.
func GitHubValidator(fs file.ReadFileFS, secretPaths ...string) Validator {
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

		for _, secretPath := range secretPaths {
			secret, err := fs.ReadFileCtx(req.Context(), secretPath)
			if err != nil {
				return nil, http.StatusInternalServerError
			}
			mac := hmac.New(sha256.New, secret)
			_, _ = mac.Write(payload)
			if hmac.Equal(sig, mac.Sum(nil)) {
				return payload, http.StatusOK
			}
		}
		return nil, http.StatusUnauthorized
	}
}
