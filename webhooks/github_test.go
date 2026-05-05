// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloudeng.io/file"
	"cloudeng.io/file/filetestutil"
	"cloudeng.io/webapp/webhooks"
)

func TestGitHubValidator(t *testing.T) {
	secret := "super-secret"

	fs := filetestutil.NewMockFS(filetestutil.FSWithConstantContents([]byte(secret), 1))
	validator := webhooks.GitHubValidator(fs.(file.ReadFileFS), "github.secret")

	payload := []byte(`{"action": "push"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	t.Run("ValidSignature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", signature)

		got, status := validator(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})

	t.Run("MissingSignature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))

		_, status := validator(req)
		if status != http.StatusUnauthorized {
			t.Errorf("got status %d, want %d", status, http.StatusUnauthorized)
		}
	})

	t.Run("InvalidSignatureFormat", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", "sha1=foo")

		_, status := validator(req)
		if status != http.StatusUnauthorized {
			t.Errorf("got status %d, want %d", status, http.StatusUnauthorized)
		}
	})

	t.Run("InvalidSignatureValue", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", "sha256=abcdef123456")

		_, status := validator(req)
		if status != http.StatusUnauthorized {
			t.Errorf("got status %d, want %d", status, http.StatusUnauthorized)
		}
	})
}
