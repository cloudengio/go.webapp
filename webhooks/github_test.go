// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloudeng.io/file"
	"cloudeng.io/file/filetestutil"
	"cloudeng.io/webapp/webhooks"
)

// mapFS is a simple in-memory ReadFileFS keyed by path.
type mapFS map[string][]byte

func (m mapFS) ReadFile(name string) ([]byte, error) {
	return m.ReadFileCtx(context.Background(), name)
}

func (m mapFS) ReadFileCtx(_ context.Context, name string) ([]byte, error) {
	if data, ok := m[name]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("%s: not found", name)
}

func sign(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestGitHubValidator(t *testing.T) {
	secret := "super-secret"

	fs := filetestutil.NewMockFS(filetestutil.FSWithConstantContents([]byte(secret), 1))
	validator := webhooks.GitHubValidator(fs.(file.ReadFileFS), "github.secret")

	payload := []byte(`{"action": "push"}`)
	signature := sign([]byte(secret), payload)

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

func TestGitHubValidatorMultipleSecrets(t *testing.T) {
	payload := []byte(`{"action": "push"}`)
	secretA := []byte("secret-a")
	secretB := []byte("secret-b")

	fs := mapFS{
		"path/a": secretA,
		"path/b": secretB,
	}

	t.Run("FirstSecretMatches", func(t *testing.T) {
		v := webhooks.GitHubValidator(fs, "path/a", "path/b")
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sign(secretA, payload))
		got, status := v(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})

	t.Run("SecondSecretMatches", func(t *testing.T) {
		v := webhooks.GitHubValidator(fs, "path/a", "path/b")
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sign(secretB, payload))
		got, status := v(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})

	t.Run("NoSecretMatches", func(t *testing.T) {
		v := webhooks.GitHubValidator(fs, "path/a", "path/b")
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sign([]byte("wrong"), payload))
		_, status := v(req)
		if status != http.StatusUnauthorized {
			t.Errorf("got status %d, want %d", status, http.StatusUnauthorized)
		}
	})

	t.Run("UnreadableSecretPath", func(t *testing.T) {
		v := webhooks.GitHubValidator(fs, "path/nonexistent")
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sign(secretA, payload))
		_, status := v(req)
		if status != http.StatusInternalServerError {
			t.Errorf("got status %d, want %d", status, http.StatusInternalServerError)
		}
	})
}
