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
	ctx := t.Context()
	payload := []byte(`{"action": "push"}`)
	secret := "super-secret"

	fs := mapFS{
		"github.secret": []byte("secrets:\n  - " + secret + "\n"),
	}
	validator, err := webhooks.GitHubValidator(ctx, fs, "github.secret")
	if err != nil {
		t.Fatalf("GitHubValidator: %v", err)
	}
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

func TestGitHubValidatorCreation(t *testing.T) {
	ctx := t.Context()
	fs := mapFS{
		"valid":   []byte("secrets:\n  - secret-a\n"),
		"invalid": []byte("this: {bad: yaml"),
	}

	t.Run("NoSecretPaths", func(t *testing.T) {
		_, err := webhooks.GitHubValidator(ctx, fs)
		if err == nil {
			t.Fatal("expected error for no secret paths, got nil")
		}
	})

	t.Run("EmptySecretPath", func(t *testing.T) {
		_, err := webhooks.GitHubValidator(ctx, fs, "")
		if err == nil {
			t.Fatal("expected error for empty secret path, got nil")
		}
	})

	t.Run("UnreadablePath", func(t *testing.T) {
		_, err := webhooks.GitHubValidator(ctx, fs, "nonexistent")
		if err == nil {
			t.Fatal("expected error for unreadable path, got nil")
		}
	})

	t.Run("InvalidYAML", func(t *testing.T) {
		_, err := webhooks.GitHubValidator(ctx, fs, "invalid")
		if err == nil {
			t.Fatal("expected error for invalid YAML, got nil")
		}
	})

	t.Run("ValidPath", func(t *testing.T) {
		_, err := webhooks.GitHubValidator(ctx, fs, "valid")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestGitHubValidatorMultipleSecrets(t *testing.T) {
	ctx := t.Context()
	payload := []byte(`{"action": "push"}`)

	fs := mapFS{
		"multi":  []byte("secrets:\n  - secret-a\n  - secret-b\n"),
		"file-a": []byte("secrets:\n  - secret-from-a\n"),
		"file-b": []byte("secrets:\n  - secret-from-b\n"),
	}

	mustValidator := func(t *testing.T, paths ...string) webhooks.Validator {
		t.Helper()
		v, err := webhooks.GitHubValidator(ctx, fs, paths...)
		if err != nil {
			t.Fatalf("GitHubValidator: %v", err)
		}
		return v
	}

	t.Run("MultipleSecretsInFile_FirstMatches", func(t *testing.T) {
		v := mustValidator(t, "multi")
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sign([]byte("secret-a"), payload))
		got, status := v(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})

	t.Run("MultipleSecretsInFile_SecondMatches", func(t *testing.T) {
		v := mustValidator(t, "multi")
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sign([]byte("secret-b"), payload))
		got, status := v(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})

	t.Run("MultipleFiles_SecondFileMatches", func(t *testing.T) {
		v := mustValidator(t, "file-a", "file-b")
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sign([]byte("secret-from-b"), payload))
		got, status := v(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})

	t.Run("NoMatch", func(t *testing.T) {
		v := mustValidator(t, "multi")
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sign([]byte("wrong"), payload))
		_, status := v(req)
		if status != http.StatusUnauthorized {
			t.Errorf("got status %d, want %d", status, http.StatusUnauthorized)
		}
	})
}
