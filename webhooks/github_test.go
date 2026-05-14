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

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/webapp/webhooks"
)

func sign(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// staticSecrets returns a getTokens function for use with GitHubValidator.
// Each call to the returned function creates fresh tokens from cloned bytes so
// that keys.NewToken's zeroing of the input does not corrupt subsequent calls.
func staticSecrets(secrets ...[]byte) func(context.Context) ([]keys.Token, error) {
	return func(_ context.Context) ([]keys.Token, error) {
		tokens := make([]keys.Token, len(secrets))
		for i, s := range secrets {
			clone := append([]byte(nil), s...)
			tokens[i] = keys.NewToken("", "", clone)
		}
		return tokens, nil
	}
}

func TestGitHubValidator(t *testing.T) {
	payload := []byte(`{"action": "push"}`)
	secret := []byte("super-secret")

	validator, err := webhooks.GitHubValidator(staticSecrets(secret))
	if err != nil {
		t.Fatalf("GitHubValidator: %v", err)
	}
	signature := sign(secret, payload)

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

	v, err := webhooks.GitHubValidator(staticSecrets(secretA, secretB))
	if err != nil {
		t.Fatalf("GitHubValidator: %v", err)
	}

	t.Run("FirstMatches", func(t *testing.T) {
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

	t.Run("SecondMatches", func(t *testing.T) {
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

	t.Run("NoMatch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sign([]byte("wrong"), payload))
		_, status := v(req)
		if status != http.StatusUnauthorized {
			t.Errorf("got status %d, want %d", status, http.StatusUnauthorized)
		}
	})

	t.Run("GetSecretsError", func(t *testing.T) {
		errSecrets := func(_ context.Context) ([]keys.Token, error) {
			return nil, fmt.Errorf("secrets unavailable")
		}
		ve, err := webhooks.GitHubValidator(errSecrets)
		if err != nil {
			t.Fatalf("GitHubValidator: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sign(secretA, payload))
		_, status := ve(req)
		if status != http.StatusInternalServerError {
			t.Errorf("got status %d, want %d", status, http.StatusInternalServerError)
		}
	})
}
