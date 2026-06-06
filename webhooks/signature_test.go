// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/webapp/webhooks"
)

// staticSecrets returns a getTokens function for use with SignatureValidator.
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

func signedRequest(t *testing.T, payload, secret []byte, header string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := webhooks.SignedHTTPRequest(req, payload, secret, header); err != nil {
		t.Fatalf("SignedHTTPRequest: %v", err)
	}
	return req
}

func TestSignedHTTPRequest(t *testing.T) {
	payload := []byte(`{"action": "push"}`)
	secret := []byte("my-secret")
	header := "X-Hub-Signature-256"

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := webhooks.SignedHTTPRequest(req, payload, secret, header); err != nil {
		t.Fatalf("SignedHTTPRequest: %v", err)
	}

	t.Run("HeaderFormat", func(t *testing.T) {
		val := req.Header.Get(header)
		if val == "" {
			t.Fatal("signature header not set")
		}
		if !bytes.HasPrefix([]byte(val), []byte("sha256=")) {
			t.Errorf("header value %q does not start with sha256=", val)
		}
	})

	t.Run("CorrectSignature", func(t *testing.T) {
		mac := hmac.New(sha256.New, secret)
		mac.Write(payload)
		want := "sha256=" + fmt.Sprintf("%x", mac.Sum(nil))
		got := req.Header.Get(header)
		if got != want {
			t.Errorf("got signature %q, want %q", got, want)
		}
	})

	t.Run("BodyReadable", func(t *testing.T) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		if !bytes.Equal(body, payload) {
			t.Errorf("got body %q, want %q", body, payload)
		}
	})

	t.Run("GetBodyCallable", func(t *testing.T) {
		if req.GetBody == nil {
			t.Fatal("GetBody is nil")
		}
		rc, err := req.GetBody()
		if err != nil {
			t.Fatalf("GetBody: %v", err)
		}
		body, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("reading GetBody: %v", err)
		}
		if !bytes.Equal(body, payload) {
			t.Errorf("got body %q, want %q", body, payload)
		}
	})

	t.Run("ContentLength", func(t *testing.T) {
		if got, want := req.ContentLength, int64(len(payload)); got != want {
			t.Errorf("got ContentLength %d, want %d", got, want)
		}
	})

	t.Run("DifferentHeaderName", func(t *testing.T) {
		req2 := httptest.NewRequest(http.MethodPost, "/", nil)
		if err := webhooks.SignedHTTPRequest(req2, payload, secret, "X-Custom-Sig"); err != nil {
			t.Fatalf("SignedHTTPRequest: %v", err)
		}
		if req2.Header.Get("X-Custom-Sig") == "" {
			t.Error("custom header not set")
		}
		if req2.Header.Get(header) != "" {
			t.Error("unexpected default header was set")
		}
	})

	t.Run("EmptyPayload", func(t *testing.T) {
		req3 := httptest.NewRequest(http.MethodPost, "/", nil)
		if err := webhooks.SignedHTTPRequest(req3, []byte{}, secret, header); err != nil {
			t.Fatalf("SignedHTTPRequest: %v", err)
		}
		if req3.Header.Get(header) == "" {
			t.Error("signature header not set for empty payload")
		}
		if req3.ContentLength != 0 {
			t.Errorf("got ContentLength %d, want 0", req3.ContentLength)
		}
	})

	t.Run("RoundTrip", func(t *testing.T) {
		getSig := webhooks.SHA256SignatureFromHeader(header)
		validator, err := webhooks.SignatureValidator(getSig, staticSecrets(secret))
		if err != nil {
			t.Fatalf("SignatureValidator: %v", err)
		}
		req4 := signedRequest(t, payload, secret, header)
		got, status := validator(req4)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})
}

func TestSHA256SignatureFromHeader(t *testing.T) {
	getSig := webhooks.SHA256SignatureFromHeader("X-Sig")
	secret := []byte("test-secret")
	payload := []byte(`{"action":"test"}`)

	t.Run("Valid", func(t *testing.T) {
		mac := hmac.New(sha256.New, secret)
		mac.Write(payload)
		expectedBytes := mac.Sum(nil)

		req := signedRequest(t, payload, secret, "X-Sig")
		got, status := getSig(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, expectedBytes) {
			t.Errorf("got sig %x, want %x", got, expectedBytes)
		}
	})

	t.Run("MissingHeader", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		_, status := getSig(req)
		if status != http.StatusBadRequest {
			t.Errorf("got status %d, want %d", status, http.StatusBadRequest)
		}
	})

	t.Run("WrongPrefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-Sig", "sha1=abc123")
		_, status := getSig(req)
		if status != http.StatusBadRequest {
			t.Errorf("got status %d, want %d", status, http.StatusBadRequest)
		}
	})

	t.Run("InvalidHex", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-Sig", "sha256=notvalidhex!!")
		_, status := getSig(req)
		if status != http.StatusBadRequest {
			t.Errorf("got status %d, want %d", status, http.StatusBadRequest)
		}
	})

	t.Run("NoEqualsSign", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-Sig", "sha256abc123")
		_, status := getSig(req)
		if status != http.StatusBadRequest {
			t.Errorf("got status %d, want %d", status, http.StatusBadRequest)
		}
	})
}

func TestSignatureValidator(t *testing.T) {
	payload := []byte(`{"action": "push"}`)
	secret := []byte("super-secret")

	getSig := webhooks.SHA256SignatureFromHeader("X-Hub-Signature-256")
	validator, err := webhooks.SignatureValidator(getSig, staticSecrets(secret))
	if err != nil {
		t.Fatalf("SignatureValidator: %v", err)
	}

	t.Run("ValidSignature", func(t *testing.T) {
		req := signedRequest(t, payload, secret, "X-Hub-Signature-256")
		got, status := validator(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})

	t.Run("MissingSignatureHeader", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		_, status := validator(req)
		if status != http.StatusBadRequest {
			t.Errorf("got status %d, want %d", status, http.StatusBadRequest)
		}
	})

	t.Run("WrongSignaturePrefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", "sha1=foo")
		_, status := validator(req)
		if status != http.StatusBadRequest {
			t.Errorf("got status %d, want %d", status, http.StatusBadRequest)
		}
	})

	t.Run("WrongSignatureValue", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", "sha256=abcdef123456")
		_, status := validator(req)
		if status != http.StatusUnauthorized {
			t.Errorf("got status %d, want %d", status, http.StatusUnauthorized)
		}
	})

	t.Run("GetTokensError", func(t *testing.T) {
		errTokens := func(_ context.Context) ([]keys.Token, error) {
			return nil, fmt.Errorf("tokens unavailable")
		}
		ve, err := webhooks.SignatureValidator(getSig, errTokens)
		if err != nil {
			t.Fatalf("SignatureValidator: %v", err)
		}
		req := signedRequest(t, payload, secret, "X-Hub-Signature-256")
		_, status := ve(req)
		if status != http.StatusInternalServerError {
			t.Errorf("got status %d, want %d", status, http.StatusInternalServerError)
		}
	})

	t.Run("CustomGetSignature", func(t *testing.T) {
		// Verify that SignatureValidator works with any getSignature function,
		// not just SHA256SignatureFromHeader.
		alwaysValid := func(req *http.Request) ([]byte, int) {
			mac := hmac.New(sha256.New, secret)
			mac.Write(payload)
			return mac.Sum(nil), http.StatusOK
		}
		vc, err := webhooks.SignatureValidator(alwaysValid, staticSecrets(secret))
		if err != nil {
			t.Fatalf("SignatureValidator: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		got, status := vc(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})
}

func TestSignatureValidatorMultipleSecrets(t *testing.T) {
	payload := []byte(`{"action": "push"}`)
	secretA := []byte("secret-a")
	secretB := []byte("secret-b")

	getSig := webhooks.SHA256SignatureFromHeader("X-Hub-Signature-256")
	v, err := webhooks.SignatureValidator(getSig, staticSecrets(secretA, secretB))
	if err != nil {
		t.Fatalf("SignatureValidator: %v", err)
	}

	t.Run("FirstMatches", func(t *testing.T) {
		req := signedRequest(t, payload, secretA, "X-Hub-Signature-256")
		got, status := v(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})

	t.Run("SecondMatches", func(t *testing.T) {
		req := signedRequest(t, payload, secretB, "X-Hub-Signature-256")
		got, status := v(req)
		if status != http.StatusOK {
			t.Errorf("got status %d, want %d", status, http.StatusOK)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got payload %q, want %q", got, payload)
		}
	})

	t.Run("NoMatch", func(t *testing.T) {
		req := signedRequest(t, payload, []byte("wrong"), "X-Hub-Signature-256")
		_, status := v(req)
		if status != http.StatusUnauthorized {
			t.Errorf("got status %d, want %d", status, http.StatusUnauthorized)
		}
	})
}
