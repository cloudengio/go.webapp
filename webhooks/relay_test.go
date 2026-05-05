// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cloudeng.io/webapp/webhooks"
)

type errReader struct{}

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func (errReader) Close() error {
	return nil
}

func TestRelay(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		relay := webhooks.NewRelay(
			webhooks.NoopValidator,
			webhooks.WithQueueSize(1),
			webhooks.WithMaxPayloadSize(1024),
			webhooks.WithLogger(slog.Default()),
		)
		handler := relay.Handler("/api")

		payload := []byte(`{"event":"test"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/webhook", bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler(w, req)

		if got, want := w.Code, http.StatusAccepted; got != want {
			t.Errorf("got status %v, want %v", got, want)
		}

		reqWait := httptest.NewRequest(http.MethodGet, "/api/wait", nil)
		wWait := httptest.NewRecorder()
		handler(wWait, reqWait)

		if got, want := wWait.Code, http.StatusOK; got != want {
			t.Errorf("got status %v, want %v", got, want)
		}
		if got, want := wWait.Header().Get("Content-Type"), "application/json"; got != want {
			t.Errorf("got content type %v, want %v", got, want)
		}

		received := wWait.Body.Bytes()
		if !bytes.Equal(received, payload) {
			t.Errorf("got %s, want %s", received, payload)
		}
	})

	t.Run("PayloadTooLarge", func(t *testing.T) {
		relay := webhooks.NewRelay(webhooks.NoopValidator)
		handler := relay.Handler("/api")

		req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader("big payload"))
		req.ContentLength = int64(webhooks.DefaultPayloadLimit + 1)
		w := httptest.NewRecorder()

		handler(w, req)

		if got, want := w.Code, http.StatusRequestEntityTooLarge; got != want {
			t.Errorf("got status %v, want %v", got, want)
		}
	})

	t.Run("InvalidContentType", func(t *testing.T) {
		relay := webhooks.NewRelay(webhooks.NoopValidator)
		handler := relay.Handler("/api")

		req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader("payload"))
		req.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		handler(w, req)

		if got, want := w.Code, http.StatusUnsupportedMediaType; got != want {
			t.Errorf("got status %v, want %v", got, want)
		}
	})

	t.Run("NilBodyAndReadErrors", func(t *testing.T) {
		relay := webhooks.NewRelay(webhooks.NoopValidator)
		handler := relay.Handler("/api")

		// Test forced nil body
		reqNil := httptest.NewRequest(http.MethodPost, "/api/webhook", nil)
		reqNil.Body = nil
		reqNil.Header.Set("Content-Type", "application/json")
		wNil := httptest.NewRecorder()
		handler(wNil, reqNil)
		if got, want := wNil.Code, http.StatusBadRequest; got != want {
			t.Errorf("nil body: got status %v, want %v", got, want)
		}

		// Test read error
		reqErr := httptest.NewRequest(http.MethodPost, "/api/webhook", nil)
		reqErr.Body = errReader{}
		reqErr.Header.Set("Content-Type", "application/json")
		wErr := httptest.NewRecorder()
		handler(wErr, reqErr)
		if got, want := wErr.Code, http.StatusBadRequest; got != want {
			t.Errorf("read error: got status %v, want %v", got, want)
		}
	})

	t.Run("QueueFull", func(t *testing.T) {
		relay := webhooks.NewRelay(webhooks.NoopValidator, webhooks.WithQueueSize(1))
		handler := relay.Handler("/api")

		req1 := httptest.NewRequest(http.MethodPost, "/api/webhook", bytes.NewReader([]byte("first")))
		req1.ContentLength = 5
		req1.Header.Set("Content-Type", "application/json")
		w1 := httptest.NewRecorder()
		handler(w1, req1)

		// Queue is now full, this second payload should be discarded due to the default select case
		req2 := httptest.NewRequest(http.MethodPost, "/api/webhook", bytes.NewReader([]byte("second")))
		req2.ContentLength = 6
		req2.Header.Set("Content-Type", "application/json")
		w2 := httptest.NewRecorder()
		handler(w2, req2)

		if got, want := w2.Code, http.StatusInternalServerError; got != want {
			t.Errorf("got status %v, want %v", got, want)
		}
	})

	t.Run("WaitContextCancelled", func(t *testing.T) {
		relay := webhooks.NewRelay(webhooks.NoopValidator)
		handler := relay.Handler("/api")

		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest(http.MethodGet, "/api/wait", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		cancel()
		handler(w, req)

		if w.Body.Len() > 0 {
			t.Errorf("expected empty body on context cancel, got %s", w.Body.String())
		}
	})

	t.Run("ValidatorError", func(t *testing.T) {
		relay := webhooks.NewRelay(func(*http.Request) ([]byte, int) {
			return nil, http.StatusUnauthorized
		})
		handler := relay.Handler("/api")

		req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader("payload"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)

		if got, want := w.Code, http.StatusUnauthorized; got != want {
			t.Errorf("got status %v, want %v", got, want)
		}
	})
}
