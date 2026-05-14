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
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		relay := webhooks.NewRelay(ctx,
			webhooks.NoopValidator,
			webhooks.WithQueueSize(1),
			webhooks.WithMaxPayloadSize(1024),
			webhooks.WithLogger(slog.Default()),
		)
		defer relay.Stop(context.Background())
		handler := relay.Handler("/api/webhook", "/api/wait")

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
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		relay := webhooks.NewRelay(ctx, webhooks.NoopValidator)
		defer relay.Stop(context.Background())
		handler := relay.Handler("/api/webhook", "/api/wait")

		req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader("big payload"))
		req.ContentLength = int64(webhooks.DefaultPayloadLimit + 1)
		w := httptest.NewRecorder()

		handler(w, req)

		if got, want := w.Code, http.StatusRequestEntityTooLarge; got != want {
			t.Errorf("got status %v, want %v", got, want)
		}
	})

	t.Run("InvalidContentType", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		relay := webhooks.NewRelay(ctx, webhooks.NoopValidator)
		defer relay.Stop(context.Background())
		handler := relay.Handler("/api/webhook", "/api/wait")

		req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader("payload"))
		req.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		handler(w, req)

		if got, want := w.Code, http.StatusUnsupportedMediaType; got != want {
			t.Errorf("got status %v, want %v", got, want)
		}
	})

	t.Run("NilBodyAndReadErrors", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		relay := webhooks.NewRelay(ctx, webhooks.NoopValidator)
		defer relay.Stop(context.Background())
		handler := relay.Handler("/api/webhook", "/api/wait")

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

	// QueueDropsOldest verifies that when the internal buffer is full the
	// oldest payload is silently dropped and the new one is accepted (202).
	// It uses capacity=2 and sends 3 payloads so that "first" is dropped.
	// After draining the two surviving payloads a final read with a cancelled
	// context confirms the queue is empty — proving "first" was removed.
	t.Run("QueueDropsOldest", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		relay := webhooks.NewRelay(ctx, webhooks.NoopValidator, webhooks.WithQueueSize(2))
		defer relay.Stop(context.Background())
		handler := relay.Handler("/api/webhook", "/api/wait")

		send := func(body []byte) int {
			req := httptest.NewRequest(http.MethodPost, "/api/webhook", bytes.NewReader(body))
			req.ContentLength = int64(len(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler(w, req)
			return w.Code
		}
		recv := func() []byte {
			req := httptest.NewRequest(http.MethodGet, "/api/wait", nil)
			w := httptest.NewRecorder()
			handler(w, req)
			return w.Body.Bytes()
		}

		first, second, third := []byte(`"first"`), []byte(`"second"`), []byte(`"third"`)

		// Fill the capacity-2 buffer.
		if got := send(first); got != http.StatusAccepted {
			t.Fatalf("first: got status %d, want %d", got, http.StatusAccepted)
		}
		if got := send(second); got != http.StatusAccepted {
			t.Fatalf("second: got status %d, want %d", got, http.StatusAccepted)
		}
		// Overflow: "first" (oldest) is dropped; "third" is accepted.
		if got := send(third); got != http.StatusAccepted {
			t.Fatalf("third: got status %d, want %d", got, http.StatusAccepted)
		}

		// "second" and "third" survive in FIFO order.
		if got := recv(); !bytes.Equal(got, second) {
			t.Errorf("first read: got %s, want %s", got, second)
		}
		if got := recv(); !bytes.Equal(got, third) {
			t.Errorf("second read: got %s, want %s", got, third)
		}

		// Queue must now be empty — "first" was dropped, not merely deferred.
		cancelledCtx, cancelReq := context.WithCancel(context.Background())
		cancelReq()
		emptyReq := httptest.NewRequest(http.MethodGet, "/api/wait", nil).WithContext(cancelledCtx)
		wEmpty := httptest.NewRecorder()
		handler(wEmpty, emptyReq)
		if wEmpty.Body.Len() > 0 {
			t.Errorf("queue not empty after draining: got %s", wEmpty.Body.String())
		}
	})

	t.Run("WaitContextCancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		relay := webhooks.NewRelay(ctx, webhooks.NoopValidator)
		defer relay.Stop(context.Background())
		handler := relay.Handler("/api/webhook", "/api/wait")

		reqCtx, reqCancel := context.WithCancel(context.Background())
		req := httptest.NewRequest(http.MethodGet, "/api/wait", nil)
		req = req.WithContext(reqCtx)
		w := httptest.NewRecorder()

		reqCancel()
		handler(w, req)

		if w.Body.Len() > 0 {
			t.Errorf("expected empty body on context cancel, got %s", w.Body.String())
		}
	})

	t.Run("ValidatorError", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		relay := webhooks.NewRelay(ctx, func(*http.Request) ([]byte, int) {
			return nil, http.StatusUnauthorized
		})
		defer relay.Stop(context.Background())
		handler := relay.Handler("/api/webhook", "/api/wait")

		req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader("payload"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)

		if got, want := w.Code, http.StatusUnauthorized; got != want {
			t.Errorf("got status %v, want %v", got, want)
		}
	})
}
