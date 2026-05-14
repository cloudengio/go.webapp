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

// newTestRelay creates a relay backed by a cancellable context and registers
// cleanup handlers so the caller never has to manage lifecycle manually.
func newTestRelay(t *testing.T, opts ...webhooks.Option) (func(http.ResponseWriter, *http.Request), *webhooks.Relay) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	relay := webhooks.NewRelay(ctx, webhooks.NoopValidator, opts...)
	t.Cleanup(func() { relay.Stop(context.Background()) })
	return relay.Handler("/api/webhook", "/api/wait"), relay
}

func postWebhook(t *testing.T, handler func(http.ResponseWriter, *http.Request), body []byte) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/webhook", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	return w.Code
}

func pollWebhook(t *testing.T, handler func(http.ResponseWriter, *http.Request)) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/wait", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	return w.Body.Bytes()
}

func TestRelayHappyPath(t *testing.T) {
	handler, _ := newTestRelay(t,
		webhooks.WithQueueSize(1),
		webhooks.WithMaxPayloadSize(1024),
		webhooks.WithLogger(slog.Default()),
	)
	payload := []byte(`{"event":"test"}`)

	if got := postWebhook(t, handler, payload); got != http.StatusAccepted {
		t.Fatalf("post: got status %d, want %d", got, http.StatusAccepted)
	}

	reqWait := httptest.NewRequest(http.MethodGet, "/api/wait", nil)
	wWait := httptest.NewRecorder()
	handler(wWait, reqWait)

	if got := wWait.Code; got != http.StatusOK {
		t.Errorf("wait: got status %d, want %d", got, http.StatusOK)
	}
	if got := wWait.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type: got %q, want application/json", got)
	}
	if !bytes.Equal(wWait.Body.Bytes(), payload) {
		t.Errorf("body: got %s, want %s", wWait.Body.Bytes(), payload)
	}
}

func TestRelayPayloadTooLarge(t *testing.T) {
	handler, _ := newTestRelay(t)

	req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader("big payload"))
	req.ContentLength = int64(webhooks.DefaultPayloadLimit + 1)
	w := httptest.NewRecorder()
	handler(w, req)

	if got := w.Code; got != http.StatusRequestEntityTooLarge {
		t.Errorf("got status %d, want %d", got, http.StatusRequestEntityTooLarge)
	}
}

func TestRelayInvalidContentType(t *testing.T) {
	handler, _ := newTestRelay(t)

	req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader("payload"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	handler(w, req)

	if got := w.Code; got != http.StatusUnsupportedMediaType {
		t.Errorf("got status %d, want %d", got, http.StatusUnsupportedMediaType)
	}
}

func TestRelayNilBody(t *testing.T) {
	handler, _ := newTestRelay(t)

	req := httptest.NewRequest(http.MethodPost, "/api/webhook", nil)
	req.Body = nil
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)

	if got := w.Code; got != http.StatusBadRequest {
		t.Errorf("nil body: got status %d, want %d", got, http.StatusBadRequest)
	}
}

func TestRelayReadError(t *testing.T) {
	handler, _ := newTestRelay(t)

	req := httptest.NewRequest(http.MethodPost, "/api/webhook", nil)
	req.Body = errReader{}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)

	if got := w.Code; got != http.StatusBadRequest {
		t.Errorf("read error: got status %d, want %d", got, http.StatusBadRequest)
	}
}

// TestRelayQueueDropsOldest verifies that when the internal buffer is full the
// oldest payload is silently dropped and the new one is accepted (202).
// It uses capacity=2 and sends 3 payloads so that "first" is dropped.
// After draining the two surviving payloads a final read with a cancelled
// context confirms the queue is empty — proving "first" was removed.
func TestRelayQueueDropsOldest(t *testing.T) {
	handler, _ := newTestRelay(t, webhooks.WithQueueSize(2))

	first, second, third := []byte(`"first"`), []byte(`"second"`), []byte(`"third"`)

	if got := postWebhook(t, handler, first); got != http.StatusAccepted {
		t.Fatalf("first: got status %d, want %d", got, http.StatusAccepted)
	}
	if got := postWebhook(t, handler, second); got != http.StatusAccepted {
		t.Fatalf("second: got status %d, want %d", got, http.StatusAccepted)
	}
	// Overflow: "first" (oldest) is dropped; "third" is accepted.
	if got := postWebhook(t, handler, third); got != http.StatusAccepted {
		t.Fatalf("third: got status %d, want %d", got, http.StatusAccepted)
	}

	if got := pollWebhook(t, handler); !bytes.Equal(got, second) {
		t.Errorf("first read: got %s, want %s", got, second)
	}
	if got := pollWebhook(t, handler); !bytes.Equal(got, third) {
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
}

func TestRelayWaitContextCancelled(t *testing.T) {
	handler, _ := newTestRelay(t)

	reqCtx, cancelReq := context.WithCancel(context.Background())
	cancelReq()
	req := httptest.NewRequest(http.MethodGet, "/api/wait", nil).WithContext(reqCtx)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Body.Len() > 0 {
		t.Errorf("expected empty body on context cancel, got %s", w.Body.String())
	}
}

func TestRelayValidatorError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	relay := webhooks.NewRelay(ctx, func(*http.Request) ([]byte, int) {
		return nil, http.StatusUnauthorized
	})
	t.Cleanup(func() { relay.Stop(context.Background()) })
	handler := relay.Handler("/api/webhook", "/api/wait")

	req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader("payload"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)

	if got := w.Code; got != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", got, http.StatusUnauthorized)
	}
}
