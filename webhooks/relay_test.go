// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloudeng.io/webapp"
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

func TestRelayForwardsHeaders(t *testing.T) {
	handler, _ := newTestRelay(t)
	payload := []byte(`{"event":"test"}`)

	// Post carrying the default forwarded headers plus one that must be dropped.
	postReq := httptest.NewRequest(http.MethodPost, "/api/webhook", bytes.NewReader(payload))
	postReq.ContentLength = int64(len(payload))
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("X-GitHub-Event", "workflow_run")
	postReq.Header.Set("X-GitHub-Delivery", "12345")
	postReq.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	if got := func() int {
		w := httptest.NewRecorder()
		handler(w, postReq)
		return w.Code
	}(); got != http.StatusAccepted {
		t.Fatalf("post: got status %d, want %d", got, http.StatusAccepted)
	}

	waitReq := httptest.NewRequest(http.MethodGet, "/api/wait", nil)
	w := httptest.NewRecorder()
	handler(w, waitReq)

	if got := w.Header().Get("X-GitHub-Event"); got != "workflow_run" {
		t.Errorf("X-GitHub-Event: got %q, want %q", got, "workflow_run")
	}
	if got := w.Header().Get("X-GitHub-Delivery"); got != "12345" {
		t.Errorf("X-GitHub-Delivery: got %q, want %q", got, "12345")
	}
	// Non-forwarded headers, including the already-verified signature, must not
	// be leaked to the client.
	if got := w.Header().Get("X-Hub-Signature-256"); got != "" {
		t.Errorf("X-Hub-Signature-256: got %q, want it dropped", got)
	}
	if !bytes.Equal(w.Body.Bytes(), payload) {
		t.Errorf("body: got %s, want %s", w.Body.Bytes(), payload)
	}
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

// makeCounter returns a CounterInc that atomically increments an int64 and a
// function to read the current value.
func makeCounter() (webapp.CounterInc, func() int64) {
	var n atomic.Int64
	return func(context.Context) { n.Add(1) }, n.Load
}

func TestRelayCounterRelayed(t *testing.T) {
	denied, deniedN := makeCounter()
	relayed, relayedN := makeCounter()
	read, readN := makeCounter()
	handler, _ := newTestRelay(t, webhooks.WithCounters(denied, relayed, read))

	postWebhook(t, handler, []byte(`"hello"`))

	if got := relayedN(); got != 1 {
		t.Errorf("relayed: got %d, want 1", got)
	}
	if got := deniedN(); got != 0 {
		t.Errorf("denied: got %d, want 0", got)
	}
	if got := readN(); got != 0 {
		t.Errorf("read: got %d, want 0", got)
	}
}

func TestRelayCounterDenied(t *testing.T) {
	denied, deniedN := makeCounter()
	relayed, relayedN := makeCounter()
	read, readN := makeCounter()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	relay := webhooks.NewRelay(ctx,
		func(*http.Request) ([]byte, int) { return nil, http.StatusUnauthorized },
		webhooks.WithCounters(denied, relayed, read),
	)
	t.Cleanup(func() { relay.Stop(context.Background()) })
	handler := relay.Handler("/api/webhook", "/api/wait")

	req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader(`"hello"`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)

	if got := deniedN(); got != 1 {
		t.Errorf("denied: got %d, want 1", got)
	}
	if got := relayedN(); got != 0 {
		t.Errorf("relayed: got %d, want 0", got)
	}
	if got := readN(); got != 0 {
		t.Errorf("read: got %d, want 0", got)
	}
}

func TestRelayCounterRead(t *testing.T) {
	denied, deniedN := makeCounter()
	relayed, relayedN := makeCounter()
	read, readN := makeCounter()
	handler, _ := newTestRelay(t, webhooks.WithCounters(denied, relayed, read))

	postWebhook(t, handler, []byte(`"hello"`))
	pollWebhook(t, handler)

	if got := readN(); got != 1 {
		t.Errorf("read: got %d, want 1", got)
	}
	if got := relayedN(); got != 1 {
		t.Errorf("relayed: got %d, want 1", got)
	}
	if got := deniedN(); got != 0 {
		t.Errorf("denied: got %d, want 0", got)
	}
}

// TestRelayCounterNoIncrementOnNonValidatorErrors verifies that infra-level
// rejections (wrong content-type, payload too large, etc.) do not touch any
// counter — only validator-returned 4xx codes increment denied.
func TestRelayCounterNoIncrementOnNonValidatorErrors(t *testing.T) {
	denied, deniedN := makeCounter()
	relayed, relayedN := makeCounter()
	read, readN := makeCounter()
	handler, _ := newTestRelay(t, webhooks.WithCounters(denied, relayed, read))

	// Wrong content-type.
	req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader(`"x"`))
	req.Header.Set("Content-Type", "text/plain")
	handler(httptest.NewRecorder(), req)

	// Payload too large.
	req2 := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader("big"))
	req2.ContentLength = int64(webhooks.DefaultPayloadLimit + 1)
	handler(httptest.NewRecorder(), req2)

	if got := deniedN(); got != 0 {
		t.Errorf("denied: got %d, want 0", got)
	}
	if got := relayedN(); got != 0 {
		t.Errorf("relayed: got %d, want 0", got)
	}
	if got := readN(); got != 0 {
		t.Errorf("read: got %d, want 0", got)
	}
}

// TestRelayCounterNoIncrementOnContextCancel verifies that a cancelled request
// context during send does not increment the relayed counter.
func TestRelayCounterNoIncrementOnContextCancel(t *testing.T) {
	denied, deniedN := makeCounter()
	relayed, relayedN := makeCounter()
	read, readN := makeCounter()

	// Use capacity 0 (defaults to DefaultQueueSize) but fill it first so the
	// FIFO's run goroutine is busy; then cancel the request context before it
	// can send — the simplest approach is just to pre-cancel the context.
	handler, _ := newTestRelay(t, webhooks.WithCounters(denied, relayed, read))

	cancelledCtx, cancelReq := context.WithCancel(context.Background())
	cancelReq()
	req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader(`"x"`))
	req = req.WithContext(cancelledCtx)
	req.ContentLength = int64(len(`"x"`))
	req.Header.Set("Content-Type", "application/json")
	handler(httptest.NewRecorder(), req)

	if got := relayedN(); got != 0 {
		t.Errorf("relayed: got %d, want 0", got)
	}
	if got := deniedN(); got != 0 {
		t.Errorf("denied: got %d, want 0", got)
	}
	if got := readN(); got != 0 {
		t.Errorf("read: got %d, want 0", got)
	}
}

// signalHandler is a slog.Handler that closes ch the first time it records a
// message equal to msg, letting a test observe a specific log event. ch and
// once are shared with any derived handler so WithAttrs/WithGroup (used by
// slog.Logger.With) preserve the override and still fire exactly once.
type signalHandler struct {
	slog.Handler
	msg  string
	ch   chan struct{}
	once *sync.Once
}

func newSignalHandler(msg string, ch chan struct{}) *signalHandler {
	return &signalHandler{
		Handler: slog.NewTextHandler(io.Discard, nil),
		msg:     msg,
		ch:      ch,
		once:    &sync.Once{},
	}
}

func (h *signalHandler) clone(base slog.Handler) *signalHandler {
	return &signalHandler{Handler: base, msg: h.msg, ch: h.ch, once: h.once}
}

func (h *signalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h.clone(h.Handler.WithAttrs(attrs))
}

func (h *signalHandler) WithGroup(name string) slog.Handler {
	return h.clone(h.Handler.WithGroup(name))
}

func (h *signalHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == h.msg {
		h.once.Do(func() { close(h.ch) })
	}
	return h.Handler.Handle(ctx, r)
}

// TestRelayExpiry verifies that a queued delivery which is not read within the
// configured TTL is dropped by the periodic expiry scan.
func TestRelayExpiry(t *testing.T) {
	expired := make(chan struct{})
	logger := slog.New(newSignalHandler("dropping expired webhook delivery", expired))
	handler, _ := newTestRelay(t,
		webhooks.WithLogger(logger),
		webhooks.WithExpiry(20*time.Millisecond, 5*time.Millisecond),
	)

	if got := postWebhook(t, handler, []byte(`"stale"`)); got != http.StatusAccepted {
		t.Fatalf("post: got status %d, want %d", got, http.StatusAccepted)
	}

	// Nothing polls, so the delivery ages past the TTL and the scan drops it.
	select {
	case <-expired:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery was not expired within the timeout")
	}

	// The queue must now be empty: a poll whose context is already cancelled
	// returns without a body only if there is nothing to deliver.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/wait", nil).WithContext(cancelledCtx)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Body.Len() > 0 {
		t.Errorf("queue not empty after expiry: got %q", w.Body.String())
	}
}
