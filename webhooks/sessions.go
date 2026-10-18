// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"hash/fnv"
	"io"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"cloudeng.io/sync/patterns"
)

// SessionKeyFunc identifies the session, if any, that a webhook delivery
// belongs to. The only requirement is that it returns the same, non-empty key
// for all deliveries of the same session and it returns true for the last
// delivery of the session. Return an empty key indicates that the delivery
// does not belong to any session. header is the header of the delivery request
// and body its payload. The webhook delivery itself has already been validated.
type SessionKeyFunc func(header http.Header, body []byte) (key string, last bool)

// GitHubWorkflowSessionKey is a SessionKeyFunc that groups the webhooks of a
// GitHub workflow run: the workflow_run and workflow_job events of a run have
// the same session, which is the run's id, and the workflow_run event with an
// action of completed is the last. All other events are not part of a session.
func GitHubWorkflowSessionKey(header http.Header, body []byte) (string, bool) {
	switch header.Get("X-GitHub-Event") {
	case "workflow_run", "workflow_job":
	default:
		return "", false
	}
	var payload struct {
		Action      string `json:"action"`
		WorkflowRun *struct {
			ID int64 `json:"id"`
		} `json:"workflow_run"`
		WorkflowJob *struct {
			RunID int64 `json:"run_id"`
		} `json:"workflow_job"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", false
	}
	switch {
	case payload.WorkflowRun != nil && payload.WorkflowRun.ID != 0:
		return strconv.FormatInt(payload.WorkflowRun.ID, 10), payload.Action == "completed"
	case payload.WorkflowJob != nil && payload.WorkflowJob.RunID != 0:
		return strconv.FormatInt(payload.WorkflowJob.RunID, 10), false
	}
	return "", false
}

// WithSessions keeps the deliveries of a session, as identified by key, together.
// Readers must stream, see Relay.WaitForWebhook, and each gets its own queue.
// A session is bound to a reader, chosen by the SessionPolicy, when its first
// delivery arrives, and all of its deliveries go to that reader. Deliveries that
// are not part of a session go to any reader. If no session reader is waiting,
// the delivery waits for any reader.
func WithSessions(key SessionKeyFunc) Option {
	return func(opts *options) {
		opts.sessionKey = key
	}
}

// WithSessionTimeout ends a session that has had no delivery for longer than
// timeout, for sessions whose last delivery never arrives. A later delivery for
// it starts a new session. Expiry is checked as deliveries arrive and readers
// finish. A timeout <= 0, the default, disables it.
func WithSessionTimeout(timeout time.Duration) Option {
	return func(opts *options) {
		opts.sessionTimeout = timeout
	}
}

// SessionPolicy chooses which of n > 0 session readers a new session is bound
// to, returning an index in [0, n). It is called once per session, when its first
// delivery arrives, and the session stays with that reader.
type SessionPolicy func(session string, n int) int

// HashSessionPolicy is the default SessionPolicy: it hashes the session key.
func HashSessionPolicy(session string, n int) int {
	h := fnv.New32a()
	h.Write([]byte(session))
	return int(h.Sum32() % uint32(n))
}

// WithSessionPolicy sets the policy that binds sessions to readers, replacing
// HashSessionPolicy. It has no effect without WithSessions.
func WithSessionPolicy(p SessionPolicy) Option {
	return func(opts *options) {
		opts.sessionPolicy = p
	}
}

// sessionReader is the queue of a reader that asks for sessions, and the number
// of sessions bound to it. There is a queue per reader, as there is for the
// deliveries that are not part of a session, so that it is the queue that is
// bounded, and that expires deliveries.
type sessionReader struct {
	queue *patterns.FIFO[delivery]
	n     int
}

// router relays deliveries to readers. Deliveries go to the shared queue, which
// any reader takes from, unless sessions are enabled, the delivery is part of a
// session and there is a reader to bind it to, in which case they go to the
// queue of that reader.
type router struct {
	ctx     context.Context
	opts    options
	shared  *patterns.FIFO[delivery]
	mu      sync.Mutex
	policy  SessionPolicy
	readers []*sessionReader
	bound   map[string]*binding // session to its reader
}

// binding is the reader that a session is bound to, and when the session last
// had a delivery.
type binding struct {
	reader *sessionReader
	last   time.Time
}

func newRouter(ctx context.Context, opts options) *router {
	policy := opts.sessionPolicy
	if policy == nil {
		policy = HashSessionPolicy
	}
	return &router{
		ctx:    ctx,
		opts:   opts,
		shared: patterns.NewFIFO(ctx, int(opts.size), expiryScan(opts)...),
		policy: policy,
		bound:  map[string]*binding{},
	}
}

// expire unbinds the sessions that have had no delivery for the timeout. The
// caller holds rt.mu.
func (rt *router) expire(now time.Time) {
	if rt.opts.sessionTimeout <= 0 {
		return
	}
	for key, b := range rt.bound {
		if now.Sub(b.last) > rt.opts.sessionTimeout {
			delete(rt.bound, key)
			b.reader.n--
		}
	}
}

// route relays d, returning the error, if any, if ctx or the relay's ctx ended
// before it could be queued.
func (rt *router) route(ctx context.Context, d delivery) error {
	if d.session != "" {
		rt.mu.Lock()
		if q := rt.bind(d); q != nil {
			// Sent under the lock, so that the queue is not closed by its reader leaving.
			defer rt.mu.Unlock()
			return rt.send(ctx, q, d)
		}
		rt.mu.Unlock()
	}
	return rt.send(ctx, rt.shared, d)
}

// send queues d, which a queue always accepts, dropping its oldest delivery if
// it is full.
func (rt *router) send(ctx context.Context, q *patterns.FIFO[delivery], d delivery) error {
	select {
	case q.In() <- d:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-rt.ctx.Done():
		return rt.ctx.Err()
	}
}

// bind returns the queue of the reader that d, which is part of a session, is
// bound to, binding it using the policy if it is not. It returns nil if there
// is no reader. The caller holds rt.mu.
func (rt *router) bind(d delivery) *patterns.FIFO[delivery] {
	now := time.Now()
	rt.expire(now)
	b := rt.bound[d.session]
	if b == nil {
		n := len(rt.readers)
		if n == 0 {
			return nil
		}
		r := rt.readers[(rt.policy(d.session, n)%n+n)%n]
		b = &binding{reader: r}
		rt.bound[d.session] = b
		r.n++
	}
	b.last = now
	if d.last {
		delete(rt.bound, d.session)
		b.reader.n--
	}
	return b.reader.queue
}

// join adds a reader, with a queue of its own for its sessions.
func (rt *router) join() *sessionReader {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	r := &sessionReader{queue: patterns.NewFIFO(rt.ctx, int(rt.opts.size), expiryScan(rt.opts)...)}
	rt.readers = append(rt.readers, r)
	return r
}

// finished reports whether r has no sessions left.
func (rt *router) finished(r *sessionReader) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.expire(time.Now())
	return r.n == 0
}

// leave removes a reader that is gone, and relays what it had not been sent to
// the shared queue, for another reader.
func (rt *router) leave(r *sessionReader) {
	rt.mu.Lock()
	rt.readers = slices.DeleteFunc(rt.readers, func(x *sessionReader) bool { return x == r })
	for key, b := range rt.bound {
		if b.reader == r {
			delete(rt.bound, key)
		}
	}
	rt.mu.Unlock()
	// Nothing is sent to it now, so that it can be closed, which flushes it.
	close(r.queue.In())
	for {
		select {
		case d, ok := <-r.queue.Out():
			if !ok {
				return
			}
			rt.requeue(d)
		case <-rt.ctx.Done():
			return
		}
	}
}

// requeue relays a delivery that was not sent, for another reader.
func (rt *router) requeue(d delivery) {
	select {
	case rt.shared.In() <- d:
	case <-rt.ctx.Done():
	}
}

// wantsStream reports whether a long polling request asks to be streamed
// deliveries, using the stream query parameter.
func wantsStream(req *http.Request) bool {
	switch req.URL.Query().Get("stream") {
	case "1", "true":
		return true
	}
	return false
}

// newDeliveryEncoder returns an encoder that writes each delivery as a
// Delivery on a line of its own.
func newDeliveryEncoder(w io.Writer) *jsontext.Encoder {
	return jsontext.NewEncoder(w)
}

func encodeDelivery(enc *jsontext.Encoder, d delivery) error {
	return json.MarshalEncode(enc, newDelivery(d), json.Deterministic(true))
}

// write sends d as a line of the stream, or as it was received.
func write(w http.ResponseWriter, enc *jsontext.Encoder, d delivery, stream bool) error {
	if stream {
		return encodeDelivery(enc, d)
	}
	return writeRaw(w, d)
}

// writeRaw relays a delivery as it was received: the payload as the body and
// the forwarded headers as headers.
func writeRaw(w http.ResponseWriter, d delivery) error {
	for name, values := range d.header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	_, err := w.Write(d.body)
	return err
}

// serve sends a reader its deliveries: from its own queue, if sessions are
// enabled, and the shared queue. A reader that streams is sent them as they
// arrive, as Deliveries, until the last of its sessions or the request ends.
// Otherwise it is sent one, as it was received.
func (r *Relay) serve(w http.ResponseWriter, req *http.Request, stream bool) {
	var flusher http.Flusher
	if stream {
		var ok bool
		if flusher, ok = w.(http.Flusher); !ok {
			http.Error(w, "streaming is not supported: the response cannot be flushed", http.StatusInternalServerError)
			return
		}
	}
	var own *sessionReader
	var ownOut <-chan delivery
	if r.opts.sessionKey != nil {
		own = r.router.join()
		ownOut = own.queue.Out()
		defer r.router.leave(own)
	}
	w.Header().Set("Content-Type", "application/json")
	if stream {
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
	}
	enc := newDeliveryEncoder(w)
	for {
		var d delivery
		var ok bool
		select {
		case d, ok = <-ownOut:
		case d, ok = <-r.router.shared.Out():
		case <-req.Context().Done():
			r.opts.logger.Info("WaitForWebhook: request context cancelled while waiting for a delivery", "err", req.Context().Err())
			return
		}
		if !ok {
			return
		}
		if err := write(w, enc, d, stream); err != nil {
			r.opts.logger.Info("WaitForWebhook: failed to write to client", "session", d.session, "err", err)
			r.router.requeue(d)
			return
		}
		if stream {
			flusher.Flush()
		}
		r.opts.logger.Info("WaitForWebhook: sent payload to client", "size", len(d.body), "session", d.session, "last", d.last)
		r.opts.readCounter(req.Context())
		if !stream || (d.last && r.router.finished(own)) {
			return
		}
	}
}
