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
// A reader that asks for sessions, see Relay.WaitForWebhook, gets its own queue.
// A session is bound to a reader, chosen by the SessionPolicy, when its first
// delivery arrives, and all of its deliveries go to that reader. Deliveries that
// are not part of a session go to any reader. If no session reader is waiting,
// deliveries are relayed as if sessions were not enabled.
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

// sessions is the readers that ask for sessions, and which of them each
// session is bound to.
type sessions struct {
	mu      sync.Mutex
	timeout time.Duration // how long a session may go without a delivery, or <= 0
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

func newSessions(timeout time.Duration, policy SessionPolicy) *sessions {
	if policy == nil {
		policy = HashSessionPolicy
	}
	return &sessions{timeout: timeout, policy: policy, bound: map[string]*binding{}}
}

// expire unbinds the sessions that have had no delivery for the timeout. The
// caller holds s.mu.
func (s *sessions) expire(now time.Time) {
	if s.timeout <= 0 {
		return
	}
	for key, b := range s.bound {
		if now.Sub(b.last) > s.timeout {
			delete(s.bound, key)
			b.reader.n--
		}
	}
}

// route sends d, which is part of a session, to the reader that its session is
// bound to, binding it using the policy if it is not. It reports false if there
// is no reader, in which case the delivery is for the caller to queue, and
// otherwise the error, if any, is that ctx or the relay's ctx ended before it
// could be sent.
func (s *sessions) route(ctx, relayCtx context.Context, d delivery) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.expire(now)
	b := s.bound[d.session]
	if b == nil {
		if len(s.readers) == 0 {
			return false, nil
		}
		n := len(s.readers)
		r := s.readers[(s.policy(d.session, n)%n+n)%n]
		b = &binding{reader: r}
		s.bound[d.session] = b
		r.n++
	}
	b.last = now
	if d.last {
		delete(s.bound, d.session)
		b.reader.n--
	}
	// Sent under the lock, so that the queue is not closed by its reader leaving.
	// The queue always accepts, dropping its oldest delivery if it is full.
	select {
	case b.reader.queue.In() <- d:
		return true, nil
	case <-ctx.Done():
		return true, ctx.Err()
	case <-relayCtx.Done():
		return true, relayCtx.Err()
	}
}

// join adds a reader that asks for sessions.
func (s *sessions) join(f *patterns.FIFO[delivery]) *sessionReader {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := &sessionReader{queue: f}
	s.readers = append(s.readers, r)
	return r
}

// finished reports whether r has no sessions left.
func (s *sessions) finished(r *sessionReader) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(time.Now())
	return r.n == 0
}

// leave removes a reader that is gone, and returns what it had not been sent,
// in order, for the caller to relay to another.
func (s *sessions) leave(relayCtx context.Context, r *sessionReader) []delivery {
	s.mu.Lock()
	s.readers = slices.DeleteFunc(s.readers, func(x *sessionReader) bool { return x == r })
	for key, b := range s.bound {
		if b.reader == r {
			delete(s.bound, key)
		}
	}
	s.mu.Unlock()
	// Nothing is sent to it now, so that it can be closed, which flushes it.
	close(r.queue.In())
	var unsent []delivery
	for {
		select {
		case d, ok := <-r.queue.Out():
			if !ok {
				return unsent
			}
			unsent = append(unsent, d)
		case <-relayCtx.Done():
			return unsent
		}
	}
}

// wantsSession reports whether a long polling request asks to be sent the
// deliveries of sessions, using the session query parameter.
func wantsSession(req *http.Request) bool {
	switch req.URL.Query().Get("session") {
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

// serveSession sends a reader that asked for sessions its deliveries, as they
// arrive, from its own queue, and those that are not part of a session, from the
// relay's, until the last of its sessions, or the request ends.
func (r *Relay) serveSession(w http.ResponseWriter, req *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "sessions are not supported: the response cannot be flushed", http.StatusInternalServerError)
		return
	}
	own := patterns.NewFIFO(r.ctx, int(r.opts.size), expiryScan(r.opts)...)
	sr := r.sessions.join(own)
	defer func() {
		// What was not sent, because of a reader that is gone, is for another.
		for _, d := range r.sessions.leave(r.ctx, sr) {
			select {
			case r.fifo.In() <- d:
			case <-r.ctx.Done():
				return
			}
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	enc := newDeliveryEncoder(w)
	for {
		var d delivery
		select {
		case d = <-own.Out():
		case d = <-r.fifo.Out():
		case <-req.Context().Done():
			r.opts.logger.Info("WaitForWebhook: request context cancelled while serving sessions", "err", req.Context().Err())
			return
		}
		if err := encodeDelivery(enc, d); err != nil {
			r.opts.logger.Info("WaitForWebhook: failed to write to client", "session", d.session, "err", err)
			// It was not sent: for another reader.
			select {
			case r.fifo.In() <- d:
			case <-r.ctx.Done():
			}
			return
		}
		flusher.Flush()
		r.opts.logger.Info("WaitForWebhook: sent payload to client", "size", len(d.body), "session", d.session, "last", d.last)
		r.opts.readCounter(req.Context())
		if d.last && r.sessions.finished(sr) {
			return
		}
	}
}
