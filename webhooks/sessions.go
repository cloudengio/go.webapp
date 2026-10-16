// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"

	"cloudeng.io/sync/patterns"
)

// SessionKeyFunc identifies the session, if any, that a webhook delivery
// belongs to, so that all of the deliveries of a session, for example all of
// the webhooks for a GitHub workflow run, are relayed to the same long polling
// reader. header is the header of the delivery request and body its payload,
// both of which have been validated. It returns an empty key for a delivery
// that is not part of a session, which can be relayed to any reader. last is
// true if the delivery is the last of its session.
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
		return "run:" + strconv.FormatInt(payload.WorkflowRun.ID, 10), payload.Action == "completed"
	case payload.WorkflowJob != nil && payload.WorkflowJob.RunID != 0:
		return "run:" + strconv.FormatInt(payload.WorkflowJob.RunID, 10), false
	}
	return "", false
}

// WithSessions configures the relay to keep the deliveries of a session, as
// identified by key, together: a long polling reader that asks for sessions,
// see Relay.WaitForWebhook, is given its own queue, and each session is bound,
// when its first delivery arrives, to the queue of the reader with the fewest
// sessions, which is sent all of its deliveries from then on. Deliveries that are
// not part of a session are relayed as they are without sessions, to any reader.
// If no such reader is waiting when the first delivery of a session arrives, it
// is relayed to any reader, as is the rest of that session.
func WithSessions(key SessionKeyFunc) Option {
	return func(opts *options) {
		opts.sessionKey = key
	}
}

// sessions is the queues of the readers that ask for sessions, and which of them
// each session is bound to. There is a queue per reader, as there is for the
// deliveries that are not part of a session, so that it is the queue that is
// bounded, and that expires deliveries.
type sessions struct {
	mu      sync.Mutex
	readers map[*patterns.FIFO[delivery]]int    // each reader's queue, and how many sessions are bound to it
	bound   map[string]*patterns.FIFO[delivery] // session to the queue of its reader
}

func newSessions() *sessions {
	return &sessions{
		readers: map[*patterns.FIFO[delivery]]int{},
		bound:   map[string]*patterns.FIFO[delivery]{},
	}
}

// route sends d, which is part of a session, to the queue of the reader that
// its session is bound to, which is the one with the fewest sessions if it
// is not bound. It reports false if there is no reader, in which case the
// delivery is for the caller to queue, and otherwise the error, if any, is that
// ctx or the relay's ctx ended before it could be sent.
func (s *sessions) route(ctx, relayCtx context.Context, d delivery) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.bound[d.session]
	if f == nil {
		for q, n := range s.readers {
			if f == nil || n < s.readers[f] {
				f = q
			}
		}
		if f == nil {
			return false, nil
		}
		s.bound[d.session] = f
		s.readers[f]++
	}
	if d.last {
		delete(s.bound, d.session)
		s.readers[f]--
	}
	// Sent under the lock, so that the queue is not closed by its reader leaving.
	// The queue always accepts, dropping its oldest delivery if it is full.
	select {
	case f.In() <- d:
		return true, nil
	case <-ctx.Done():
		return true, ctx.Err()
	case <-relayCtx.Done():
		return true, relayCtx.Err()
	}
}

// join returns a queue for a reader that asks for sessions.
func (s *sessions) join(f *patterns.FIFO[delivery]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readers[f] = 0
}

// finished reports whether the reader of f has no sessions left.
func (s *sessions) finished(f *patterns.FIFO[delivery]) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readers[f] == 0
}

// leave removes the queue of a reader that is gone, and returns what it had
// not been sent, in order, for the caller to relay to another.
func (s *sessions) leave(relayCtx context.Context, f *patterns.FIFO[delivery]) []delivery {
	s.mu.Lock()
	delete(s.readers, f)
	for key, q := range s.bound {
		if q == f {
			delete(s.bound, key)
		}
	}
	s.mu.Unlock()
	// Nothing is sent to it now, so that it can be closed, which flushes it.
	close(f.In())
	var unsent []delivery
	for {
		select {
		case d, ok := <-f.Out():
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

// sessionDelivery is a delivery as it is sent to a reader that asked for
// sessions, one JSON value per line.
type sessionDelivery struct {
	Headers http.Header     `json:"headers,omitempty"`
	Session string          `json:"session,omitempty"`
	Last    bool            `json:"last,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Body    string          `json:"body,omitempty"` // the payload, if it is not JSON
}

func newSessionDelivery(d delivery) sessionDelivery {
	s := sessionDelivery{Headers: d.header, Session: d.session, Last: d.last}
	if json.Valid(d.body) {
		s.Payload = d.body
	} else {
		s.Body = string(d.body)
	}
	return s
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
	r.sessions.join(own)
	defer func() {
		// What was not sent, because of a reader that is gone, is for another.
		for _, d := range r.sessions.leave(r.ctx, own) {
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
	enc := json.NewEncoder(w)
	for {
		var d delivery
		select {
		case d = <-own.Out():
		case d = <-r.fifo.Out():
		case <-req.Context().Done():
			r.opts.logger.Info("WaitForWebhook: request context cancelled while serving sessions", "err", req.Context().Err())
			return
		}
		if err := enc.Encode(newSessionDelivery(d)); err != nil {
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
		if d.last && r.sessions.finished(own) {
			return
		}
	}
}
