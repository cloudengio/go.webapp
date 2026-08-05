// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"cloudeng.io/sync/patterns"
	"cloudeng.io/webapp"
)

// Relay is an HTTP handler that receives JSON payloads and relays them
// over a channel for subsequent processing. It is designed to be used in a webhook
// server to receive webhook payloads and relay them to another http handler
// that is used as a long polling endpoint for a client to receive
// the payloads. The Webhook endpoint will accept POST requests with JSON
// payloads and the Wait endpoint will accept GET requests and will block
// until a payload is received.
// When the internal buffer is full the oldest webhook is dropped to make
// room for the new one.
type Relay struct {
	fifo      *patterns.FIFO[delivery]
	validator Validator
	opts      options
}

// delivery is a validated webhook payload together with the subset of the
// incoming request headers that the relay forwards to long-polling clients.
type delivery struct {
	header     http.Header
	body       []byte
	expiration time.Time // when the webhook expires
}

type options struct {
	size             int64
	payloadLimit     int64
	forwardedHeaders []string
	expiry           time.Duration
	expiryScan       time.Duration
	logger           *slog.Logger
	deniedCounter    webapp.CounterInc // validation failed, e.g. due to invalid signature
	relayedCounter   webapp.CounterInc // successfully relayed to FIFO
	readCounter      webapp.CounterInc // successfully read from FIFO and sent to client
}

const (
	DefaultQueueSize    = 100
	DefaultPayloadLimit = 1024 * 1024 // 1MB
)

// DefaultForwardedHeaders are the request headers copied from an incoming
// webhook delivery onto the long-poll response when WithForwardedHeaders is not
// used. They carry the GitHub event type and delivery metadata a client needs
// to dispatch events. The X-Hub-Signature-256 header is deliberately omitted:
// the relay has already verified it, and the client has no secret to re-check.
var DefaultForwardedHeaders = []string{
	"X-GitHub-Event",
	"X-GitHub-Delivery",
	"X-GitHub-Hook-ID",
}

// Option is a function that configures the Relay.
type Option func(*options)

// WithQueueSize sets the size of the internal buffer for relaying payloads.
// When the buffer is full the oldest payload is dropped.
func WithQueueSize(size int64) Option {
	return func(opts *options) {
		opts.size = size
	}
}

// WithMaxPayloadSize sets the maximum allowed payload size for incoming webhook
// requests.
func WithMaxPayloadSize(size int64) Option {
	return func(opts *options) {
		opts.payloadLimit = size
	}
}

// WithForwardedHeaders sets the request header names that are copied from an
// incoming webhook delivery onto the long-poll response sent to clients. It
// replaces DefaultForwardedHeaders; pass no names to forward none. Header
// matching is case-insensitive and absent headers are skipped.
func WithForwardedHeaders(names ...string) Option {
	return func(opts *options) {
		// Use a non-nil, possibly empty slice so callers can opt out of all
		// header forwarding without falling back to the default set.
		opts.forwardedHeaders = append([]string{}, names...)
	}
}

// WithExpiry configures the relay to drop queued deliveries that have waited
// longer than ttl without being read by a client, guarding against unbounded
// staleness when no client is polling. The queue is scanned every scanInterval;
// if scanInterval is <= 0 it defaults to ttl. Expiry is disabled (the default)
// when ttl is <= 0, in which case deliveries are only dropped by the queue's
// drop-oldest behaviour when it is full.
func WithExpiry(ttl, scanInterval time.Duration) Option {
	return func(opts *options) {
		opts.expiry = ttl
		opts.expiryScan = scanInterval
	}
}

// WithLogger sets the logger for the Relay.
func WithLogger(logger *slog.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

// WithCounters sets the counters for the Relay. If any of the counters are nil,
// they will be set to a no-op counter that does nothing when called.
// deniedCounter is incremented when a request is denied because the payload fails
// validation, e.g. due to an invalid signature.
// relayedCounter is incremented when a payload is successfully relayed to the FIFO.
// readCounter is incremented when a payload is successfully read from the FIFO and
// sent to a client.
func WithCounters(deniedCounter, relayedCounter, readCounter webapp.CounterInc) Option {
	return func(opts *options) {
		opts.deniedCounter = deniedCounter
		opts.relayedCounter = relayedCounter
		opts.readCounter = readCounter
	}
}

func noopCounter(context.Context) {}

// Validator is called to validate and extract the webhook payload
// from an incoming request. It should return the payload as a byte slice
// and an error if validation fails.
type Validator func(r *http.Request) ([]byte, int)

func NoopValidator(req *http.Request) ([]byte, int) {
	defer req.Body.Close()
	payload, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, http.StatusBadRequest
	}
	return payload, http.StatusOK
}

// NewRelay creates a new Relay with the provided Validator and options.
// ctx governs the lifetime of the internal FIFO goroutine; cancel it or
// call Stop to shut down cleanly.
func NewRelay(ctx context.Context, validator Validator, opts ...Option) *Relay {
	var options options
	for _, opt := range opts {
		opt(&options)
	}
	if options.logger == nil {
		options.logger = slog.New(slog.DiscardHandler)
	}
	if options.size == 0 {
		options.size = DefaultQueueSize
	}
	if options.payloadLimit == 0 {
		options.payloadLimit = DefaultPayloadLimit
	}
	if options.forwardedHeaders == nil {
		options.forwardedHeaders = DefaultForwardedHeaders
	}
	if options.deniedCounter == nil {
		options.deniedCounter = noopCounter
	}
	if options.relayedCounter == nil {
		options.relayedCounter = noopCounter
	}
	if options.readCounter == nil {
		options.readCounter = noopCounter
	}
	options.logger = options.logger.With("component", "webhooks.Relay")
	return &Relay{
		fifo:      patterns.NewFIFO(ctx, int(options.size), expiryScan(options)...),
		validator: validator,
		opts:      options,
	}
}

// expiryScan returns the FIFO options that implement delivery expiry, or nil
// when expiry is disabled.
func expiryScan(opts options) []patterns.Option[delivery] {
	if opts.expiry <= 0 {
		return nil
	}
	interval := opts.expiryScan
	if interval <= 0 {
		interval = opts.expiry
	}
	ttl, logger := opts.expiry, opts.logger
	remove := func(d delivery) bool {
		if time.Now().After(d.expiration) {
			logger.Info("dropping expired webhook delivery", "expiration", d.expiration, "ttl", ttl, "size", len(d.body))
			return true
		}
		return false
	}
	return []patterns.Option[delivery]{patterns.WithPeriodicScan(interval, remove)}
}

// Stop shuts down the internal FIFO goroutine. It blocks until the goroutine
// exits or ctx is cancelled.
func (r *Relay) Stop(ctx context.Context) {
	r.fifo.Stop(ctx)
}

// ServeWebhook handles incoming webhook requests, validates them using the
// provided Validator, and relays the payload to the FIFO for processing.
// If the internal buffer is full the oldest payload is dropped to make room.
// It responds with appropriate HTTP status codes based on the validation outcome.
func (r *Relay) ServeWebhook(w http.ResponseWriter, req *http.Request) {
	if req.ContentLength > r.opts.payloadLimit {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if req.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if req.Body == nil {
		// Paranonoial check since http.Request should always have a non-nil Body, but we check it just in case.
		http.Error(w, "request body is required", http.StatusBadRequest)
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, r.opts.payloadLimit)
	payload, status := r.validator(req)
	if status != http.StatusOK {
		http.Error(w, "invalid payload", status)
		if status >= http.StatusBadRequest && status < http.StatusInternalServerError {
			r.opts.deniedCounter(req.Context())
		}
		return
	}
	if err := req.Context().Err(); err != nil {
		r.opts.logger.Info("ServeWebhook: context already cancelled before send", "err", err)
		return
	}
	select {
	case r.fifo.In() <- delivery{header: r.forwardedHeaders(req.Header), body: payload, expiration: time.Now().Add(r.opts.expiry)}:
		r.opts.logger.Info("ServeWebhook: received payload and sent to FIFO", "size", len(payload))
		r.opts.relayedCounter(req.Context())
	case <-req.Context().Done():
		err := req.Context().Err()
		r.opts.logger.Info("ServeWebhook: context cancelled while trying to send payload to FIFO", "err", err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// WaitForWebhook waits for a payload to be received on the FIFO and responds
// with the payload as JSON. It is intended to support long polling by
// blocking until a webhook payload is available.
// If the request context is cancelled while waiting, it logs the cancellation
// and returns without responding.
func (r *Relay) WaitForWebhook(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	select {
	case job, ok := <-r.fifo.Out():
		if !ok {
			return
		}
		for name, values := range job.header {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(job.body)
		r.opts.logger.Info("WaitForWebhook: sent payload to client", "size", len(job.body))
		r.opts.readCounter(req.Context())
	case <-req.Context().Done():
		err := req.Context().Err()
		r.opts.logger.Info("WaitForWebhook: request context cancelled while waiting for payload from FIFO", "err", err)
	}
}

// forwardedHeaders returns a copy of the configured subset of src, or nil if no
// configured header is present. The returned values are copied so they are not
// aliased with the request headers once it has been recycled.
func (r *Relay) forwardedHeaders(src http.Header) http.Header {
	out := make(http.Header, len(r.opts.forwardedHeaders))
	for _, name := range r.opts.forwardedHeaders {
		if values := src.Values(name); len(values) > 0 {
			out[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DeliveryHandler returns an http.Handler that serves the webhook endpoint
// for receiving payloads.
func (r *Relay) DeliveryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.ServeWebhook(w, req)
	})
}

// PollingHandler returns an http.Handler that serves the wait endpoint for
// long polling clients to receive payloads.
func (r *Relay) PollingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.WaitForWebhook(w, req)
	})
}

// Handler returns an http.HandlerFunc that routes requests to the appropriate
// handler based on the URL path. It expects the webhook endpoint to be at
// deliveryPath and the wait endpoint to be at relayPath. Requests to
// other paths will receive a 404 Not Found response.
func (r *Relay) Handler(deliveryPath, relayPath string) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case deliveryPath:
			r.ServeWebhook(w, req)
		case relayPath:
			r.WaitForWebhook(w, req)
		default:
			http.NotFound(w, req)
		}
	}
}
