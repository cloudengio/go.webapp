// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"io"
	"log/slog"
	"net/http"
	"path"
)

// Relay is an HTTP handler that receives JSON payloads and relays them
// over a channel for subsequent processing. It is designed to be used in a webhook
// server to receive webhook payloads and relay them to another http handler
// that is used as a long polling endpoint for a client to receive
// the payloads. The Webhook endpoint will accept POST requests with JSON
// payloads and the Wait endpoint will accept GET requests and will block
// until a payload is received/
type Relay struct {
	jobsCh    chan []byte
	validator Validator
	opts      options
}

type options struct {
	size         int
	payloadLimit int
	logger       *slog.Logger
}

const (
	DefaultQueueSize    = 100
	DefaultPayloadLimit = 1024 * 1024 // 1MB
)

// Option is a function that configures the Relay.
type Option func(*options)

// WithQueueSize sets the size of the channel buffer for relaying payloads.
func WithQueueSize(size int) Option {
	return func(opts *options) {
		opts.size = size
	}
}

// WithMaxPayloadSize sets the maximum allowed payload size for incoming webhook
// requests.
func WithMaxPayloadSize(size int) Option {
	return func(opts *options) {
		opts.payloadLimit = size
	}
}

// WithLogger sets the logger for the Relay.
func WithLogger(logger *slog.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

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

// NewRelay creates a new Relay with the provided Validator and options. The
func NewRelay(validator Validator, opts ...Option) *Relay {
	var options options
	options.size = DefaultQueueSize
	options.payloadLimit = DefaultPayloadLimit
	for _, opt := range opts {
		opt(&options)
	}
	if options.logger == nil {
		options.logger = slog.New(slog.DiscardHandler)
	}
	options.logger = options.logger.With("component", "webhooks.Relay")
	return &Relay{
		jobsCh:    make(chan []byte, options.size),
		validator: validator,
		opts:      options,
	}
}

// ServeWebhook handles incoming webhook requests, validates them using the
// provided Validator, and relays the payload to the channel for processing.
// It responds with appropriate HTTP status codes based on the validation and
// processing outcome.
func (r *Relay) ServeWebhook(w http.ResponseWriter, req *http.Request) {
	if req.ContentLength > int64(r.opts.payloadLimit) {
		http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if req.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if req.Body == nil {
		// Paranonoial check since http.Request should always have a non-nil Body, but we check it just in case.
		http.Error(w, "Request body is required", http.StatusBadRequest)
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, int64(r.opts.payloadLimit))
	payload, status := r.validator(req)
	if status != http.StatusOK {
		http.Error(w, "Invalid payload", status)
		return
	}
	select {
	case r.jobsCh <- payload:
		r.opts.logger.Info("ServeWebhook: received payload and sent to channel", "size", len(payload))
	case <-req.Context().Done():
		err := req.Context().Err()
		r.opts.logger.Info("ServeWebhook: context cancelled while trying to send payload to channel", "err", err)
	default:
		w.WriteHeader(http.StatusInternalServerError)
		r.opts.logger.Error("ServeWebhook: channel is full, unable to process payload", "size", len(payload))
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// WaitForWebhook waits for a payload to be received on the channel and responds
// with the payload as JSON. It is intended to support long polling by
// blocking until a webhook payload is available.
// If the request context is cancelled while waiting, it logs the cancellation
// and returns without responding.
func (r *Relay) WaitForWebhook(w http.ResponseWriter, req *http.Request) {
	select {
	case job := <-r.jobsCh:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(job)
		r.opts.logger.Info("WaitForWebhook: sent payload to client", "size", len(job))
	case <-req.Context().Done():
		err := req.Context().Err()
		r.opts.logger.Info("WaitForWebhook: request context cancelled while waiting for payload from channel", "err", err)
	}
}

// Handler returns an http.HandlerFunc that routes requests to the appropriate
// handler based on the URL path. It expects the webhook endpoint to be at
// {prefix}/webhook and the wait endpoint to be at {prefix}/wait. Requests to
// other paths will receive a 404 Not Found response.
func (r *Relay) Handler(prefix string) func(w http.ResponseWriter, req *http.Request) {
	hookPath := path.Join(prefix, "webhook")
	waitPath := path.Join(prefix, "wait")
	return func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case hookPath:
			r.ServeWebhook(w, req)
		case waitPath:
			r.WaitForWebhook(w, req)
		default:
			http.NotFound(w, req)
		}
	}
}
