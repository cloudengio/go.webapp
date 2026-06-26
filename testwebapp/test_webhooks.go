// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/sync/errgroup"
	"cloudeng.io/webapi/operations"
	"gopkg.in/yaml.v3"
)

// WebhookRoundTripSpec defines a single webhook round-trip test: a signed
// payload is delivered to DeliveryURL and the relayed result is read back from
// RelayURL and compared to the original payload. The signer for each delivery
// URL is looked up from the map passed to NewWebhookRoundTripTest.
type WebhookRoundTripSpec struct {
	DeliveryURL string `yaml:"delivery_url" doc:"URL that the webhook payload is delivered to"`
	RelayURL    string `yaml:"relay_url" doc:"URL that the relayed result is read from"`
}

// String implements fmt.Stringer, returning the YAML representation of the spec.
func (s WebhookRoundTripSpec) String() string {
	out, err := yaml.Marshal(s)
	if err != nil {
		return err.Error()
	}
	return string(out)
}

// WebhookRoundTripTest validates webhook relay round-trips for a set of specs.
type WebhookRoundTripTest struct {
	signers map[string]operations.Signer
	specs   []WebhookRoundTripSpec
}

// NewWebhookRoundTripTest creates a new WebhookRoundTripTest. signers maps each
// delivery URL to the operations.Signer used to sign payloads for that endpoint;
// a nil or missing entry means the request is sent unsigned.
func NewWebhookRoundTripTest(signers map[string]operations.Signer, specs ...WebhookRoundTripSpec) *WebhookRoundTripTest {
	return &WebhookRoundTripTest{signers: signers, specs: specs}
}

func (w *WebhookRoundTripTest) Run(ctx context.Context, client *http.Client) error {
	ctxlog.Info(ctx, "webhook-roundtrip: starting", "num_specs", len(w.specs))
	var g errgroup.T
	for _, spec := range w.specs {
		g.Go(func() error {
			err := w.runOne(ctx, spec, client)
			if err != nil {
				ctxlog.Error(ctx, "webhook-roundtrip", "spec", spec, "success", false, "error", err)
				return fmt.Errorf("%v: %w", spec, err)
			}
			ctxlog.Info(ctx, "webhook-roundtrip", "spec", spec, "success", true)
			return nil
		})
	}
	return g.Wait()
}

type webhookTestPayload struct {
	ID   string `json:"id"`
	Time string `json:"time"`
}

func (w *WebhookRoundTripTest) runOne(ctx context.Context, spec WebhookRoundTripSpec, client *http.Client) error {
	payload := webhookTestPayload{
		ID:   fmt.Sprintf("test-%d", time.Now().UnixNano()),
		Time: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := w.deliver(ctx, spec, client, payload); err != nil {
		return err
	}
	return w.wait(ctx, spec, client, payload)
}

func (w *WebhookRoundTripTest) deliver(ctx context.Context, spec WebhookRoundTripSpec, client *http.Client, payload webhookTestPayload) error {
	opts := []operations.Option{operations.WithHTTPClient(client)}
	if signer := w.signers[spec.DeliveryURL]; signer != nil {
		opts = append(opts, operations.WithSigner(signer))
	}

	ep := operations.NewPutEndpoint[webhookTestPayload, struct{}](opts...)
	_, _, _, err := ep.Post(ctx, spec.DeliveryURL, payload)
	if err != nil {
		return fmt.Errorf("delivering webhook: %w", err)
	}

	return nil
}

// DrainRelayURL collects all payloads from relayURL, decoding each as T.
// It uses timeout as an idle deadline: after receiving a payload it resets
// the timer, so a short queue returns quickly. It returns when no payload
// arrives within timeout or ctx is cancelled.
func DrainRelayURL[T any](ctx context.Context, client *http.Client, relayURL string, timeout time.Duration) ([]T, error) {
	ep := operations.NewEndpoint[T](operations.WithHTTPClient(client))
	var results []T
	for {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		idleCtx, cancel := context.WithTimeout(ctx, timeout)
		got, _, _, err := ep.Get(idleCtx, relayURL)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return results, ctx.Err()
			}
			if errors.Is(idleCtx.Err(), context.DeadlineExceeded) {
				return results, nil
			}
			return results, err
		}
		results = append(results, got)
	}
}

func (w *WebhookRoundTripTest) wait(ctx context.Context, spec WebhookRoundTripSpec, client *http.Client, want webhookTestPayload) error {
	ep := operations.NewEndpoint[webhookTestPayload](
		operations.WithHTTPClient(client),
	)
	for {
		got, data, _, err := ep.Get(ctx, spec.RelayURL)
		if err != nil {
			ctxlog.Error(ctx, "webhook-relay", "spec", spec, "got", string(data), "error", err)
			return fmt.Errorf("waiting for relay: %w", err)
		}
		if got == want {
			return nil
		}
		ctxlog.Info(ctx, "webhook-relay-skip", "spec", spec, "got", got, "want", want)
	}
}
