// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/webapi/operations"
	"cloudeng.io/webapp/testwebapp"
	"cloudeng.io/webapp/webhooks"
)

func TestWebhookRoundTripSpecString(t *testing.T) {
	spec := testwebapp.WebhookRoundTripSpec{
		DeliveryURL: "http://example.com/deliver",
		RelayURL:    "http://example.com/relay",
	}
	got := spec.String()
	for _, want := range []string{"delivery_url: http://example.com/deliver", "relay_url: http://example.com/relay"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, want it to contain %q", got, want)
		}
	}
}

// newWebhookRelay creates a relay server backed by an HMAC-SHA256 validator,
// registers cleanup, and returns the test server.
func newWebhookRelay(t *testing.T, secret []byte, signHeader string) *httptest.Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	getSig := webhooks.SHA256SignatureFromHeader(signHeader)
	getTokens := func(_ context.Context) ([]keys.Token, error) {
		token := keys.NewToken("", "", append([]byte(nil), secret...))
		return []keys.Token{token}, nil
	}
	validator, err := webhooks.SignatureValidator(getSig, getTokens)
	if err != nil {
		t.Fatalf("SignatureValidator: %v", err)
	}

	relay := webhooks.NewRelay(ctx, validator)
	handler := relay.Handler("/webhooks/deliver", "/webhooks/relay")
	srv := httptest.NewServer(http.HandlerFunc(handler))

	t.Cleanup(func() {
		relay.Stop(context.Background())
		cancel()
		srv.Close()
	})
	return srv
}

func hmacSigner(secret []byte, signHeader string) operations.Signer {
	return func(_ context.Context, hdr http.Header, body []byte) error {
		return webhooks.SignHTTPRequest(hdr, body, secret, signHeader)
	}
}

func webhookSpec(srv *httptest.Server) testwebapp.WebhookRoundTripSpec {
	return testwebapp.WebhookRoundTripSpec{
		DeliveryURL: srv.URL + "/webhooks/deliver",
		RelayURL:    srv.URL + "/webhooks/relay",
	}
}

func TestWebhookRoundTrip(t *testing.T) {
	secret := []byte("test-webhook-secret")
	header := "X-Test-Signature"

	t.Run("HappyPath", func(t *testing.T) {
		srv := newWebhookRelay(t, secret, header)
		spec := webhookSpec(srv)
		signers := map[string]operations.Signer{spec.DeliveryURL: hmacSigner(secret, header)}
		wrt := testwebapp.NewWebhookRoundTripTest(signers, spec)
		if err := wrt.Run(t.Context(), srv.Client()); err != nil {
			t.Errorf("expected success, got %v", err)
		}
	})

	t.Run("WrongSecret", func(t *testing.T) {
		srv := newWebhookRelay(t, secret, header)
		spec := webhookSpec(srv)
		signers := map[string]operations.Signer{spec.DeliveryURL: hmacSigner([]byte("wrong-secret"), header)}
		wrt := testwebapp.NewWebhookRoundTripTest(signers, spec)
		if err := wrt.Run(t.Context(), srv.Client()); err == nil {
			t.Error("expected error for wrong secret, got nil")
		}
	})

	// MultipleSpecs uses a separate relay per spec to avoid FIFO ordering races.
	t.Run("MultipleSpecs", func(t *testing.T) {
		srv1 := newWebhookRelay(t, secret, header)
		srv2 := newWebhookRelay(t, secret, header)
		spec1, spec2 := webhookSpec(srv1), webhookSpec(srv2)
		signers := map[string]operations.Signer{
			spec1.DeliveryURL: hmacSigner(secret, header),
			spec2.DeliveryURL: hmacSigner(secret, header),
		}
		wrt := testwebapp.NewWebhookRoundTripTest(signers, spec1, spec2)
		if err := wrt.Run(t.Context(), srv1.Client()); err != nil {
			t.Errorf("expected success, got %v", err)
		}
	})

	t.Run("DeliveryUnreachable", func(t *testing.T) {
		spec := testwebapp.WebhookRoundTripSpec{
			DeliveryURL: "http://127.0.0.1:0/webhooks/deliver",
			RelayURL:    "http://127.0.0.1:0/webhooks/relay",
		}
		signers := map[string]operations.Signer{spec.DeliveryURL: hmacSigner(secret, header)}
		wrt := testwebapp.NewWebhookRoundTripTest(signers, spec)
		if err := wrt.Run(t.Context(), http.DefaultClient); err == nil {
			t.Error("expected error for unreachable server, got nil")
		}
	})

}
