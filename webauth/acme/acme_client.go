// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/sync/errgroup"
	"cloudeng.io/webapp"
	"golang.org/x/crypto/acme/autocert"
)

// Client implements an ACME client that periodically refreshes
// certificates for a set of hosts using the provided autocert.Manager.
type Client struct {
	mgr  *autocert.Manager
	opts clientOptions
}

type ClientOption func(o *clientOptions)

type clientOptions struct {
	refreshInterval  time.Duration
	refreshMetric    webapp.CounterVecInc
	refreshOnFailure time.Duration
}

// WithRefreshInterval configures the client to refresh certificates
// at the provided interval. The default is 1 hour.
func WithRefreshInterval(interval time.Duration) ClientOption {
	return func(o *clientOptions) {
		o.refreshInterval = interval
	}
}

// WithRefreshMetric configures the client to increment the provided metric
// with the outcome of each refresh operation. The metric will be
// incremented with the labels: host, status.
func WithRefreshMetric(refresh webapp.CounterVecInc) ClientOption {
	return func(o *clientOptions) {
		o.refreshMetric = refresh
	}
}

// WithRefreshOnFailure configures the client to refresh certificates
// at the provided interval when a refresh fails. If not set, the default
// is 1 minute.
func WithRefreshOnFailure(interval time.Duration) ClientOption {
	return func(o *clientOptions) {
		o.refreshOnFailure = interval
	}
}

// NewClient creates a new client that refreshes certificates for the
// provided hosts using the autocert.Manager.
func NewClient(mgr *autocert.Manager, opts ...ClientOption) *Client {
	var o clientOptions
	o.refreshMetric = func(context.Context, ...string) {}
	for _, opt := range opts {
		opt(&o)
	}
	if o.refreshInterval <= 0 {
		o.refreshInterval = time.Hour
	}
	if o.refreshOnFailure <= 0 {
		o.refreshOnFailure = time.Minute
	}
	return &Client{
		mgr:  mgr,
		opts: o,
	}
}

// Start starts the client, refreshing certificates for the provided hosts.
// It returns a function that can be called to stop the client.
func (s *Client) Start(ctx context.Context, hosts ...string) (func() error, error) {
	hosts = slices.Clone(hosts)
	refreshCtx, cancel := context.WithCancel(ctx)
	logger := ctxlog.Logger(ctx).With("component", "acme_client")
	errCh := make(chan error, 1)
	go s.refresh(refreshCtx, logger, errCh, hosts)
	return func() error {
		return s.stop(logger, cancel, errCh)
	}, nil
}

func (s *Client) stop(logger *slog.Logger, cancel func(), errCh <-chan error) error {
	cancel()
	logger.Info("stopping acme client")
	select {
	case err := <-errCh:
		if err != nil {
			logger.Error("acme client stopped with error", "error", err)
		} else {
			logger.Info("acme client stopped")
		}
		return err
	case <-time.After(5 * time.Second):
		logger.Warn("timeout waiting for acme server to stop")
		return fmt.Errorf("timeout waiting for acme server to stop")
	}
}

func (s *Client) getCertificate(ctx context.Context, logger *slog.Logger, host string) {
	ticker := time.NewTicker(s.opts.refreshOnFailure)
	defer ticker.Stop()
	for {
		err := s.refreshHost(ctx, logger, host)
		if err == nil {
			return
		}
		logger.Error("failed to refresh certificate using tls hello", "host", host, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Client) refresh(ctx context.Context, logger *slog.Logger, errCh chan<- error, hosts []string) {
	grp := &errgroup.T{}
	for _, host := range hosts {
		h := host
		grp.Go(func() error {
			logger.Info("starting certificate refresh loop", "host", h, "interval", s.opts.refreshInterval.String())
			ticker := time.NewTicker(s.opts.refreshInterval)
			defer ticker.Stop()
			for {
				s.getCertificate(ctx, logger, h)
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
				}
			}
		})
	}
	errCh <- grp.Wait()
}

func (s *Client) refreshHost(ctx context.Context, logger *slog.Logger, host string) error {
	hello := tls.ClientHelloInfo{
		ServerName:       host,
		CipherSuites:     webapp.PreferredCipherSuites,
		SignatureSchemes: webapp.PreferredSignatureSchemes,
	}
	logger.Info("refreshing certificate using tls hello", "host", host)
	cert, err := s.mgr.GetCertificate(&hello)
	if err != nil {
		s.opts.refreshMetric(ctx, host, "failed")
		return err
	}
	leaf := cert.Leaf
	logger.Info("refreshed certificate using tls hello", "host", host, "expiry", leaf.NotAfter, "serial", fmt.Sprintf("%0*x", len(leaf.SerialNumber.Bytes())*2, leaf.SerialNumber))
	if time.Now().After(leaf.NotAfter) {
		logger.Warn("certificate has expired", "host", host, "expiry", leaf.NotAfter, "serial", fmt.Sprintf("%0*x", len(leaf.SerialNumber.Bytes())*2, leaf.SerialNumber))
		s.opts.refreshMetric(ctx, host, "expired")
	} else {
		s.opts.refreshMetric(ctx, host, "ok")
	}
	return nil
}
