// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package acme_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloudeng.io/errors"
	"cloudeng.io/logging"
	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/webapp"
	"cloudeng.io/webapp/webauth/acme"
	"cloudeng.io/webapp/webauth/acme/certcache"
	"cloudeng.io/webapp/webauth/acme/pebble/pebbletest"
)

func TestACMEClient_FullFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	ctx = ctxlog.WithLogger(ctx, slog.New(slog.NewJSONHandler(logging.NewJSONFormatter(os.Stderr, "", "  "), nil)))

	tmpDir := t.TempDir()

	// Start a pebble server.
	pebbleServer, pebbleCfg, _, pebbleCacheDir, pebbleTestDir := pebbletest.Start(ctx, t, tmpDir)
	defer func() {
		if err := pebbleServer.EnsureStopped(ctx, time.Second); err != nil {
			t.Errorf("failed to stop pebble server: %v", err)
		}
	}()
	certDir := filepath.Join(pebbleCacheDir, "certs")
	// Prepare the autocert manager.
	lb, err := certcache.NewLocalStore(certDir)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := certcache.NewCachingStore(pebbleCacheDir, lb)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := acme.NewAutocertManager(cache, acme.AutocertConfig{
		Provider: pebbleCfg.DirectoryURL(),
	}, "pebble-test.example.com")
	if err != nil {
		t.Fatal(err)
	}
	stripPort := certcache.WrapHostPolicyNoPort(mgr.HostPolicy)
	mgr.HostPolicy = stripPort
	mgr.Client.HTTPClient, err = webapp.NewHTTPClient(ctx,
		webapp.WithCustomCAPEMFile(filepath.Join(pebbleTestDir, pebbleCfg.CAFile)))
	if err != nil {
		t.Fatalf("failed to create acme manager http client: %v", err)
	}
	httpHandler := mgr.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))

	// Start HTTP server to handle ACME HTTP-01 challenges.
	httpListener, httpServer, err := webapp.NewHTTPServer(ctx, fmt.Sprintf(":%d", pebbleCfg.HTTPPort), httpHandler)
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		err := webapp.ServeWithShutdown(ctx, httpListener, httpServer, time.Minute)
		errCh <- err
	}()

	// Start the client to refresh certs.

	client := acme.NewClient(mgr, time.Minute, "pebble-test.example.com")
	if err != nil {
		t.Fatalf("failed to create acme client: %v", err)
	}
	stopAcmeClient, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start acme client: %v", err)
	}

	localhostCert := filepath.Join(certDir, "pebble-test.example.com")

	leaf, intermediates := pebbletest.WaitForNewCert(ctx, t,
		"waiting for cert", localhostCert, "")
	if err := leaf.VerifyHostname("pebble-test.example.com"); err != nil {
		t.Fatalf("hostname verification failed: %v", err)
	}

	if err := pebbleCfg.ValidateCertificate(ctx, leaf, intermediates); err != nil {
		t.Fatalf("failed to validate certificate: %v", err)
	}

	cancel()
	var errs errors.M
	errs.Append(<-errCh)
	errs.Append(stopAcmeClient())
	if err := errs.Err(); err != nil {
		t.Fatal(err)
	}
}
