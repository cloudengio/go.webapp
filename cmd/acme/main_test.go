// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloudeng.io/logging"
	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/webapp/webauth/acme"
	"cloudeng.io/webapp/webauth/acme/pebble"
	"cloudeng.io/webapp/webauth/acme/pebble/pebbletest"
)

func defaultManagerFlags(pebbleCfg pebble.Config, pebbleTestDir, pebbleCacheDir string) certManagerFlags {
	return certManagerFlags{
		ClientHostFlag: ClientHostFlag{pebbleCfg.Address},
		ServiceFlags: acme.ServiceFlags{
			Provider: pebbleCfg.DirectoryURL(),
			Email:    "dev@cloudeng.io",
		},
		HTTPPort:         pebbleCfg.HTTPPort,
		TestingCAPEMFlag: TestingCAPEMFlag{filepath.Join(pebbleTestDir, pebbleCfg.CAFile)},
		RefreshInterval:  time.Minute,
		TLSCertStoreFlags: TLSCertStoreFlags{
			LocalCacheDir: pebbleCacheDir,
		},
	}
}

func TestNewCert(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(logging.NewJSONFormatter(os.Stderr, "", "  "), nil))
	ctx := ctxlog.WithLogger(t.Context(), logger)

	tmpDir := t.TempDir()

	pebbleServer, pebbleCfg, _, pebbleCacheDir, pebbleTestDir := pebbletest.Start(ctx, t, tmpDir)
	defer pebbleServer.EnsureStopped(ctx, time.Second) //nolint:errcheck

	mgrFlags := defaultManagerFlags(pebbleCfg, pebbleTestDir, pebbleCacheDir)
	mgrFlags.RefreshInterval = time.Second

	stopAndWaitForCertManager := runCertManager(ctx, t, &mgrFlags, "pebble-test.example.com")

	// Wait for at least one certificate to be issued.
	if _, err := pebbleServer.WaitForOrderAuthorized(ctx); err != nil {
		t.Fatalf("failed to wait for issued certificate serial: %v", err)
	}

	localhostCert := filepath.Join(pebbleCacheDir, "certs", "pebble-test.example.com")
	leaf, intermediates := pebbletest.WaitForNewCert(ctx, t, "new cert", localhostCert, "")

	if err := leaf.VerifyHostname("pebble-test.example.com"); err != nil {
		t.Fatalf("hostname verification failed: %v", err)
	}

	if err := pebbleCfg.ValidateCertificate(ctx, leaf, intermediates); err != nil {
		t.Fatalf("failed to validate certificate: %v", err)
	}

	validFor := leaf.NotAfter.Sub(leaf.NotBefore)
	found := false
	for _, period := range pebbleCfg.PossibleValidityPeriods() {
		if durationWithin(period, validFor, time.Second*10) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected validity period to be one of %v, got %v", pebbleCfg.PossibleValidityPeriods(), validFor)
	}

	stopAndWaitForCertManager(t)
}

func TestCertRenewal(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(logging.NewJSONFormatter(os.Stderr, "", "  "), nil))
	ctx := ctxlog.WithLogger(t.Context(), logger)

	tmpDir := t.TempDir()

	pebbleServer, pebbleCfg, recorder, pebbleCacheDir, pebbleTestDir := pebbletest.Start(ctx, t, tmpDir,
		pebble.WithValidityPeriod(10), // short lived certs to force renewal
	)
	defer pebbleServer.EnsureStopped(ctx, time.Second) //nolint:errcheck

	mgrFlags := defaultManagerFlags(pebbleCfg, pebbleTestDir, pebbleCacheDir)
	mgrFlags.RenewBefore = time.Second * 15 // allow immediate renewal
	mgrFlags.RefreshInterval = time.Second

	stopAndWaitForCertManager := runCertManager(ctx, t, &mgrFlags, "pebble-test.example.com")

	var previousSerial string
	for i := range 3 {
		// Wait for a certificate to be issued.
		if _, err := pebbleServer.WaitForOrderAuthorized(ctx); err != nil {
			t.Fatalf("%v: failed to wait for issued certificate serial: %v", i, err)
		}

		localhostCert := filepath.Join(pebbleCacheDir, "certs", "pebble-test.example.com")

		leaf, intermediates := pebbletest.WaitForNewCert(ctx, t,
			fmt.Sprintf("waiting for cert %v", i),
			localhostCert, previousSerial, recorder)

		if err := leaf.VerifyHostname("pebble-test.example.com"); err != nil {
			t.Fatalf("%v: hostname verification failed: %v", i, err)
		}

		if err := pebbleCfg.ValidateCertificate(ctx, leaf, intermediates); err != nil {
			t.Fatalf("%v: failed to validate certificate: %v", i, err)
		}

		validFor := leaf.NotAfter.Sub(leaf.NotBefore)
		serial := fmt.Sprintf("%0*x", len(leaf.SerialNumber.Bytes())*2, leaf.SerialNumber)
		t.Logf("obtained certificate %v valid for %v (serial %v)", i, validFor, serial)
		previousSerial = serial
	}

	stopAndWaitForCertManager(t)
}

func durationWithin(d1, d2, tolerance time.Duration) bool {
	diff := d1 - d2
	if diff < 0 {
		diff = -diff
	}
	return diff <= tolerance
}

func runCertManager(ctx context.Context, t *testing.T, flags *certManagerFlags, host string) func(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		err := certManagerCmd{}.manageCerts(ctx, flags, []string{host})
		t.Logf("cert manager exited: %v", err)
		errCh <- err
	}()

	return func(t *testing.T) {
		cancel()
		waitForServer(t, errCh)
	}
}

func waitForServer(t *testing.T, errCh <-chan error) {
	t.Logf("waiting for cert manager to exit")
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("cert manager exited with unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for cert manager to exit")
	}
}
