// Copyright 2021 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package acme_test

import (
	"context"
	"crypto/tls"
	"flag"
	"net"
	"strings"
	"testing"
	"time"

	"cloudeng.io/cmdutil/flags"
	"cloudeng.io/webapp/webauth/acme"
	"golang.org/x/crypto/acme/autocert"
)

// helloWithConn returns a *tls.ClientHelloInfo with a non-nil Conn, as is
// required for the RemoteAddr() call made by the code under test when it
// rejects a hello for not supporting ECDSA.
func helloWithConn(t *testing.T, serverName string, opts ...func(*tls.ClientHelloInfo)) *tls.ClientHelloInfo {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	hello := &tls.ClientHelloInfo{
		ServerName: serverName,
		Conn:       serverConn,
	}
	for _, opt := range opts {
		opt(hello)
	}
	return hello
}

var (
	ecdsaCipherSuite = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	rsaCipherSuite   = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
)

func TestSupportsECDSA(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hello *tls.ClientHelloInfo
		want  bool
	}{
		{
			name:  "no information at all",
			hello: &tls.ClientHelloInfo{},
			want:  false,
		},
		{
			name: "ecdsa cipher suite present",
			hello: &tls.ClientHelloInfo{
				CipherSuites: []uint16{rsaCipherSuite, ecdsaCipherSuite},
			},
			want: true,
		},
		{
			name: "only rsa cipher suites",
			hello: &tls.ClientHelloInfo{
				CipherSuites: []uint16{rsaCipherSuite},
			},
			want: false,
		},
		{
			name: "rsa-only signature schemes short-circuits despite ecdsa cipher suite",
			hello: &tls.ClientHelloInfo{
				SignatureSchemes: []tls.SignatureScheme{tls.PSSWithSHA256, tls.PKCS1WithSHA256},
				CipherSuites:     []uint16{ecdsaCipherSuite},
			},
			want: false,
		},
		{
			name: "ecdsa signature scheme and matching cipher suite",
			hello: &tls.ClientHelloInfo{
				SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
				CipherSuites:     []uint16{ecdsaCipherSuite},
			},
			want: true,
		},
		{
			name: "unsupported curve despite ecdsa cipher suite",
			hello: &tls.ClientHelloInfo{
				SupportedCurves: []tls.CurveID{tls.CurveP384},
				CipherSuites:    []uint16{ecdsaCipherSuite},
			},
			want: false,
		},
		{
			name: "supported curve and matching cipher suite",
			hello: &tls.ClientHelloInfo{
				SupportedCurves: []tls.CurveID{tls.CurveP256},
				CipherSuites:    []uint16{ecdsaCipherSuite},
			},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := acme.SupportsECDSA(tc.hello); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetCertificateECDSAOnly(t *testing.T) {
	wantCert := &tls.Certificate{}
	var calledWith *tls.ClientHelloInfo
	getCert := acme.GetCertificateECDSAOnly(func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		calledWith = hello
		return wantCert, nil
	})

	t.Run("ecdsa supported", func(t *testing.T) {
		calledWith = nil
		hello := helloWithConn(t, "example.com", func(h *tls.ClientHelloInfo) {
			h.CipherSuites = []uint16{ecdsaCipherSuite}
		})
		cert, err := getCert(hello)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cert != wantCert {
			t.Errorf("got %v, want %v", cert, wantCert)
		}
		if calledWith != hello {
			t.Error("wrapped getCert was not called with the supplied hello")
		}
	})

	t.Run("ecdsa not supported", func(t *testing.T) {
		calledWith = nil
		hello := helloWithConn(t, "example.com", func(h *tls.ClientHelloInfo) {
			h.CipherSuites = []uint16{rsaCipherSuite}
		})
		_, err := getCert(hello)
		if err == nil || !strings.Contains(err.Error(), "does not support ECDSA certificates") {
			t.Errorf("got %v, want an ECDSA-unsupported error", err)
		}
		if calledWith != nil {
			t.Error("wrapped getCert should not have been called")
		}
	})
}

func TestFlags(t *testing.T) {
	ctx := context.Background()
	cl := acme.ServiceFlags{}
	flagSet := &flag.FlagSet{}
	err := flags.RegisterFlagsInStruct(flagSet, "subcmd", &cl, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = flagSet.Parse([]string{
		"--acme-renew-before=1h",
		"--acme-email=foo@bar"})
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := acme.NewAutocertManager(autocert.DirCache(t.TempDir()), cl.AutocertConfig(), "login.domain", "allowed-domain-a", "allowed-domain-b")
	if err != nil {
		t.Fatal(err)
	}

	hostPolicy := mgr.HostPolicy
	for _, host := range []string{"login.domain", "allowed-domain-a", "allowed-domain-b"} {
		if err := hostPolicy(ctx, host); err != nil {
			t.Fatalf("unexpected error for host %v: %v", host, err)
		}
	}

	err = hostPolicy(ctx, "not-there")
	if err == nil || !strings.Contains(err.Error(), `host "not-there" not configured in HostWhitelist`) {
		t.Errorf("missing or unexpected error: %v", err)
	}

	if got, want := mgr.Client.DirectoryURL, acme.LetsEncryptStaging; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	if got, want := mgr.RenewBefore, time.Hour; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

}

// newTestManager creates a Manager with no allowed hosts, so that any call to
// the underlying autocert.Manager.GetCertificate that gets past the
// AllowRSACertificates check fails fast (on HostPolicy, before any network
// access) with a distinctly different error than the ECDSA-rejection one,
// making it possible to tell which check, if any, rejected the request.
func newTestManager(t *testing.T, allowRSA bool) *acme.Manager {
	t.Helper()
	mgr, err := acme.NewAutocertManager(autocert.DirCache(t.TempDir()), acme.AutocertConfig{
		AllowRSACertificates: allowRSA,
	})
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func TestManagerGetCertificateRefusesRSAWhenNotAllowed(t *testing.T) {
	mgr := newTestManager(t, false)

	hello := helloWithConn(t, "test.example.com", func(h *tls.ClientHelloInfo) {
		h.CipherSuites = []uint16{rsaCipherSuite}
	})
	_, err := mgr.GetCertificate(hello)
	if err == nil || !strings.Contains(err.Error(), "does not support ECDSA certificates") {
		t.Errorf("got %v, want an ECDSA-unsupported error", err)
	}
}

func TestManagerGetCertificateAllowsECDSAWhenNotAllowingRSA(t *testing.T) {
	mgr := newTestManager(t, false)

	// The client does support ECDSA, so the RSA check should pass and the
	// request should fall through to the underlying autocert.Manager, which
	// fails fast on HostPolicy since no hosts are configured.
	hello := helloWithConn(t, "test.example.com", func(h *tls.ClientHelloInfo) {
		h.CipherSuites = []uint16{ecdsaCipherSuite}
	})
	_, err := mgr.GetCertificate(hello)
	if err == nil || strings.Contains(err.Error(), "does not support ECDSA certificates") {
		t.Errorf("got %v, want a HostWhitelist error, not an ECDSA-unsupported error", err)
	}
	if !strings.Contains(err.Error(), "not configured in HostWhitelist") {
		t.Errorf("got %v, want a HostWhitelist error", err)
	}
}

func TestManagerGetCertificateAllowsRSAWhenAllowed(t *testing.T) {
	mgr := newTestManager(t, true)

	// AllowRSACertificates is true, so even an RSA-only client should fall
	// through to the underlying autocert.Manager without being rejected for
	// lacking ECDSA support, and fail fast on HostPolicy instead.
	hello := helloWithConn(t, "test.example.com", func(h *tls.ClientHelloInfo) {
		h.CipherSuites = []uint16{rsaCipherSuite}
	})
	_, err := mgr.GetCertificate(hello)
	if err == nil || strings.Contains(err.Error(), "does not support ECDSA certificates") {
		t.Errorf("got %v, want a HostWhitelist error, not an ECDSA-unsupported error", err)
	}
	if !strings.Contains(err.Error(), "not configured in HostWhitelist") {
		t.Errorf("got %v, want a HostWhitelist error", err)
	}
}

func TestManagerTLSConfigWiresGetCertificate(t *testing.T) {
	mgr := newTestManager(t, false)

	cfg := mgr.TLSConfig()
	if cfg.GetCertificate == nil {
		t.Fatal("cfg.GetCertificate is nil")
	}

	hello := helloWithConn(t, "test.example.com", func(h *tls.ClientHelloInfo) {
		h.CipherSuites = []uint16{rsaCipherSuite}
	})
	_, err := cfg.GetCertificate(hello)
	if err == nil || !strings.Contains(err.Error(), "does not support ECDSA certificates") {
		t.Errorf("got %v, want an ECDSA-unsupported error", err)
	}
}
