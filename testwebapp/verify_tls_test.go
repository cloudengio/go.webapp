// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloudeng.io/webapp"
	"cloudeng.io/webapp/testwebapp"
	"gopkg.in/yaml.v3"
)

func TestTLSSpecString(t *testing.T) {
	spec := testwebapp.TLSSpec{
		Host:               "example.com",
		Port:               "443",
		ExpandDNSNames:     true,
		CheckSerialNumbers: true,
		CipherSuites:       webapp.CipherSuites{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	got := spec.String()
	for _, want := range []string{"host: example.com", "port: \"443\"", "expand-dns-names: true", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, want it to contain %q", got, want)
		}
	}
}

func TestWithCustomCAPEMFile(t *testing.T) {
	specs := []testwebapp.TLSSpec{
		{Host: "example.com"},
		{Host: "example.org", CustomCAPEM: "custom.pem"},
	}
	pemFile := "/path/to/ca.pem"
	got := testwebapp.WithCustomCAPEMFile(specs, pemFile)

	if got[0].CustomCAPEM != pemFile {
		t.Errorf("got %v, want %v", got[0].CustomCAPEM, pemFile)
	}
	if got[1].CustomCAPEM != "custom.pem" {
		t.Errorf("got %v, want %v", got[1].CustomCAPEM, "custom.pem")
	}

	got = testwebapp.WithCustomCAPEMFile(specs, "")
	if got[0].CustomCAPEM != pemFile {
		t.Errorf("got %v, want %v", got[0].CustomCAPEM, pemFile)
	}
}

func TestTLSTest(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "active")
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()
	port := u.Port()

	// Write the server's cert to a file so we can use it as a custom CA.
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "server.pem")
	certOut, err := os.Create(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}); err != nil {
		t.Fatal(err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatal(err)
	}
	// httptest.NewTLSServer creates a cert that doesn't have the IP/Hostname in it properly for verification
	// by default unless we do more work, OR we can just trust the cert pool from the client provided by httptest.
	// However, TLSTest uses its own client creation logic.
	// For tlsvalidate to work with httptest generated certs, we need to extract the cert.

	// Actually, httptest certs are usually self-signed or signed by a temporary CA.
	// Let's try to use the raw cert as the root CA.

	specs := []testwebapp.TLSSpec{
		{
			Host:        host,
			Port:        port,
			CustomCAPEM: caFile,
		},
	}

	// We need to bypass hostname verification because httptest certs are for "example.com" usually or 127.0.0.1
	// but tlsvalidate does strict checking.
	// Wait, httptest.NewTLSServer certs are valid for 127.0.0.1?
	// Let's check what tlsvalidate does. It uses Go's crypto/tls.
	// If the cert isn't valid for localhost, this will fail.
	// httptest certs ARE valid for local IPs mostly.

	tlsTest := testwebapp.NewTLSTest(specs...)
	if err := tlsTest.Run(ctx); err != nil {
		t.Fatalf("TLSTest.Run failed: %v", err)
	}

	// Test failure with wrong CA
	specs[0].CustomCAPEM = filepath.Join(tmpDir, "nonexistent.pem")
	tlsTest = testwebapp.NewTLSTest(specs...)
	if err := tlsTest.Run(ctx); err == nil {
		t.Fatal("TLSTest.Run expected failure with nonexistent CA file")
	}
}

func TestTLSTestSignatureAlgorithms(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "active")
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()
	port := u.Port()

	if got, want := ts.Certificate().SignatureAlgorithm, x509.SHA256WithRSA; got != want {
		t.Fatalf("test setup: expected server cert signature algorithm %v, got %v", want, got)
	}

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "server.pem")
	certOut, err := os.Create(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}); err != nil {
		t.Fatal(err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatal(err)
	}

	// The server's cert signature algorithm is in the allowed set, so the
	// test should pass.
	specs := []testwebapp.TLSSpec{
		{
			Host:                host,
			Port:                port,
			CustomCAPEM:         caFile,
			SignatureAlgorithms: []x509.SignatureAlgorithm{x509.SHA384WithRSA, x509.SHA256WithRSA},
		},
	}
	tlsTest := testwebapp.NewTLSTest(specs...)
	if err := tlsTest.Run(ctx); err != nil {
		t.Fatalf("TLSTest.Run failed: %v", err)
	}

	// The server's cert signature algorithm is not in the allowed set, so
	// the test should fail.
	specs[0].SignatureAlgorithms = []x509.SignatureAlgorithm{x509.ECDSAWithSHA256}
	tlsTest = testwebapp.NewTLSTest(specs...)
	err = tlsTest.Run(ctx)
	if err == nil {
		t.Fatal("TLSTest.Run expected failure for disallowed signature algorithm")
	}
	if !strings.Contains(err.Error(), "is not one of the allowed algorithms") {
		t.Errorf("expected error to contain %q, but got %q", "is not one of the allowed algorithms", err.Error())
	}
}

func TestTLSTestNotAllowedSignatureAlgorithms(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "active")
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()
	port := u.Port()

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "server.pem")
	certOut, err := os.Create(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}); err != nil {
		t.Fatal(err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatal(err)
	}

	// The server's cert signature algorithm is not in the denied set, so the
	// test should pass.
	specs := []testwebapp.TLSSpec{
		{
			Host:                          host,
			Port:                          port,
			CustomCAPEM:                   caFile,
			NotAllowedSignatureAlgorithms: webapp.SignatureAlgorithms{x509.ECDSAWithSHA256},
		},
	}
	tlsTest := testwebapp.NewTLSTest(specs...)
	if err := tlsTest.Run(ctx); err != nil {
		t.Fatalf("TLSTest.Run failed: %v", err)
	}

	// The server's cert signature algorithm is in the denied set, so the
	// test should fail.
	specs[0].NotAllowedSignatureAlgorithms = webapp.SignatureAlgorithms{x509.SHA256WithRSA}
	tlsTest = testwebapp.NewTLSTest(specs...)
	err = tlsTest.Run(ctx)
	if err == nil {
		t.Fatal("TLSTest.Run expected failure for denied signature algorithm")
	}
	if !strings.Contains(err.Error(), "is one of the denied algorithms") {
		t.Errorf("expected error to contain %q, but got %q", "is one of the denied algorithms", err.Error())
	}
}

func TestCipherSuitesYAML(t *testing.T) {
	// TLS_RSA_WITH_AES_128_CBC_SHA is one of the "insecure" ciphersuites
	// returned by tls.InsecureCipherSuites rather than tls.CipherSuites; it
	// must round-trip just like the secure ones.
	var spec testwebapp.TLSSpec
	in := "cipher-suites: [TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_CBC_SHA]"
	if err := yaml.Unmarshal([]byte(in), &spec); err != nil {
		t.Fatal(err)
	}
	c := spec.CipherSuites
	want := webapp.CipherSuites{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}
	if len(c) != len(want) {
		t.Fatalf("got %v, want %v", c, want)
	}
	for i := range c {
		if c[i] != want[i] {
			t.Errorf("got %v, want %v", c, want)
		}
	}

	if err := yaml.Unmarshal([]byte("cipher-suites: [not-a-real-ciphersuite]"), &spec); err == nil {
		t.Error("expected an error for an unknown ciphersuite name")
	}

	out, err := yaml.Marshal(testwebapp.TLSSpec{CipherSuites: want})
	if err != nil {
		t.Fatal(err)
	}
	for _, wantSubstr := range []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA"} {
		if got := string(out); !strings.Contains(got, wantSubstr) {
			t.Errorf("marshaled output %q does not contain %q", got, wantSubstr)
		}
	}
}

func TestCipherSuitesYAMLInsecureKeyword(t *testing.T) {
	var spec testwebapp.TLSSpec
	if err := yaml.Unmarshal([]byte("cipher-suites: [insecure]"), &spec); err != nil {
		t.Fatal(err)
	}
	c := spec.CipherSuites

	want := make(webapp.CipherSuites, 0, len(tls.InsecureCipherSuites()))
	for _, cs := range tls.InsecureCipherSuites() {
		want = append(want, cs.ID)
	}
	if len(c) != len(want) {
		t.Fatalf("got %v suites, want %v suites: got %v, want %v", len(c), len(want), c, want)
	}
	for i := range c {
		if c[i] != want[i] {
			t.Errorf("got %v, want %v", c, want)
		}
	}

	// 'insecure' can be mixed with explicitly named suites.
	if err := yaml.Unmarshal([]byte("cipher-suites: [insecure, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]"), &spec); err != nil {
		t.Fatal(err)
	}
	c = spec.CipherSuites
	if got, want := len(c), len(want)+1; got != want {
		t.Fatalf("got %v suites, want %v suites: %v", got, want, c)
	}
	if got, want := c[len(c)-1], tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestTLSTestInsecureCipherSuiteName verifies that TLSSpec.NotAllowedCipherSuites
// accepts the name of an "insecure" ciphersuite (one of tls.InsecureCipherSuites
// rather than tls.CipherSuites) and wires it through to the validator. The
// httptest server below negotiates a modern/secure ciphersuite, so this does
// not exercise an actual handshake using the insecure ciphersuite, but it does
// confirm that the insecure name parses and that validation still passes when
// the (insecure) denied ciphersuite is never negotiated.
func TestTLSTestInsecureCipherSuiteName(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "active")
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()
	port := u.Port()

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "server.pem")
	certOut, err := os.Create(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}); err != nil {
		t.Fatal(err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatal(err)
	}

	var spec testwebapp.TLSSpec
	if err := yaml.Unmarshal(fmt.Appendf(nil, `
host: %s
port: %s
custom-ca-pem: %s
not-allowed-cipher-suites: [TLS_RSA_WITH_AES_128_CBC_SHA]
`, host, port, caFile), &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.NotAllowedCipherSuites) != 1 || spec.NotAllowedCipherSuites[0] != tls.TLS_RSA_WITH_AES_128_CBC_SHA {
		t.Fatalf("test setup: NotAllowedCipherSuites = %v", spec.NotAllowedCipherSuites)
	}

	tlsTest := testwebapp.NewTLSTest(spec)
	if err := tlsTest.Run(ctx); err != nil {
		t.Fatalf("TLSTest.Run failed: %v", err)
	}
}

func TestSignatureAlgorithmsYAML(t *testing.T) {
	var spec testwebapp.TLSSpec
	in := "signature-algorithms: [SHA256-RSA, ECDSA-SHA256]"
	if err := yaml.Unmarshal([]byte(in), &spec); err != nil {
		t.Fatal(err)
	}
	s := spec.SignatureAlgorithms
	want := webapp.SignatureAlgorithms{x509.SHA256WithRSA, x509.ECDSAWithSHA256}
	if len(s) != len(want) {
		t.Fatalf("got %v, want %v", s, want)
	}
	for i := range s {
		if s[i] != want[i] {
			t.Errorf("got %v, want %v", s, want)
		}
	}

	if err := yaml.Unmarshal([]byte("signature-algorithms: [not-a-real-algorithm]"), &spec); err == nil {
		t.Error("expected an error for an unknown signature algorithm name")
	}

	out, err := yaml.Marshal(testwebapp.TLSSpec{SignatureAlgorithms: want})
	if err != nil {
		t.Fatal(err)
	}
	if got, wantSubstr := string(out), "SHA256-RSA"; !strings.Contains(got, wantSubstr) {
		t.Errorf("marshaled output %q does not contain %q", got, wantSubstr)
	}
}

func TestSignatureAlgorithmsYAMLShortNames(t *testing.T) {
	testCases := []struct {
		name string
		want webapp.SignatureAlgorithms
	}{
		{
			name: "rsa",
			want: webapp.SignatureAlgorithms{x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA},
		},
		{
			name: "dsa",
			want: webapp.SignatureAlgorithms{x509.DSAWithSHA1, x509.DSAWithSHA256},
		},
		{
			name: "ecdsa",
			want: webapp.SignatureAlgorithms{x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512},
		},
		{
			name: "ed25519",
			want: webapp.SignatureAlgorithms{x509.PureEd25519},
		},
		{
			name: "rsa-pss",
			want: webapp.SignatureAlgorithms{x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var spec testwebapp.TLSSpec
			if err := yaml.Unmarshal(fmt.Appendf(nil, "signature-algorithms: [%s]", tc.name), &spec); err != nil {
				t.Fatal(err)
			}
			s := spec.SignatureAlgorithms
			if len(s) != len(tc.want) {
				t.Fatalf("got %v, want %v", s, tc.want)
			}
			for i := range s {
				if s[i] != tc.want[i] {
					t.Errorf("got %v, want %v", s, tc.want)
				}
			}
		})
	}

	// Shortnames can be mixed with explicitly named algorithms.
	var spec testwebapp.TLSSpec
	if err := yaml.Unmarshal([]byte("signature-algorithms: [ed25519, SHA256-RSA]"), &spec); err != nil {
		t.Fatal(err)
	}
	s := spec.SignatureAlgorithms
	want := webapp.SignatureAlgorithms{x509.PureEd25519, x509.SHA256WithRSA}
	if len(s) != len(want) {
		t.Fatalf("got %v, want %v", s, want)
	}
	for i := range s {
		if s[i] != want[i] {
			t.Errorf("got %v, want %v", s, want)
		}
	}
}
