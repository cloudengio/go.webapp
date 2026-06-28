// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cloudeng.io/net/http/httptracing"
	"cloudeng.io/webapp"
	"cloudeng.io/webapp/webauth/acme"
)

func noCertError() string {
	switch runtime.GOOS {
	case "windows":
		return "x509: certificate signed by unknown authority"
	case "darwin":
		return "failed to verify certificate: x509: “localhost” certificate is not trusted"
	case "linux":
		return "x509: certificate signed by unknown authority"
	default:
		return "failed to verify certificate: x509: certificate signed by unknown authority"
	}
}

func newCert(t *testing.T, name string, isCA bool, signer *x509.Certificate, signerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	var parent *x509.Certificate
	var parentKey *rsa.PrivateKey
	if signer == nil {
		parent = template
		parentKey = privKey
	} else {
		parent = signer
		parentKey = signerKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &privKey.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	return cert, privKey
}

func TestNewHTTPClient(t *testing.T) {
	ctx := context.Background()
	t.Run("default", func(t *testing.T) { testNewHTTPClientDefault(ctx, t) })
	t.Run("with-custom-ca", func(t *testing.T) { testNewHTTPClientWithCustomCA(ctx, t) })
	t.Run("with-dns-resolver-addr", func(t *testing.T) { testNewHTTPClientWithDNSServer(ctx, t) })
	t.Run("with-tracing", func(t *testing.T) { testNewHTTPClientWithTracing(ctx, t) })
	t.Run("client-hello-supports-ecdsa", func(t *testing.T) { testNewHTTPClientHelloSupportsECDSA(ctx, t) })
}

func testNewHTTPClientDefault(ctx context.Context, t *testing.T) {
	client, err := webapp.NewHTTPClient(ctx)
	if err != nil {
		t.Fatalf("NewHTTPClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected a client, got nil")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected a default http.Transport, got %T", client.Transport)
	}
	if transport.TLSClientConfig.RootCAs != nil {
		t.Error("expected default RootCAs to be nil")
	}
}

func testNewHTTPClientWithCustomCA(ctx context.Context, t *testing.T) {
	// 1. Create a root CA and a server cert signed by it.
	rootCert, rootKey := newCert(t, "test-ca", true, nil, nil)
	serverCert, serverKey := newCert(t, "localhost", false, rootCert, rootKey)

	// 2. Start a TLS server with the server cert.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
		}},
	}
	server.StartTLS()
	defer server.Close()

	// 3. Write the root CA to a temp file.
	tmpDir := t.TempDir()
	caPemFile := filepath.Join(tmpDir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	if err := os.WriteFile(caPemFile, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}

	// 4. Create a client with the custom CA and make a request.
	client, err := webapp.NewHTTPClient(ctx, webapp.WithCustomCAPEMFile(caPemFile))
	if err != nil {
		t.Fatalf("NewHTTPClient with custom CA failed: %v", err)
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request with custom CA failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}

	// 5. Create a default client and ensure the request fails.
	defaultClient := &http.Client{}
	_, err = defaultClient.Get(server.URL)
	if err == nil {
		t.Fatal("expected request with default client to fail")
	}
	expected := noCertError()
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("expected %q, got: %v", expected, err)
	}
}

func testNewHTTPClientWithDNSServer(ctx context.Context, t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake DNS server: %v", err)
	}
	defer pc.Close()

	received := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 512)
		if _, _, err := pc.ReadFrom(buf); err == nil {
			received <- struct{}{}
		}
	}()

	client, err := webapp.NewHTTPClient(ctx, webapp.WithDNSServer(pc.LocalAddr().String()))
	if err != nil {
		t.Fatalf("NewHTTPClient with custom DNS resolver failed: %v", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://this-host-does-not-exist.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected request to fail since the fake DNS server never replies")
	}

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a DNS query to be sent to the custom resolver address")
	}
}

// testNewHTTPClientHelloSupportsECDSA is a regression test for a bug where
// NewHTTPClient's transport forced MinVersion to TLS 1.3, which causes Go's
// TLS client to omit the configured CipherSuites from the wire ClientHello
// entirely (TLS 1.3 ignores that field and only ever offers its fixed AEAD
// suite list). That, in turn, made acme.SupportsECDSA(hello) - which looks
// for legacy TLS_ECDHE_ECDSA_* suite IDs in hello.CipherSuites - report that
// the client did not support ECDSA certificates, even though it does.
func testNewHTTPClientHelloSupportsECDSA(ctx context.Context, t *testing.T) {
	rootCert, rootKey := newCert(t, "test-ca", true, nil, nil)
	serverCert, serverKey := newCert(t, "localhost", false, rootCert, rootKey)

	var capturedHello *tls.ClientHelloInfo
	var capturedVersion uint16
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedVersion = r.TLS.Version
		w.WriteHeader(http.StatusOK)
	}))
	// Set Certificates explicitly (rather than relying on GetCertificate) so
	// that httptest.Server.StartTLS does not inject its own default cert
	// (it only does so when Certificates is empty, regardless of
	// GetCertificate), and use GetConfigForClient - which fires for every
	// connection irrespective of how the certificate is selected - to
	// capture the ClientHelloInfo.
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
		}},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			capturedHello = hello
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	client, err := webapp.NewHTTPClient(ctx, webapp.WithCustomCAPool(rootPool))
	if err != nil {
		t.Fatalf("NewHTTPClient failed: %v", err)
	}

	// Use "localhost" rather than the server's 127.0.0.1 URL so that the
	// client sends an SNI ServerName (Go's TLS client omits SNI for IP
	// literals), matching real-world usage against a named host.
	resp, err := client.Get("https://localhost:" + port)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if capturedHello == nil {
		t.Fatal("server did not observe a ClientHelloInfo")
	}
	if !acme.SupportsECDSA(capturedHello) {
		t.Errorf("acme.SupportsECDSA(hello) = false, want true; CipherSuites: %v", capturedHello.CipherSuites)
	}
	if capturedVersion != tls.VersionTLS13 {
		t.Errorf("negotiated TLS version = %#x, want TLS 1.3 (%#x)", capturedVersion, tls.VersionTLS13)
	}
}

func testNewHTTPClientWithTracing(ctx context.Context, t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	client, err := webapp.NewHTTPClient(ctx, webapp.WithTracingTransport(
		httptracing.WithTraceLogger(logger),
	))
	if err != nil {
		t.Fatalf("NewHTTPClient with tracing failed: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request with tracing client failed: %v", err)
	}
	resp.Body.Close()

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, `"method":"GET`) {
		t.Errorf("log output does not contain request trace: %s", logOutput)
	}
}
