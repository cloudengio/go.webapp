// Copyright 2021 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package tlsvalidate_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"cloudeng.io/webapp/tlsvalidate"
)

func newCert(t *testing.T, name string, isCA bool, san []string, ipSANs []net.IP, signer *x509.Certificate, signerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
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
		DNSNames:              san,
		IPAddresses:           ipSANs,
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

func startTLSServer(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey, addr string) (string, func()) {
	t.Helper()
	serverCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}
	//nolint:gosec // G402 we want to test min version handling
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = srv.ServeTLS(ln, "", "")
	}()
	return ln.Addr().String(), func() {
		srv.Shutdown(context.Background()) //nolint:errcheck
	}
}

// startTLSServerDefaultVersion starts a TLS server that does not restrict the
// TLS version, allowing it to negotiate TLS 1.3 (and hence a different
// negotiated cipher suite than a server forced to use TLS 1.2, see
// startTLSServer).
func startTLSServerDefaultVersion(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey, addr string) (string, func()) {
	t.Helper()
	serverCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = srv.ServeTLS(ln, "", "")
	}()
	return ln.Addr().String(), func() {
		srv.Shutdown(context.Background()) //nolint:errcheck
	}
}

func newECDSACert(t *testing.T, name string, isCA bool, san []string, ipSANs []net.IP, signer *x509.Certificate, signerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              san,
		IPAddresses:           ipSANs,
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	var parent *x509.Certificate
	var parentKey *ecdsa.PrivateKey
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

func startECDSATLSServer(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey, addr string) (string, func()) {
	t.Helper()
	serverCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}
	//nolint:gosec // G402 we want to test signature algorithm handling
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = srv.ServeTLS(ln, "", "")
	}()
	return ln.Addr().String(), func() {
		srv.Shutdown(context.Background()) //nolint:errcheck
	}
}

func TestValidator(t *testing.T) {
	ctx := context.Background()

	// 1. Create certs
	rootCert, rootKey := newCert(t, "root.com", true, nil, nil, nil, nil)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	leafCert, leafKey := newCert(t, "leaf.com", false, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, rootCert, rootKey)

	// 2. Start a server
	addr, cleanup := startTLSServer(t, leafCert, leafKey, "127.0.0.1:0")
	defer cleanup()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	_, cleanup6 := startTLSServer(t, leafCert, leafKey, net.JoinHostPort("::1", port))
	defer cleanup6()

	testCases := []struct {
		name     string
		opts     []tlsvalidate.Option
		host     string
		port     string
		errorMsg string
	}{
		{
			name: "valid cert",
			opts: []tlsvalidate.Option{
				tlsvalidate.WithRootCAs(rootPool),
			},
			host: host,
			port: port,
		},
		{
			name: "valid cert with SAN",
			opts: []tlsvalidate.Option{
				tlsvalidate.WithRootCAs(rootPool),
			},
			host: "localhost",
			port: port,
		},
		{
			name: "wrong root CAs",
			opts: []tlsvalidate.Option{
				tlsvalidate.WithRootCAs(x509.NewCertPool()),
			},
			host:     host,
			port:     port,
			errorMsg: "certificate signed by unknown authority",
		},
		{
			name: "valid for not met",
			opts: []tlsvalidate.Option{
				tlsvalidate.WithRootCAs(rootPool),
				tlsvalidate.WithValidForAtLeast(2 * time.Hour),
			},
			host:     host,
			port:     port,
			errorMsg: "is less than the required",
		},
		{
			name: "issuer regex match",
			opts: []tlsvalidate.Option{
				tlsvalidate.WithRootCAs(rootPool),
				tlsvalidate.WithIssuerRegexps(regexp.MustCompile("CN=root.com")),
			},
			host: host,
			port: port,
		},
		{
			name: "issuer regex no match",
			opts: []tlsvalidate.Option{
				tlsvalidate.WithRootCAs(rootPool),
				tlsvalidate.WithIssuerRegexps(regexp.MustCompile("CN=wrong.com")),
			},
			host:     host,
			port:     port,
			errorMsg: "does not match any of the specified patterns",
		},
		{
			name: "min tls version met",
			opts: []tlsvalidate.Option{
				tlsvalidate.WithRootCAs(rootPool),
				tlsvalidate.WithTLSMinVersion(tls.VersionTLS12),
			},
			host: host,
			port: port,
		},
		{
			name: "min tls version not met",
			opts: []tlsvalidate.Option{
				tlsvalidate.WithRootCAs(rootPool),
				tlsvalidate.WithTLSMinVersion(tls.VersionTLS13),
			},
			host:     host,
			port:     port,
			errorMsg: "tls: protocol version not supported", // This comes from the handshake
		},
		{
			name: "expand dns",
			opts: []tlsvalidate.Option{
				tlsvalidate.WithRootCAs(rootPool),
				tlsvalidate.WithExpandDNSNames(true),
			},
			host: "localhost",
			port: port,
		},
		{
			name: "ipv4 only",
			opts: []tlsvalidate.Option{
				tlsvalidate.WithRootCAs(rootPool),
				tlsvalidate.WithExpandDNSNames(true),
				tlsvalidate.WithIPv4Only(true),
			},
			host: "localhost",
			port: port,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := tlsvalidate.NewValidator(tc.opts...)
			err := validator.Validate(ctx, tc.host, tc.port)
			if len(tc.errorMsg) > 0 {
				if err == nil {
					t.Fatalf("expected an error but got none")
				}
				if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("expected error to contain %q, but got %q", tc.errorMsg, err.Error())
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestErrValidator(t *testing.T) {
	ctx := context.Background()

	rootCert, rootKey := newCert(t, "root.com", true, nil, nil, nil, nil)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	leafCert, leafKey := newCert(t, "leaf.com", false, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, rootCert, rootKey)

	addr, cleanup := startTLSServer(t, leafCert, leafKey, "127.0.0.1:0")
	defer cleanup()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	validator := tlsvalidate.NewValidator(
		tlsvalidate.WithRootCAs(rootPool),
		tlsvalidate.WithIssuerRegexps(regexp.MustCompile("CN=wrong.com")),
	)
	err = validator.Validate(ctx, host, port)
	if err == nil {
		t.Fatal("expected an error but got none")
	}

	errValidator, ok := errors.AsType[*tlsvalidate.ErrValidator](err)
	if !ok {
		t.Fatalf("expected error to be (or wrap) a tlsvalidate.ErrValidator, got %T: %v", err, err)
	}
	if errValidator.Certificate == nil {
		t.Fatal("expected ErrValidator.Certificate to be set")
	}
	if got, want := errValidator.Certificate.SerialNumber, leafCert.SerialNumber; got.Cmp(want) != 0 {
		t.Errorf("ErrValidator.Certificate.SerialNumber = %v, want %v", got, want)
	}
	if errValidator.Err == nil {
		t.Fatal("expected ErrValidator.Err to be set")
	}
	if !strings.Contains(errValidator.Error(), "does not match any of the specified patterns") {
		t.Errorf("ErrValidator.Error() = %q, want it to contain %q", errValidator.Error(), "does not match any of the specified patterns")
	}
}

func TestCheckSerialNumbers(t *testing.T) {
	ctx := context.Background()

	// Serve different serial numbers for the same host using ipv4 and ipv6 addresses to expand
	// localhost to two different IPs.

	// Cert 1
	rootCert1, rootKey1 := newCert(t, "root1.com", true, nil, nil, nil, nil)
	leafCert1, leafKey1 := newCert(t, "leaf.com", false, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, rootCert1, rootKey1)
	addr1, cleanup1 := startTLSServer(t, leafCert1, leafKey1, "127.0.0.1:0")
	defer cleanup1()
	_, port1, _ := net.SplitHostPort(addr1)

	// Cert 2 (different serial)
	time.Sleep(time.Second)
	rootCert2, rootKey2 := newCert(t, "root2.com", true, nil, nil, nil, nil)
	leafCert2, leafKey2 := newCert(t, "leaf.com", false, []string{"localhost"}, []net.IP{net.ParseIP("::1")}, rootCert2, rootKey2)
	_, cleanup2 := startTLSServer(t, leafCert2, leafKey2, net.JoinHostPort("::1", port1))
	defer cleanup2()

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert1)
	rootPool.AddCert(rootCert2)

	// This test is tricky because we need two servers with different certs for the same host.
	// We'll simulate this by validating 'localhost' which resolves to 127.0.0.1, but we'll
	// point to two different ports. This isn't a perfect test of the multi-IP case, but
	// it tests the serial number comparison logic.

	// First, validate against one server, should be fine.
	validator := tlsvalidate.NewValidator(
		tlsvalidate.WithRootCAs(rootPool),
		tlsvalidate.WithExpandDNSNames(true),
		tlsvalidate.WithCheckSerialNumbers(true),
	)
	err := validator.Validate(ctx, "localhost", port1)
	if err == nil {
		t.Fatalf("expected serial number check to fail on first server, but it passed")
	}
	if !strings.Contains(err.Error(), "mismatched serial numbers") {
		t.Errorf("expected mismatched serial numbers error, but got: %v", err)
	}

}

func TestCheckSignatureAlgorithm(t *testing.T) {
	ctx := context.Background()

	// Use an ECDSA root/leaf (sha256WithECDSA) and an RSA root/leaf
	// (sha256WithRSA) so that the two servers present certificates signed
	// with different signature algorithms despite covering the same host.
	rootCert1, rootKey1 := newCert(t, "root1.com", true, nil, nil, nil, nil)
	leafCert1, leafKey1 := newCert(t, "leaf.com", false, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, rootCert1, rootKey1)
	addr1, cleanup1 := startTLSServer(t, leafCert1, leafKey1, "127.0.0.1:0")
	defer cleanup1()
	_, port1, _ := net.SplitHostPort(addr1)

	rootCert2, rootKey2 := newECDSACert(t, "root2.com", true, nil, nil, nil, nil)
	leafCert2, leafKey2 := newECDSACert(t, "leaf.com", false, []string{"localhost"}, []net.IP{net.ParseIP("::1")}, rootCert2, rootKey2)
	_, cleanup2 := startECDSATLSServer(t, leafCert2, leafKey2, net.JoinHostPort("::1", port1))
	defer cleanup2()

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert1)
	rootPool.AddCert(rootCert2)

	validator := tlsvalidate.NewValidator(
		tlsvalidate.WithRootCAs(rootPool),
		tlsvalidate.WithExpandDNSNames(true),
		tlsvalidate.WithCheckSignatureAlgorithm(true),
	)
	err := validator.Validate(ctx, "localhost", port1)
	if err == nil {
		t.Fatalf("expected signature algorithm check to fail, but it passed")
	}
	if !strings.Contains(err.Error(), "mismatched signature algorithms") {
		t.Errorf("expected mismatched signature algorithms error, but got: %v", err)
	}
}

func TestAllowedSignatureAlgorithms(t *testing.T) {
	ctx := context.Background()

	rootCert, rootKey := newCert(t, "root.com", true, nil, nil, nil, nil)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	leafCert, leafKey := newCert(t, "leaf.com", false, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, rootCert, rootKey)
	addr, cleanup := startTLSServer(t, leafCert, leafKey, "127.0.0.1:0")
	defer cleanup()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := leafCert.SignatureAlgorithm, x509.SHA256WithRSA; got != want {
		t.Fatalf("test setup: expected leaf cert signature algorithm %v, got %v", want, got)
	}

	testCases := []struct {
		name     string
		algs     []x509.SignatureAlgorithm
		errorMsg string
	}{
		{
			name: "allowed algorithm present",
			algs: []x509.SignatureAlgorithm{x509.SHA384WithRSA, x509.SHA256WithRSA},
		},
		{
			name:     "allowed algorithm absent",
			algs:     []x509.SignatureAlgorithm{x509.ECDSAWithSHA256, x509.SHA384WithRSA},
			errorMsg: "is not one of the allowed algorithms",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := tlsvalidate.NewValidator(
				tlsvalidate.WithRootCAs(rootPool),
				tlsvalidate.WithAllowedSignatureAlgorithms(tc.algs...),
			)
			err := validator.Validate(ctx, host, port)
			if len(tc.errorMsg) > 0 {
				if err == nil {
					t.Fatalf("expected an error but got none")
				}
				if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("expected error to contain %q, but got %q", tc.errorMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDeniedSignatureAlgorithms(t *testing.T) {
	ctx := context.Background()

	rootCert, rootKey := newCert(t, "root.com", true, nil, nil, nil, nil)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	leafCert, leafKey := newCert(t, "leaf.com", false, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, rootCert, rootKey)
	addr, cleanup := startTLSServer(t, leafCert, leafKey, "127.0.0.1:0")
	defer cleanup()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name     string
		algs     []x509.SignatureAlgorithm
		errorMsg string
	}{
		{
			name: "denied algorithm absent",
			algs: []x509.SignatureAlgorithm{x509.ECDSAWithSHA256},
		},
		{
			name:     "denied algorithm present",
			algs:     []x509.SignatureAlgorithm{x509.ECDSAWithSHA256, x509.SHA256WithRSA},
			errorMsg: "is one of the denied algorithms",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := tlsvalidate.NewValidator(
				tlsvalidate.WithRootCAs(rootPool),
				tlsvalidate.WithDeniedSignatureAlgorithms(tc.algs...),
			)
			err := validator.Validate(ctx, host, port)
			if len(tc.errorMsg) > 0 {
				if err == nil {
					t.Fatalf("expected an error but got none")
				}
				if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("expected error to contain %q, but got %q", tc.errorMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDeniedCipherSuites(t *testing.T) {
	ctx := context.Background()

	rootCert, rootKey := newCert(t, "root.com", true, nil, nil, nil, nil)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	leafCert, leafKey := newCert(t, "leaf.com", false, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, rootCert, rootKey)
	addr, cleanup := startTLSServer(t, leafCert, leafKey, "127.0.0.1:0")
	defer cleanup()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name     string
		suites   []uint16
		errorMsg string
	}{
		{
			name:   "denied ciphersuite absent",
			suites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
		{
			name:     "denied ciphersuite present",
			suites:   []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			errorMsg: "is one of the denied ciphersuites",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := tlsvalidate.NewValidator(
				tlsvalidate.WithRootCAs(rootPool),
				tlsvalidate.WithCiphersuites([]uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}),
				tlsvalidate.WithDeniedCipherSuites(tc.suites...),
			)
			err := validator.Validate(ctx, host, port)
			if len(tc.errorMsg) > 0 {
				if err == nil {
					t.Fatalf("expected an error but got none")
				}
				if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("expected error to contain %q, but got %q", tc.errorMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseCipherSuite(t *testing.T) {
	id, err := tlsvalidate.ParseCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := id, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	// Insecure ciphersuites are also recognized.
	id, err = tlsvalidate.ParseCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := id, tls.TLS_RSA_WITH_AES_128_CBC_SHA; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	if _, err := tlsvalidate.ParseCipherSuite("not-a-real-ciphersuite"); err == nil {
		t.Error("expected an error for an unknown ciphersuite name")
	}
}

func TestParseSignatureAlgorithm(t *testing.T) {
	alg, err := tlsvalidate.ParseSignatureAlgorithm("SHA256-RSA")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := alg, x509.SHA256WithRSA; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	alg, err = tlsvalidate.ParseSignatureAlgorithm("Ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := alg, x509.PureEd25519; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	if _, err := tlsvalidate.ParseSignatureAlgorithm("not-a-real-algorithm"); err == nil {
		t.Error("expected an error for an unknown signature algorithm name")
	}
}

func TestCheckCipherSuites(t *testing.T) {
	ctx := context.Background()

	rootCert, rootKey := newCert(t, "root.com", true, nil, nil, nil, nil)
	leafCert, leafKey := newCert(t, "leaf.com", false, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, rootCert, rootKey)

	// startTLSServer forces TLS 1.2, so it negotiates a TLS 1.2 cipher suite
	// (e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256). startTLSServerDefaultVersion
	// does not restrict the version, so it negotiates a TLS 1.3 cipher suite
	// (e.g. TLS_AES_128_GCM_SHA256) instead, giving us two addresses for the
	// same host with genuinely different negotiated cipher suites.
	addr1, cleanup1 := startTLSServer(t, leafCert, leafKey, "127.0.0.1:0")
	defer cleanup1()
	_, port1, _ := net.SplitHostPort(addr1)

	_, cleanup2 := startTLSServerDefaultVersion(t, leafCert, leafKey, net.JoinHostPort("::1", port1))
	defer cleanup2()

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	validator := tlsvalidate.NewValidator(
		tlsvalidate.WithRootCAs(rootPool),
		tlsvalidate.WithExpandDNSNames(true),
		tlsvalidate.WithCheckCipherSuites(true),
	)
	err := validator.Validate(ctx, "localhost", port1)
	if err == nil {
		t.Fatalf("expected cipher suite check to fail, but it passed")
	}
	if !strings.Contains(err.Error(), "mismatched cipher suites") {
		t.Errorf("expected mismatched cipher suites error, but got: %v", err)
	}
}
