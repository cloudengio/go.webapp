package testwebapp_test

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"cloudeng.io/webapp/testwebapp"
)

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
