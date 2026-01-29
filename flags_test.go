package webapp_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cloudeng.io/webapp"
	"cloudeng.io/webapp/devtest"
)

type mockFS struct {
	root string
}

func (m *mockFS) ReadFileCtx(ctx context.Context, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(m.root, name))
}

func (m *mockFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(m.root, name))
}

func TestTLSConfigUsingCertFilesFS(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	err := devtest.NewSelfSignedCert(certFile, keyFile, devtest.CertDNSHosts("localhost"))
	if err != nil {
		t.Fatalf("failed to create self signed cert: %v", err)
	}

	fs := &mockFS{root: tmpDir}

	// Test success using filenames relative to the mockFS root
	cfg, err := webapp.TLSConfigUsingCertFilesFS(ctx, fs, "cert.pem", "key.pem")
	if err != nil {
		t.Fatalf("TLSConfigUsingCertFilesFS failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("got %d certificates, want 1", len(cfg.Certificates))
	}

	// Test missing files
	_, err = webapp.TLSConfigUsingCertFilesFS(ctx, fs, "missing.pem", "key.pem")
	if err == nil {
		t.Error("expected error for missing cert file")
	}

	// Test invalid args
	_, err = webapp.TLSConfigUsingCertFilesFS(ctx, fs, "", "key.pem")
	if err == nil {
		t.Error("expected error for empty cert file arg")
	}
}

func TestTLSConfigUsingCertFiles(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	err := devtest.NewSelfSignedCert(certFile, keyFile, devtest.CertDNSHosts("localhost"))
	if err != nil {
		t.Fatalf("failed to create self signed cert: %v", err)
	}

	// Test success
	cfg, err := webapp.TLSConfigUsingCertFiles(certFile, keyFile)
	if err != nil {
		t.Fatalf("TLSConfigUsingCertFiles failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("got %d certificates, want 1", len(cfg.Certificates))
	}

	// Test missing files
	_, err = webapp.TLSConfigUsingCertFiles("missing.pem", keyFile)
	if err == nil {
		t.Error("expected error for missing cert file")
	}

	// Test invalid args
	_, err = webapp.TLSConfigUsingCertFiles("", keyFile)
	if err == nil {
		t.Error("expected error for empty cert file arg")
	}
}
