// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloudeng.io/webapp/devtest"
	"cloudeng.io/webapp/testwebapp"
)

func tlsTestServer(t *testing.T) (srvURL string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := devtest.NewSelfSignedCert(certFile, keyFile, devtest.CertPrivateKey(key)); err != nil {
		t.Fatalf("create cert: %v", err)
	}
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("decode cert PEM: no block found")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1 id="title">Secure Page</h1></body></html>`)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, x509Cert
}

func TestWithSuppressedCertErrorsFor(t *testing.T) {
	srvURL, cert := tlsTestServer(t)

	t.Run("NavigationSucceeds", func(t *testing.T) {
		ct := testwebapp.NewNavigationTest(
			[]testwebapp.NavigationSpec{
				{URL: srvURL, Selectors: []string{"#title"}},
			},
			testwebapp.WithSuppressedCertErrorsFor(cert),
		)
		if err := ct.Run(t.Context()); err != nil {
			t.Fatalf("expected success with suppressed cert errors, got: %v", err)
		}
	})

	t.Run("NavigationFailsWithoutSuppressedCertErrors", func(t *testing.T) {
		ct := testwebapp.NewNavigationTest(
			[]testwebapp.NavigationSpec{
				{URL: srvURL, Selectors: []string{"#title"}},
			},
			testwebapp.WithElementTimeout(3*time.Second),
		)
		err := ct.Run(t.Context())
		if err == nil {
			t.Fatal("expected failure without suppressed cert errors")
		}
		if !errors.Is(err, testwebapp.ErrNavigateUnexpectedError) {
			t.Errorf("expected ErrNavigateElementNotFound, got: %v", err)
		}
	})
}

func TestClick(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<html>
				<body>
					<button id="btn1">Button 1</button>
					<div id="result"></div>
					<script>
						document.getElementById('btn1').addEventListener('click', () => {
							const btn2 = document.createElement('button');
							btn2.id = 'btn2';
							btn2.textContent = 'Button 2';
							btn2.addEventListener('click', () => {
								document.getElementById('result').textContent = 'success';
							});
							document.body.appendChild(btn2);
						});
					</script>
				</body>
			</html>
		`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Run("SuccessSequentialClick", func(t *testing.T) {
		ct := testwebapp.NewNavigationTest([]testwebapp.NavigationSpec{
			{
				URL:       srv.URL,
				Selectors: []string{"#btn1", "#btn2"},
				Action:    testwebapp.SelectorActionClick,
			},
		})
		if err := ct.Run(t.Context()); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})

	t.Run("FailureElementNotFound", func(t *testing.T) {
		ct := testwebapp.NewNavigationTest([]testwebapp.NavigationSpec{
			{
				URL:       srv.URL,
				Selectors: []string{"#btn1", "#nonexistent"},
				Action:    testwebapp.SelectorActionClick,
			},
		}, testwebapp.WithElementTimeout(2*time.Second))
		err := ct.Run(t.Context())
		if err == nil {
			t.Fatal("expected failure, got nil")
		}
		if !errors.Is(err, testwebapp.ErrNavigateElementNotFound) {
			t.Errorf("expected ErrNavigateElementNotFound, got %v", err)
		}
	})
}
