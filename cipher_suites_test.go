// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"

	"cloudeng.io/webapp"
	"gopkg.in/yaml.v3"
)

func TestParseCipherSuite(t *testing.T) {
	id, err := webapp.ParseCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := id, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	// Insecure ciphersuites are also recognized.
	id, err = webapp.ParseCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := id, tls.TLS_RSA_WITH_AES_128_CBC_SHA; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	if _, err := webapp.ParseCipherSuite("not-a-real-ciphersuite"); err == nil {
		t.Error("expected an error for an unknown ciphersuite name")
	}
}

func TestParseSignatureAlgorithm(t *testing.T) {
	alg, err := webapp.ParseSignatureAlgorithm("SHA256-RSA")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := alg, x509.SHA256WithRSA; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	alg, err = webapp.ParseSignatureAlgorithm("Ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := alg, x509.PureEd25519; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	if _, err := webapp.ParseSignatureAlgorithm("not-a-real-algorithm"); err == nil {
		t.Error("expected an error for an unknown signature algorithm name")
	}
}

func TestCipherSuitesString(t *testing.T) {
	c := webapp.CipherSuites{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	want := "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	if got := c.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := (webapp.CipherSuites{}).String(), ""; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSignatureAlgorithmsString(t *testing.T) {
	s := webapp.SignatureAlgorithms{x509.SHA256WithRSA, x509.PureEd25519}
	want := "SHA256-RSA,Ed25519"
	if got := s.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := (webapp.SignatureAlgorithms{}).String(), ""; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCipherSuitesYAML(t *testing.T) {
	// TLS_RSA_WITH_AES_128_CBC_SHA is one of the "insecure" ciphersuites
	// returned by tls.InsecureCipherSuites rather than tls.CipherSuites; it
	// must round-trip just like the secure ones.
	var c webapp.CipherSuites
	in := "[TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_CBC_SHA]"
	if err := yaml.Unmarshal([]byte(in), &c); err != nil {
		t.Fatal(err)
	}
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

	if err := yaml.Unmarshal([]byte("[not-a-real-ciphersuite]"), &c); err == nil {
		t.Error("expected an error for an unknown ciphersuite name")
	}

	out, err := yaml.Marshal(want)
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
	var c webapp.CipherSuites
	if err := yaml.Unmarshal([]byte("[insecure]"), &c); err != nil {
		t.Fatal(err)
	}

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
	if err := yaml.Unmarshal([]byte("[insecure, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]"), &c); err != nil {
		t.Fatal(err)
	}
	if got, want := len(c), len(want)+1; got != want {
		t.Fatalf("got %v suites, want %v suites: %v", got, want, c)
	}
	if got, want := c[len(c)-1], tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSignatureAlgorithmsYAML(t *testing.T) {
	var s webapp.SignatureAlgorithms
	in := "[SHA256-RSA, ECDSA-SHA256]"
	if err := yaml.Unmarshal([]byte(in), &s); err != nil {
		t.Fatal(err)
	}
	want := webapp.SignatureAlgorithms{x509.SHA256WithRSA, x509.ECDSAWithSHA256}
	if len(s) != len(want) {
		t.Fatalf("got %v, want %v", s, want)
	}
	for i := range s {
		if s[i] != want[i] {
			t.Errorf("got %v, want %v", s, want)
		}
	}

	if err := yaml.Unmarshal([]byte("[not-a-real-algorithm]"), &s); err == nil {
		t.Error("expected an error for an unknown signature algorithm name")
	}

	out, err := yaml.Marshal(want)
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
			var s webapp.SignatureAlgorithms
			if err := yaml.Unmarshal(fmt.Appendf(nil, "[%s]", tc.name), &s); err != nil {
				t.Fatal(err)
			}
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
	var s webapp.SignatureAlgorithms
	if err := yaml.Unmarshal([]byte("[ed25519, SHA256-RSA]"), &s); err != nil {
		t.Fatal(err)
	}
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
