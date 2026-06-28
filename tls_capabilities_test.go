// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp_test

import (
	"crypto/tls"
	"strings"
	"testing"

	"cloudeng.io/webapp"
	"gopkg.in/yaml.v3"
)

func TestParseSignatureScheme(t *testing.T) {
	scheme, err := webapp.ParseSignatureScheme("ECDSAWithP256AndSHA256")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := scheme, tls.ECDSAWithP256AndSHA256; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	if _, err := webapp.ParseSignatureScheme("not-a-real-scheme"); err == nil {
		t.Error("expected an error for an unknown signature scheme name")
	}
}

func TestTLSSignatureSchemesString(t *testing.T) {
	s := webapp.TLSSignatureSchemes{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256}
	want := "ECDSAWithP256AndSHA256,PSSWithSHA256"
	if got := s.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := (webapp.TLSSignatureSchemes{}).String(), ""; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTLSSignatureSchemesYAML(t *testing.T) {
	var s webapp.TLSSignatureSchemes
	in := "[ECDSAWithP256AndSHA256, PSSWithSHA256]"
	if err := yaml.Unmarshal([]byte(in), &s); err != nil {
		t.Fatal(err)
	}
	want := webapp.TLSSignatureSchemes{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256}
	if len(s) != len(want) {
		t.Fatalf("got %v, want %v", s, want)
	}
	for i := range s {
		if s[i] != want[i] {
			t.Errorf("got %v, want %v", s, want)
		}
	}

	if err := yaml.Unmarshal([]byte("[not-a-real-scheme]"), &s); err == nil {
		t.Error("expected an error for an unknown signature scheme name")
	}

	out, err := yaml.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if got, wantSubstr := string(out), "ECDSAWithP256AndSHA256"; !strings.Contains(got, wantSubstr) {
		t.Errorf("marshaled output %q does not contain %q", got, wantSubstr)
	}
}

func TestParseCurveID(t *testing.T) {
	curve, err := webapp.ParseCurveID("X25519")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := curve, tls.X25519; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	if _, err := webapp.ParseCurveID("not-a-real-curve"); err == nil {
		t.Error("expected an error for an unknown curve name")
	}
}

func TestTLSCurvesString(t *testing.T) {
	c := webapp.TLSCurves{tls.CurveP256, tls.X25519}
	want := "CurveP256,X25519"
	if got := c.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := (webapp.TLSCurves{}).String(), ""; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTLSCurvesYAML(t *testing.T) {
	var c webapp.TLSCurves
	in := "[CurveP256, X25519]"
	if err := yaml.Unmarshal([]byte(in), &c); err != nil {
		t.Fatal(err)
	}
	want := webapp.TLSCurves{tls.CurveP256, tls.X25519}
	if len(c) != len(want) {
		t.Fatalf("got %v, want %v", c, want)
	}
	for i := range c {
		if c[i] != want[i] {
			t.Errorf("got %v, want %v", c, want)
		}
	}

	if err := yaml.Unmarshal([]byte("[not-a-real-curve]"), &c); err == nil {
		t.Error("expected an error for an unknown curve name")
	}

	out, err := yaml.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if got, wantSubstr := string(out), "CurveP256"; !strings.Contains(got, wantSubstr) {
		t.Errorf("marshaled output %q does not contain %q", got, wantSubstr)
	}
}

func TestParseTLSVersion(t *testing.T) {
	version, err := webapp.ParseTLSVersion("TLS 1.3")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := version, uint16(tls.VersionTLS13); got != want {
		t.Errorf("got %#04x, want %#04x", got, want)
	}

	// Hex fallback, as used by tls.VersionName for unrecognized versions.
	version, err = webapp.ParseTLSVersion("0x0301")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := version, uint16(tls.VersionTLS10); got != want {
		t.Errorf("got %#04x, want %#04x", got, want)
	}

	// Plain decimal, for backwards compatibility with configs that specify
	// the raw version number.
	version, err = webapp.ParseTLSVersion("772")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := version, uint16(tls.VersionTLS13); got != want {
		t.Errorf("got %#04x, want %#04x", got, want)
	}

	if _, err := webapp.ParseTLSVersion("not-a-real-version"); err == nil {
		t.Error("expected an error for an unknown version name")
	}
}

func TestTLSVersionString(t *testing.T) {
	v := webapp.TLSVersion(tls.VersionTLS13)
	if got, want := v.String(), "TLS 1.3"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTLSVersionYAML(t *testing.T) {
	type cfg struct {
		Version webapp.TLSVersion `yaml:"version"`
	}

	var c cfg
	if err := yaml.Unmarshal([]byte(`version: "TLS 1.3"`), &c); err != nil {
		t.Fatal(err)
	}
	if got, want := c.Version, webapp.TLSVersion(tls.VersionTLS13); got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	// Hex fallback, as used by tls.VersionName for unrecognized versions.
	var c2 cfg
	if err := yaml.Unmarshal([]byte(`version: "0x0301"`), &c2); err != nil {
		t.Fatal(err)
	}
	if got, want := c2.Version, webapp.TLSVersion(tls.VersionTLS10); got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	var c3 cfg
	if err := yaml.Unmarshal([]byte(`version: not-a-real-version`), &c3); err == nil {
		t.Error("expected an error for an unknown version name")
	}

	out, err := yaml.Marshal(cfg{Version: webapp.TLSVersion(tls.VersionTLS13)})
	if err != nil {
		t.Fatal(err)
	}
	if got, wantSubstr := string(out), "TLS 1.3"; !strings.Contains(got, wantSubstr) {
		t.Errorf("marshaled output %q does not contain %q", got, wantSubstr)
	}
}

func TestTLSVersionsString(t *testing.T) {
	v := webapp.TLSVersions{tls.VersionTLS12, tls.VersionTLS13}
	want := "TLS 1.2,TLS 1.3"
	if got := v.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := (webapp.TLSVersions{}).String(), ""; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTLSVersionsYAML(t *testing.T) {
	var v webapp.TLSVersions
	in := "[TLS 1.2, TLS 1.3]"
	if err := yaml.Unmarshal([]byte(in), &v); err != nil {
		t.Fatal(err)
	}
	want := webapp.TLSVersions{tls.VersionTLS12, tls.VersionTLS13}
	if len(v) != len(want) {
		t.Fatalf("got %v, want %v", v, want)
	}
	for i := range v {
		if v[i] != want[i] {
			t.Errorf("got %v, want %v", v, want)
		}
	}

	if err := yaml.Unmarshal([]byte("[not-a-real-version]"), &v); err == nil {
		t.Error("expected an error for an unknown version name")
	}

	out, err := yaml.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if got, wantSubstr := string(out), "TLS 1.3"; !strings.Contains(got, wantSubstr) {
		t.Errorf("marshaled output %q does not contain %q", got, wantSubstr)
	}
}
