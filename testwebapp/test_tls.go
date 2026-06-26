// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	goerrors "errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"cloudeng.io/cmdutil/cmdyaml"
	"cloudeng.io/errors"
	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/webapp"
	"cloudeng.io/webapp/devtest"
	"cloudeng.io/webapp/tlsvalidate"
	"gopkg.in/yaml.v3"
)

// TLSSpec represents a specification for a TLS test.
type TLSSpec struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`

	CustomDNSServer string `yaml:"custom-dns-server" doc:"custom DNS server to use for resolving hostnames, if empty the system resolver is used"` // custom DNS server to use for resolving hostnames, if empty the system resolver is used

	LogCertInfo bool `yaml:"log-cert-info" doc:"if true, log certificate information"` // if true, log certificate information

	ExpandDNSNames     bool               `yaml:"expand-dns-names" doc:"see tlsvalidate.WithExpandDNSNames"`                                                              // see tlsvalidate.WithExpandDNSNames
	CheckSerialNumbers bool               `yaml:"check-serial-numbers" doc:"see tlsvalidate.WithCheckSerialNumbers"`                                                      // see tlsvalidate.WithCheckSerialNumbers
	ValidFor           time.Duration      `yaml:"valid-for" doc:"see tlsvalidate.WithValidForAtLeast"`                                                                    // see tlsvalidate.WithValidForAtLeast
	TLSMinVersion      uint16             `yaml:"tls-min-version" doc:"see tlsvalidate.WithTLSMinVersion"`                                                                // see tlsvalidate.WithTLSMinVersion
	IssuerREs          cmdyaml.RegexpList `yaml:"issuer-res" doc:"see tlsvalidate.WithIssuerRegexps"`                                                                     // see tlsvalidate.WithIssuerRegexps
	CustomCAPEM        string             `yaml:"custom-ca-pem" doc:"used tlsvalidate.WithCustomRootCAPEM"`                                                               // used tlsvalidate.WithCustomRootCAPEM
	CustomCAPEMOnly    bool               `yaml:"custom-ca-pem-only" doc:"if true, only the custom CA PEM file is used, otherwise it's appended to the system cert pool"` // if true, only the custom CA PEM file is used, otherwise it's appended to the system cert pool

	// CipherSuites and SignatureAlgorithms specify the set of algorithms that
	// the server must support/use; if either is non-empty the corresponding
	// check is run. NotAllowedCipherSuites and NotAllowedSignatureAlgorithms
	// specify algorithms that the server must not use; if either is
	// non-empty and the server negotiates/uses one of them, validation
	// fails.
	CipherSuites                  CipherSuites        `yaml:"cipher-suites" doc:"names of the cipher suites that the server must support, e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; see tls.CipherSuites for a list of supported cipher suites"`
	NotAllowedCipherSuites        CipherSuites        `yaml:"not-allowed-cipher-suites" doc:"names of the cipher suites that the server must not negotiate; see tls.CipherSuites for a list of supported cipher suites. Use 'insecure' to refer to all insecure suites."`
	SignatureAlgorithms           SignatureAlgorithms `yaml:"signature-algorithms" doc:"names of the signature algorithms that the certificate must use, e.g. SHA256-RSA; see tlsvalidate.WithAllowedSignatureAlgorithms. Use 'rsa', 'dsa', 'ecdsa', 'ed25519' or 'rsa-pss' to refer to all algorithms of that type."`
	NotAllowedSignatureAlgorithms SignatureAlgorithms `yaml:"not-allowed-signature-algorithms" doc:"names of the signature algorithms that the certificate must not use; see tlsvalidate.WithDeniedSignatureAlgorithms"`

	client *http.Client
}

// String implements fmt.Stringer, returning the YAML representation of the spec.
func (s TLSSpec) String() string {
	out, err := yaml.Marshal(s)
	if err != nil {
		return err.Error()
	}
	return string(out)
}

// CipherSuites is a list of TLS cipher suite names, e.g.
// "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" as returned by tls.CipherSuiteName.
// When unmarshaled from YAML it accepts a list of such names and converts
// them to the corresponding crypto/tls constants.
type CipherSuites []uint16

// UnmarshalYAML implements yaml.Unmarshaler.
func (c *CipherSuites) UnmarshalYAML(node *yaml.Node) error {
	var names []string
	if err := node.Decode(&names); err != nil {
		return fmt.Errorf("unmarshal: %v", err)
	}
	suites := make(CipherSuites, 0, len(names))
	for _, name := range names {
		if name == "insecure" {
			for _, c := range tls.InsecureCipherSuites() {
				suites = append(suites, c.ID)
			}
			continue
		}
		id, err := tlsvalidate.ParseCipherSuite(name)
		if err != nil {
			return err
		}
		suites = append(suites, id)
	}
	*c = suites
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (c CipherSuites) MarshalYAML() (any, error) {
	names := make([]string, len(c))
	for i, id := range c {
		names[i] = tls.CipherSuiteName(id)
	}
	return names, nil
}

// SignatureAlgorithms is a list of x509 signature algorithm names, e.g.
// "SHA256-RSA" as returned by x509.SignatureAlgorithm.String(). When
// unmarshaled from YAML it accepts a list of such names and converts them to
// the corresponding crypto/x509 constants.
type SignatureAlgorithms []x509.SignatureAlgorithm

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *SignatureAlgorithms) UnmarshalYAML(node *yaml.Node) error {
	var names []string
	if err := node.Decode(&names); err != nil {
		return fmt.Errorf("unmarshal: %v", err)
	}
	algs := make(SignatureAlgorithms, 0, len(names))
	for _, name := range names {
		switch name {
		case "rsa":
			algs = append(algs, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA)
		case "dsa":
			algs = append(algs, x509.DSAWithSHA1, x509.DSAWithSHA256)
		case "ecdsa":
			algs = append(algs, x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512)
		case "ed25519":
			algs = append(algs, x509.PureEd25519)
		case "rsa-pss":
			algs = append(algs, x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS)
		default:
			alg, err := tlsvalidate.ParseSignatureAlgorithm(name)
			if err != nil {
				return err
			}
			algs = append(algs, alg)
		}
	}
	*s = algs
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (s SignatureAlgorithms) MarshalYAML() (any, error) {
	names := make([]string, len(s))
	for i, alg := range s {
		names[i] = alg.String()
	}
	return names, nil
}

// WithCustomCAPEMFile sets the custom CA PEM file for all specs if
// not already set in each/any spec.
func WithCustomCAPEMFile(s []TLSSpec, pemFile string) []TLSSpec {
	if len(pemFile) == 0 {
		return s
	}
	for i := range s {
		if len(s[i].CustomCAPEM) > 0 {
			continue
		}
		s[i].CustomCAPEM = pemFile
	}
	return s
}

var (
	ErrTLSSpecUnexpectedError  = errors.New("tls unexpected error")
	ErrTLSInvalidSerialNumbers = errors.New("tls invalid serial numbers")
	ErrTLSInvalidValidFor      = errors.New("tls invalid duration")
	ErrTLSInvalidIssuer        = errors.New("tls invalid issuer")
)

// TLSTest can be used to validate TLS certificates for a set of hosts.
type TLSTest struct {
	specs []TLSSpec // the specifications for the TLS tests
}

func NewTLSTest(specs ...TLSSpec) *TLSTest {
	return &TLSTest{specs: specs}
}

/*
func (t *TLSTest) compileREs() error {
	for i, spec := range t.specs {
		var res []*regexp.Regexp
		for _, issuer := range spec.IssuerREs {
			re, err := regexp.Compile(issuer)
			if err != nil {
				return err
			}
			res = append(res, re)
		}
		t.specs[i].issuerREs = res
	}
	return nil
}
*/

func (t *TLSTest) configureHTTPClients(ctx context.Context) error {
	for i, spec := range t.specs {
		t.specs[i].client = http.DefaultClient
		if len(spec.CustomCAPEM) > 0 {
			client, err := webapp.NewHTTPClient(ctx, webapp.WithCustomCAPEMFile(spec.CustomCAPEM))
			if err != nil {
				return err
			}
			t.specs[i].client = client
		}
	}
	return nil
}

func (t *TLSTest) Run(ctx context.Context) error {
	ctxlog.Info(ctx, "tls: starting", "num_specs", len(t.specs))
	//if err := t.compileREs(); err != nil {
	//	return err
	//}
	if err := t.configureHTTPClients(ctx); err != nil {
		return err
	}
	var errs errors.M
	for _, spec := range t.specs {
		err := t.verify(ctx, spec)
		if err != nil {
			logger := ctxlog.Logger(ctx).With(
				"spec", spec, "success", false, "error", err)
			if ev, ok := goerrors.AsType[*tlsvalidate.ErrValidator](err); ok {
				logger = logger.With(
					"cert.subject", ev.Certificate.Subject.CommonName,
					"cert.issuer", ev.Certificate.Issuer.CommonName,
					"cert.serial", webapp.SerialNumberOpenSSL(ev.Certificate.SerialNumber),
					"cert.not_before", ev.Certificate.NotBefore,
					"cert.not_after", ev.Certificate.NotAfter,
				)
			}
			logger.Error("tls: verification failed")
			errs.Append(fmt.Errorf("%v: %w", spec, err))
			continue
		}
		ctxlog.Info(ctx, "tls", "spec", spec, "success", true)
	}
	return errs.Err()
}

func (s TLSSpec) options() ([]tlsvalidate.Option, error) {
	o := []tlsvalidate.Option{
		tlsvalidate.WithLogCertificateInfo(s.LogCertInfo),
		tlsvalidate.WithValidForAtLeast(s.ValidFor),
		tlsvalidate.WithIssuerRegexps(s.IssuerREs.Regexps()...),
		tlsvalidate.WithCheckSerialNumbers(s.CheckSerialNumbers),
		tlsvalidate.WithExpandDNSNames(s.ExpandDNSNames),
		tlsvalidate.WithTLSMinVersion(s.TLSMinVersion),
		tlsvalidate.WithCustomDNSServer(s.CustomDNSServer),
		tlsvalidate.WithCiphersuites(s.CipherSuites),
		tlsvalidate.WithAllowedSignatureAlgorithms(s.SignatureAlgorithms...),
		tlsvalidate.WithDeniedCipherSuites(s.NotAllowedCipherSuites...),
		tlsvalidate.WithDeniedSignatureAlgorithms(s.NotAllowedSignatureAlgorithms...),
	}
	if len(s.CustomCAPEM) == 0 {
		return o, nil
	}
	var err error
	var certPool *x509.CertPool
	if s.CustomCAPEMOnly {
		certPool, err = devtest.CertPoolForTesting(s.CustomCAPEM)
	} else {
		certPool, err = devtest.CertPoolWithSystemRootsForTesting(s.CustomCAPEM)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create cert pool: %w", err)
	}
	return append(o, tlsvalidate.WithRootCAs(certPool)), nil
}

func (t TLSTest) verify(ctx context.Context, spec TLSSpec) error {
	opts, err := spec.options()
	if err != nil {
		return err
	}
	validator := tlsvalidate.NewValidator(opts...)
	port := spec.Port
	if len(port) == 0 {
		port = "443"
	}
	return validator.Validate(ctx, spec.Host, port)
}

func LetsEncryptTLSSpec() TLSSpec {
	re := regexp.MustCompile(`Let'?s Encrypt`)
	const tlsVersionTLS13 uint16 = 0x0304 // TLS 1.3
	return TLSSpec{
		ExpandDNSNames:     true,
		CheckSerialNumbers: true,
		ValidFor:           240 * time.Hour, // cert should be valid for at least 10 days
		TLSMinVersion:      tlsVersionTLS13, // TLS 1.3
		IssuerREs:          cmdyaml.RegexpList{cmdyaml.Regexp{Regexp: re}},
	}
}
