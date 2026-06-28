// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseCipherSuite returns the cipher suite ID for the given name, as
// returned by tls.CipherSuiteName, e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".
// It returns an error if name does not match any cipher suite known to the
// crypto/tls package, including its insecure ones.
func ParseCipherSuite(name string) (uint16, error) {
	for _, cs := range tls.CipherSuites() {
		if cs.Name == name {
			return cs.ID, nil
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if cs.Name == name {
			return cs.ID, nil
		}
	}
	return 0, fmt.Errorf("unknown cipher suite %q", name)
}

// signatureAlgorithms lists every x509.SignatureAlgorithm that has a non-empty
// human readable name, i.e. excluding x509.UnknownSignatureAlgorithm and
// x509.MD2WithRSA (which crypto/x509 never assigns a name to).
var signatureAlgorithms = []x509.SignatureAlgorithm{
	x509.MD5WithRSA,
	x509.SHA1WithRSA,
	x509.SHA256WithRSA,
	x509.SHA384WithRSA,
	x509.SHA512WithRSA,
	x509.DSAWithSHA1,
	x509.DSAWithSHA256,
	x509.ECDSAWithSHA1,
	x509.ECDSAWithSHA256,
	x509.ECDSAWithSHA384,
	x509.ECDSAWithSHA512,
	x509.SHA256WithRSAPSS,
	x509.SHA384WithRSAPSS,
	x509.SHA512WithRSAPSS,
	x509.PureEd25519,
}

// ParseSignatureAlgorithm returns the x509.SignatureAlgorithm for the given
// name, as returned by x509.SignatureAlgorithm.String(), e.g. "SHA256-RSA" or
// "Ed25519". It returns an error if name does not match any known signature
// algorithm.
func ParseSignatureAlgorithm(name string) (x509.SignatureAlgorithm, error) {
	for _, alg := range signatureAlgorithms {
		if alg.String() == name {
			return alg, nil
		}
	}
	return x509.UnknownSignatureAlgorithm, fmt.Errorf("unknown signature algorithm %q", name)
}

// CipherSuites is a list of TLS cipher suite names, e.g.
// "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" as returned by tls.CipherSuiteName.
// When unmarshaled from YAML it accepts a list of such names, plus the
// special name "insecure" which expands to every cipher suite returned by
// tls.InsecureCipherSuites, and converts them to the corresponding
// crypto/tls constants.
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
		id, err := ParseCipherSuite(name)
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

// String implements fmt.Stringer, returning a comma separated list of the
// cipher suite names in c, as returned by tls.CipherSuiteName.
func (c CipherSuites) String() string {
	names := make([]string, len(c))
	for i, id := range c {
		names[i] = tls.CipherSuiteName(id)
	}
	return strings.Join(names, ",")
}

// SignatureAlgorithms is a list of x509 signature algorithm names, e.g.
// "SHA256-RSA" as returned by x509.SignatureAlgorithm.String(). When
// unmarshaled from YAML it accepts a list of such names, plus the special
// shortnames "rsa", "dsa", "ecdsa", "ed25519" and "rsa-pss" which each expand
// to every algorithm of that type, and converts them to the corresponding
// crypto/x509 constants.
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
			alg, err := ParseSignatureAlgorithm(name)
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

// String implements fmt.Stringer, returning a comma separated list of the
// signature algorithm names in s, as returned by
// x509.SignatureAlgorithm.String().
func (s SignatureAlgorithms) String() string {
	names := make([]string, len(s))
	for i, alg := range s {
		names[i] = alg.String()
	}
	return strings.Join(names, ",")
}
