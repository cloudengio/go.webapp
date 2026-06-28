// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// signatureSchemes lists every tls.SignatureScheme known to crypto/tls.
var signatureSchemes = []tls.SignatureScheme{
	tls.PKCS1WithSHA256,
	tls.PKCS1WithSHA384,
	tls.PKCS1WithSHA512,
	tls.PSSWithSHA256,
	tls.PSSWithSHA384,
	tls.PSSWithSHA512,
	tls.ECDSAWithP256AndSHA256,
	tls.ECDSAWithP384AndSHA384,
	tls.ECDSAWithP521AndSHA512,
	tls.Ed25519,
	tls.PKCS1WithSHA1,
	tls.ECDSAWithSHA1,
}

// ParseSignatureScheme returns the tls.SignatureScheme for the given name, as
// returned by tls.SignatureScheme.String(), e.g. "ECDSAWithP256AndSHA256".
// It returns an error if name does not match any known signature scheme.
func ParseSignatureScheme(name string) (tls.SignatureScheme, error) {
	for _, s := range signatureSchemes {
		if s.String() == name {
			return s, nil
		}
	}
	return 0, fmt.Errorf("unknown signature scheme %q", name)
}

// TLSSignatureSchemes is a list of TLS signature scheme names, e.g.
// "ECDSAWithP256AndSHA256" as returned by tls.SignatureScheme.String(). When
// unmarshaled from YAML it accepts a list of such names and converts them to
// the corresponding crypto/tls constants.
type TLSSignatureSchemes []tls.SignatureScheme

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *TLSSignatureSchemes) UnmarshalYAML(node *yaml.Node) error {
	var names []string
	if err := node.Decode(&names); err != nil {
		return fmt.Errorf("unmarshal: %v", err)
	}
	schemes := make(TLSSignatureSchemes, len(names))
	for i, name := range names {
		scheme, err := ParseSignatureScheme(name)
		if err != nil {
			return err
		}
		schemes[i] = scheme
	}
	*s = schemes
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (s TLSSignatureSchemes) MarshalYAML() (any, error) {
	names := make([]string, len(s))
	for i, scheme := range s {
		names[i] = scheme.String()
	}
	return names, nil
}

// String implements fmt.Stringer, returning a comma separated list of the
// signature scheme names in s, as returned by tls.SignatureScheme.String().
func (s TLSSignatureSchemes) String() string {
	names := make([]string, len(s))
	for i, scheme := range s {
		names[i] = scheme.String()
	}
	return strings.Join(names, ",")
}

// curveIDs lists every tls.CurveID known to crypto/tls.
var curveIDs = []tls.CurveID{
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
	tls.X25519,
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.SecP384r1MLKEM1024,
}

// ParseCurveID returns the tls.CurveID for the given name, as returned by
// tls.CurveID.String(), e.g. "CurveP256" or "X25519". It returns an error if
// name does not match any known curve/group ID.
func ParseCurveID(name string) (tls.CurveID, error) {
	for _, c := range curveIDs {
		if c.String() == name {
			return c, nil
		}
	}
	return 0, fmt.Errorf("unknown curve %q", name)
}

// TLSCurves is a list of TLS curve/group names, e.g. "CurveP256" or "X25519"
// as returned by tls.CurveID.String(). When unmarshaled from YAML it accepts
// a list of such names and converts them to the corresponding crypto/tls
// constants.
type TLSCurves []tls.CurveID

// UnmarshalYAML implements yaml.Unmarshaler.
func (c *TLSCurves) UnmarshalYAML(node *yaml.Node) error {
	var names []string
	if err := node.Decode(&names); err != nil {
		return fmt.Errorf("unmarshal: %v", err)
	}
	curves := make(TLSCurves, len(names))
	for i, name := range names {
		curve, err := ParseCurveID(name)
		if err != nil {
			return err
		}
		curves[i] = curve
	}
	*c = curves
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (c TLSCurves) MarshalYAML() (any, error) {
	names := make([]string, len(c))
	for i, curve := range c {
		names[i] = curve.String()
	}
	return names, nil
}

// String implements fmt.Stringer, returning a comma separated list of the
// curve/group names in c, as returned by tls.CurveID.String().
func (c TLSCurves) String() string {
	names := make([]string, len(c))
	for i, curve := range c {
		names[i] = curve.String()
	}
	return strings.Join(names, ",")
}

// tlsVersions lists every TLS version constant known to crypto/tls.
var tlsVersions = []uint16{
	tls.VersionTLS10,
	tls.VersionTLS11,
	tls.VersionTLS12,
	tls.VersionTLS13,
}

// ParseTLSVersion returns the TLS version constant for the given name, as
// returned by tls.VersionName, e.g. "TLS 1.3". It also accepts a "0x0304"-
// style hex value (the fallback format tls.VersionName itself returns for
// versions it does not recognize) or a plain decimal number (e.g. "772"),
// for backwards compatibility with configs that specify the raw version
// number. It returns an error if name does not match any of these forms.
func ParseTLSVersion(name string) (uint16, error) {
	for _, v := range tlsVersions {
		if tls.VersionName(v) == name {
			return v, nil
		}
	}
	if hex, ok := strings.CutPrefix(name, "0x"); ok {
		if v, err := strconv.ParseUint(hex, 16, 16); err == nil {
			return uint16(v), nil
		}
	}
	if v, err := strconv.ParseUint(name, 10, 16); err == nil {
		return uint16(v), nil
	}
	return 0, fmt.Errorf("unknown TLS version %q", name)
}

// TLSVersion is a single TLS version, e.g. "TLS 1.3" as returned by
// tls.VersionName. When unmarshaled from YAML it accepts such a name, or a
// "0x..." hex value for a version tls.VersionName does not recognize, and
// converts it to the corresponding uint16 version number.
type TLSVersion uint16

// UnmarshalYAML implements yaml.Unmarshaler.
func (v *TLSVersion) UnmarshalYAML(node *yaml.Node) error {
	var name string
	if err := node.Decode(&name); err != nil {
		return fmt.Errorf("unmarshal: %v", err)
	}
	version, err := ParseTLSVersion(name)
	if err != nil {
		return err
	}
	*v = TLSVersion(version)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (v TLSVersion) MarshalYAML() (any, error) {
	return tls.VersionName(uint16(v)), nil
}

// String implements fmt.Stringer, returning the version name, as returned by
// tls.VersionName.
func (v TLSVersion) String() string {
	return tls.VersionName(uint16(v))
}

// TLSVersions is a list of TLS version names, e.g. "TLS 1.3" as returned by
// tls.VersionName. When unmarshaled from YAML it accepts a list of such
// names, or "0x..." hex values for versions tls.VersionName does not
// recognize, and converts them to the corresponding uint16 version numbers.
type TLSVersions []uint16

// UnmarshalYAML implements yaml.Unmarshaler.
func (v *TLSVersions) UnmarshalYAML(node *yaml.Node) error {
	var names []string
	if err := node.Decode(&names); err != nil {
		return fmt.Errorf("unmarshal: %v", err)
	}
	versions := make(TLSVersions, len(names))
	for i, name := range names {
		version, err := ParseTLSVersion(name)
		if err != nil {
			return err
		}
		versions[i] = version
	}
	*v = versions
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (v TLSVersions) MarshalYAML() (any, error) {
	names := make([]string, len(v))
	for i, version := range v {
		names[i] = tls.VersionName(version)
	}
	return names, nil
}

// String implements fmt.Stringer, returning a comma separated list of the
// version names in v, as returned by tls.VersionName.
func (v TLSVersions) String() string {
	names := make([]string, len(v))
	for i, version := range v {
		names[i] = tls.VersionName(version)
	}
	return strings.Join(names, ",")
}
