package testwebapp

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"cloudeng.io/errors"
	"cloudeng.io/webapp/tlsvalidate"
)

// TLSSpec represents a specification for a TLS test.
type TLSSpec struct {
	Host               string        `yaml:"host"`
	Port               string        `yaml:"port"`
	ExpandDNSNames     bool          `yaml:"expand-dns-names"`     // see tlsvalidate.WithExpandDNSNames
	CheckSerialNumbers bool          `yaml:"check-serial-numbers"` // see tlsvalidate.WithCheckSerialNumbers
	ValidFor           time.Duration `yaml:"valid-for"`            // see tlsvalidate.WithValidForAtLeast
	TLSMinVersion      uint16        `yaml:"tls-min-version"`      // see tlsvalidate.WithTLSMinVersion
	IssuerREs          []string      `yaml:"issuer-res"`           // see tlsvalidate.WithIssuerRegexps
	issuerREs          []*regexp.Regexp
}

var (
	ErrTLSSpecUnexpectedError  = errors.New("tls unexpected error")
	ErrTLSInvalidSerialNumbers = errors.New("tls invalid serial numbers")
	ErrTLSInvalidValidFor      = errors.New("tls invalid duration")
	ErrTLSInvalidIssuer        = errors.New("tls invalid issuer")
)

// TLSTest can be used to validate TLS certificates for a set of hosts.
type TLSTest struct {
	client *http.Client // the client to use for making requests
	specs  []TLSSpec    // the specifications for the TLS tests
}

func NewTLSTest(client *http.Client, specs ...TLSSpec) *TLSTest {
	return &TLSTest{client: client, specs: specs}
}

func (t TLSTest) compileREs() error {
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

func (t *TLSTest) Run(ctx context.Context) error {
	if err := t.compileREs(); err != nil {
		return err
	}
	var errs errors.M
	for _, spec := range t.specs {
		err := t.verify(ctx, spec)
		if err != nil {
			errs.Append(fmt.Errorf("%v: %w", spec, err))
			continue
		}
	}
	return errs.Err()
}

func (s TLSSpec) options() []tlsvalidate.Option {
	return []tlsvalidate.Option{
		tlsvalidate.WithExpandDNSNames(s.CheckSerialNumbers),
		tlsvalidate.WithValidForAtLeast(s.ValidFor),
		tlsvalidate.WithIssuerRegexps(s.issuerREs...),
		tlsvalidate.WithCheckSerialNumbers(s.CheckSerialNumbers),
		tlsvalidate.WithExpandDNSNames(s.ExpandDNSNames),
		tlsvalidate.WithTLSMinVersion(s.TLSMinVersion),
	}
}

func (t TLSTest) verify(ctx context.Context, spec TLSSpec) error {
	opts := spec.options()
	validator := tlsvalidate.NewValidator(opts...)
	return validator.Validate(ctx, spec.Host, spec.Port)
}
