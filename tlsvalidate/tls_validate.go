// Copyright 2021 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

// Package tlsvalidate provides functions for validating TLS certificates
// across multiple hosts and addresses.
package tlsvalidate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"

	"cloudeng.io/errors"
	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/net/netutil"
	"cloudeng.io/sync/errgroup"
	"cloudeng.io/webapp"
)

// Option represents an option for configuring a Validator.
type Option func(o *options)

// WithIPv4Only returns an option that configures the validator to only consider
// IPv4 addresses for a host.
func WithIPv4Only(ipv4Only bool) Option {
	return func(o *options) {
		o.ipv4Only = ipv4Only
	}
}

// WithValidForAtLeast returns an option that configures the validator to check
// that the certificate is valid for at least the specified duration.
func WithValidForAtLeast(validFor time.Duration) Option {
	return func(o *options) {
		o.validFor = validFor
	}
}

// WithIssuerRegexps returns an option that configures the validator to check
// that the certificate's issuer matches at least one of the provided regular
// expressions.
func WithIssuerRegexps(exprs ...*regexp.Regexp) Option {
	return func(o *options) {
		o.issuerREs = exprs
	}
}

// WithExpandDNSNames returns an option that configures the validator to expand
// the supplied hostname to all of its IP addresses. If false, the hostname
// is used as is.
func WithExpandDNSNames(expand bool) Option {
	return func(o *options) {
		o.expand = expand
	}
}

// WithRootCAs returns an option that configures the validator to use the
// supplied pool of root CAs for verification. WithRootCAs takes precedence
// over WithCustomRootCAPEM.
func WithRootCAs(rootCAs *x509.CertPool) Option {
	return func(o *options) {
		o.rootCAs = rootCAs
	}
}

// WithCustomRootCAPEM returns an option that configures the validator to use
// the root CAs specified in the PEM file for verification. Note that
// WithRootCAs takes precedence over WithCustomRootCAPEM.
func WithCustomRootCAPEM(pemFile string) Option {
	return func(o *options) {
		o.pemFile = pemFile
	}
}

// WithCheckSerialNumbers returns an option that configures the validator to
// check that the certificates for all IP addresses for a given host have the
// same serial number.
func WithCheckSerialNumbers(check bool) Option {
	return func(o *options) {
		o.checkSerial = check
	}
}

// WithCheckSignatureAlgorithm returns an option that configures the validator
// to check that the certificates for all IP addresses for a given host use
// the same signature algorithm.
func WithCheckSignatureAlgorithm(check bool) Option {
	return func(o *options) {
		o.checkSignature = check
	}
}

// WithCheckCipherSuites returns an option that configures the validator to
// check that the same cipher suite is negotiated for all IP addresses for a
// given host.
func WithCheckCipherSuites(check bool) Option {
	return func(o *options) {
		o.checkCipherSuite = check
	}
}

// WithTLSMinVersion returns an option that configures the validator to check
// that the TLS version used is at least the specified version.
func WithTLSMinVersion(version uint16) Option {
	return func(o *options) {
		o.tlsMinVer = version
	}
}

// WithCiphersuites returns an option that configures the validator to check
// that the ciphersuite used is one of the specified ciphersuites. It does so
// by restricting the TLS handshake to the specified ciphersuites, so the
// handshake will fail if the server does not support at least one of them.
func WithCiphersuites(suites []uint16) Option {
	return func(o *options) {
		o.ciphersuites = suites
	}
}

// WithAllowedSignatureAlgorithms returns an option that configures the
// validator to check that the leaf certificate's signature algorithm is one
// of the specified algorithms.
func WithAllowedSignatureAlgorithms(algs ...x509.SignatureAlgorithm) Option {
	return func(o *options) {
		o.allowedSignatureAlgorithms = algs
	}
}

// WithDeniedSignatureAlgorithms returns an option that configures the
// validator to fail if the leaf certificate's signature algorithm is one of
// the specified algorithms.
func WithDeniedSignatureAlgorithms(algs ...x509.SignatureAlgorithm) Option {
	return func(o *options) {
		o.deniedSignatureAlgorithms = algs
	}
}

// WithDeniedCipherSuites returns an option that configures the validator to
// fail if the negotiated ciphersuite is one of the specified ciphersuites.
func WithDeniedCipherSuites(suites ...uint16) Option {
	return func(o *options) {
		o.deniedCipherSuites = suites
	}
}

// WithCustomDNSServer returns an option that configures the validator to use
// the specified custom DNS server for resolving hostnames. The address may be
// a bare IP address, in which case the standard DNS port (53) is used, or an
// address that includes an explicit port.
func WithCustomDNSServer(addr string) Option {
	return func(o *options) {
		o.customDNSServer = addr
	}
}

// WithLogCertificateInfo returns an option that configures the validator to
// log certificate information to using ctxlog.Info.
func WithLogCertificateInfo(log bool) Option {
	return func(o *options) {
		o.logCertificateInfo = log
	}
}

// ErrValidator is an error type that wraps a certificate and an error. It is used
// to provide more context when a certificate validation fails.
type ErrValidator struct {
	Host        string
	Addr        string
	Port        string
	Certificate *x509.Certificate
	Err         error
}

func (e *ErrValidator) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "certificate validation failed"
}

func (e *ErrValidator) Unwrap() error {
	return e.Err
}

type options struct {
	ipv4Only                   bool
	validFor                   time.Duration
	issuerREs                  []*regexp.Regexp
	expand                     bool
	rootCAs                    *x509.CertPool
	pemFile                    string
	checkSerial                bool
	checkSignature             bool
	checkCipherSuite           bool
	tlsMinVer                  uint16
	ciphersuites               []uint16
	allowedSignatureAlgorithms []x509.SignatureAlgorithm
	deniedSignatureAlgorithms  []x509.SignatureAlgorithm
	deniedCipherSuites         []uint16
	customDNSServer            string
	logCertificateInfo         bool
}

// Validator provides a way to validate TLS certificates.
type Validator struct {
	opts     options
	resolver *net.Resolver
}

// NewValidator returns a new Validator configured with the supplied options.
func NewValidator(opts ...Option) *Validator {
	v := &Validator{}
	for _, opt := range opts {
		opt(&v.opts)
	}
	if v.opts.customDNSServer != "" {
		v.opts.customDNSServer = netutil.EnsureHostPort(v.opts.customDNSServer, "53")
		v.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, v.opts.customDNSServer)
			},
		}
	}
	return v
}

func certPool(pemFile string) (*x509.CertPool, error) {
	rootCAs := x509.NewCertPool()
	certs, err := os.ReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file %q: %w", pemFile, err)
	}
	// Append the custom certs to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		return nil, fmt.Errorf("no certs appended from %q", pemFile)
	}
	return rootCAs, nil
}

func (v *Validator) getStates(ctx context.Context, addrs []string, host, port string) ([]tlsState, error) {
	states := &tlsStates{
		states: make([]tlsState, 0, len(addrs)),
	}
	g, ctx := errgroup.WithContext(ctx)
	for _, addr := range addrs {
		g.Go(func() error {
			s, err := v.getTLSState(ctx, &tls.Config{
				ServerName:    host,
				RootCAs:       v.opts.rootCAs,
				MinVersion:    v.opts.tlsMinVer,
				CipherSuites:  v.opts.ciphersuites,
				Renegotiation: tls.RenegotiateNever,
			}, addr, port)
			if err != nil {
				return err
			}
			states.add(tlsState{
				host:  host,
				addr:  addr,
				port:  port,
				state: s,
			})
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return states.states, nil
}

func (v *Validator) verifyAcrossHosts(ctx context.Context, errs *errors.M, host string, states []tlsState) {
	if len(states) > 1 {
		serial := states[0].state.PeerCertificates[0].SerialNumber
		alg := states[0].state.PeerCertificates[0].SignatureAlgorithm
		suite := states[0].state.CipherSuite

		for _, cs := range states[1:] {
			if v.opts.checkSerial && serial.Cmp(cs.state.PeerCertificates[0].SerialNumber) != 0 {
				err := cs.error(cs.state.PeerCertificates[0],
					fmt.Errorf("%v: %v mismatched serial numbers: (%v) != (%v)", host, cs.addr, serial, cs.state.PeerCertificates[0].SerialNumber))
				errs.Append(err)

			}
			if v.opts.checkSignature && alg != cs.state.PeerCertificates[0].SignatureAlgorithm {
				err := cs.error(cs.state.PeerCertificates[0],
					fmt.Errorf("%v: %v mismatched signature algorithms: (%v) != (%v)", host, cs.addr, alg, cs.state.PeerCertificates[0].SignatureAlgorithm))
				errs.Append(err)
			}
			if v.opts.checkCipherSuite && suite != cs.state.CipherSuite {
				err := cs.error(cs.state.PeerCertificates[0],
					fmt.Errorf("%v: %v mismatched cipher suites: (%v) != (%v)", host, cs.addr, tls.CipherSuiteName(suite), tls.CipherSuiteName(cs.state.CipherSuite)))
				errs.Append(err)
			}
		}
	}
}

// Validate performs TLS validation for the given host and port. It may expand
// the host to multiple IP addresses and will validate each one concurrently.
func (v *Validator) Validate(ctx context.Context, host, port string) error {
	if v.opts.rootCAs == nil && len(v.opts.pemFile) > 0 {
		rootCAs, err := certPool(v.opts.pemFile)
		if err != nil {
			return err
		}
		v.opts.rootCAs = rootCAs
	}
	addrs, err := v.expandHost(ctx, host)
	if err != nil {
		return err
	}
	addrs = v.ignoreIPv6(addrs)

	states, err := v.getStates(ctx, addrs, host, port)
	if err != nil {
		return err
	}
	var errs errors.M
	for _, cs := range states {
		if err := v.validateConnectionState(ctx, &cs); err != nil {
			errs.Append(err)
		}
	}
	v.verifyAcrossHosts(ctx, &errs, host, states)
	return errs.Err()
}

func (s *tlsState) error(cert *x509.Certificate, err error) *ErrValidator {
	return &ErrValidator{
		Host:        s.host,
		Addr:        s.addr,
		Port:        s.port,
		Certificate: cert,
		Err:         err,
	}
}

func (v *Validator) logCertificateInfo(ctx context.Context, cs *tlsState) {
	if v.opts.logCertificateInfo {
		logger := ctxlog.Logger(ctx)
		for i, cert := range cs.state.PeerCertificates {
			logger.Info("certificate info",
				"index", i,
				"isleaf", i == 0,
				"host", cs.host,
				"addr", cs.addr,
				"port", cs.port,
				"subject", cert.Subject.CommonName,
				"serial", webapp.SerialNumberOpenSSL(cert.SerialNumber),
				"issuer", cert.Issuer.String(),
				"notbefore", cert.NotBefore,
				"notafter", cert.NotAfter,
				"signature_algorithm", cert.SignatureAlgorithm.String(),
				"cipher_suite", tls.CipherSuiteName(cs.state.CipherSuite),
			)
		}
	}
}

func (v *Validator) validateConnectionState(ctx context.Context, cs *tlsState) error {
	state := cs.state
	if len(state.PeerCertificates) == 0 {
		return &ErrValidator{
			Err: fmt.Errorf("no peer certificates found"),
		}
	}
	v.logCertificateInfo(ctx, cs)
	leaf := state.PeerCertificates[0]
	if len(v.opts.issuerREs) > 0 {
		matched := false
		issuer := leaf.Issuer.String()
		for _, re := range v.opts.issuerREs {
			if re.MatchString(issuer) {
				matched = true
				break
			}
		}
		if !matched {
			return cs.error(leaf, fmt.Errorf("certificate issuer %q does not match any of the specified patterns", issuer))
		}
	}

	if v.opts.validFor > 0 {
		if validFor := time.Until(leaf.NotAfter); validFor < v.opts.validFor {
			return cs.error(leaf, fmt.Errorf("certificate is valid for %v which is less than the required %v", validFor, v.opts.validFor))
		}
	}

	if len(v.opts.allowedSignatureAlgorithms) > 0 {
		if !slices.Contains(v.opts.allowedSignatureAlgorithms, leaf.SignatureAlgorithm) {
			return cs.error(leaf, fmt.Errorf("certificate signature algorithm %v is not one of the allowed algorithms %v", leaf.SignatureAlgorithm, v.opts.allowedSignatureAlgorithms))
		}
	}

	if len(v.opts.deniedSignatureAlgorithms) > 0 {
		if slices.Contains(v.opts.deniedSignatureAlgorithms, leaf.SignatureAlgorithm) {
			return cs.error(leaf, fmt.Errorf("certificate signature algorithm %v is one of the denied algorithms %v", leaf.SignatureAlgorithm, v.opts.deniedSignatureAlgorithms))
		}
	}

	if len(v.opts.deniedCipherSuites) > 0 {
		if slices.Contains(v.opts.deniedCipherSuites, state.CipherSuite) {
			return cs.error(leaf, fmt.Errorf("negotiated cipher suite %v is one of the denied ciphersuites %v", tls.CipherSuiteName(state.CipherSuite), cipherSuiteNames(v.opts.deniedCipherSuites)))
		}
	}
	return nil
}

func cipherSuiteNames(suites []uint16) []string {
	names := make([]string, len(suites))
	for i, s := range suites {
		names[i] = tls.CipherSuiteName(s)
	}
	return names
}

func (v *Validator) ignoreIPv6(addrs []string) []string {
	if !v.opts.ipv4Only {
		return addrs
	}
	ipv4 := []string{}
	for _, addr := range addrs {
		if len(net.ParseIP(addr).To4()) == net.IPv4len {
			ipv4 = append(ipv4, addr)
		}
	}
	return ipv4
}

func (v *Validator) expandHost(ctx context.Context, host string) ([]string, error) {
	if v.opts.expand {
		if v.resolver != nil {
			return v.resolver.LookupHost(ctx, host)
		}
		return net.LookupHost(host)
	}
	return []string{host}, nil
}

func (v *Validator) getTLSState(ctx context.Context, cfg *tls.Config, addr, port string) (tls.ConnectionState, error) {
	cfg = cfg.Clone()
	dialer := &net.Dialer{}
	if v.resolver != nil {
		dialer.Resolver = v.resolver
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr, port))
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, cfg)
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return tls.ConnectionState{}, err
	}
	return tlsConn.ConnectionState(), nil
}

type tlsState struct {
	host, addr, port string
	state            tls.ConnectionState
}

type tlsStates struct {
	mu     sync.Mutex
	states []tlsState
}

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

func (ts *tlsStates) add(state tlsState) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.states = append(ts.states, state)
}
