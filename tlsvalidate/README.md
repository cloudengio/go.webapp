# Package [cloudeng.io/webapp/tlsvalidate](https://pkg.go.dev/cloudeng.io/webapp/tlsvalidate?tab=doc)

```go
import cloudeng.io/webapp/tlsvalidate
```

Package tlsvalidate provides functions for validating TLS certificates
across multiple hosts and addresses.

## Functions
### Func ParseCipherSuite
```go
func ParseCipherSuite(name string) (uint16, error)
```
ParseCipherSuite returns the cipher suite ID for the given name, as returned
by tls.CipherSuiteName, e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".
It returns an error if name does not match any cipher suite known to the
crypto/tls package, including its insecure ones.

### Func ParseSignatureAlgorithm
```go
func ParseSignatureAlgorithm(name string) (x509.SignatureAlgorithm, error)
```
ParseSignatureAlgorithm returns the x509.SignatureAlgorithm for the given
name, as returned by x509.SignatureAlgorithm.String(), e.g. "SHA256-RSA" or
"Ed25519". It returns an error if name does not match any known signature
algorithm.



## Types
### Type ErrValidator
```go
type ErrValidator struct {
	Host        string
	Addr        string
	Port        string
	Certificate *x509.Certificate
	Err         error
}
```
ErrValidator is an error type that wraps a certificate and an error.
It is used to provide more context when a certificate validation fails.

### Methods

```go
func (e *ErrValidator) Error() string
```


```go
func (e *ErrValidator) Unwrap() error
```




### Type Option
```go
type Option func(o *options)
```
Option represents an option for configuring a Validator.

### Functions

```go
func WithAllowedSignatureAlgorithms(algs ...x509.SignatureAlgorithm) Option
```
WithAllowedSignatureAlgorithms returns an option that configures the
validator to check that the leaf certificate's signature algorithm is one of
the specified algorithms.


```go
func WithCheckCipherSuites(check bool) Option
```
WithCheckCipherSuites returns an option that configures the validator to
check that the same cipher suite is negotiated for all IP addresses for a
given host.


```go
func WithCheckSerialNumbers(check bool) Option
```
WithCheckSerialNumbers returns an option that configures the validator to
check that the certificates for all IP addresses for a given host have the
same serial number.


```go
func WithCheckSignatureAlgorithm(check bool) Option
```
WithCheckSignatureAlgorithm returns an option that configures the validator
to check that the certificates for all IP addresses for a given host use the
same signature algorithm.


```go
func WithCiphersuites(suites []uint16) Option
```
WithCiphersuites returns an option that configures the validator to check
that the ciphersuite used is one of the specified ciphersuites. It does
so by restricting the TLS handshake to the specified ciphersuites, so the
handshake will fail if the server does not support at least one of them.


```go
func WithCustomDNSServer(addr string) Option
```
WithCustomDNSServer returns an option that configures the validator to use
the specified custom DNS server for resolving hostnames. The address may
be a bare IP address, in which case the standard DNS port (53) is used,
or an address that includes an explicit port.


```go
func WithCustomRootCAPEM(pemFile string) Option
```
WithCustomRootCAPEM returns an option that configures the validator to
use the root CAs specified in the PEM file for verification. Note that
WithRootCAs takes precedence over WithCustomRootCAPEM.


```go
func WithDeniedCipherSuites(suites ...uint16) Option
```
WithDeniedCipherSuites returns an option that configures the validator to
fail if the negotiated ciphersuite is one of the specified ciphersuites.


```go
func WithDeniedSignatureAlgorithms(algs ...x509.SignatureAlgorithm) Option
```
WithDeniedSignatureAlgorithms returns an option that configures the
validator to fail if the leaf certificate's signature algorithm is one of
the specified algorithms.


```go
func WithExpandDNSNames(expand bool) Option
```
WithExpandDNSNames returns an option that configures the validator to expand
the supplied hostname to all of its IP addresses. If false, the hostname is
used as is.


```go
func WithIPv4Only(ipv4Only bool) Option
```
WithIPv4Only returns an option that configures the validator to only
consider IPv4 addresses for a host.


```go
func WithIssuerRegexps(exprs ...*regexp.Regexp) Option
```
WithIssuerRegexps returns an option that configures the validator to check
that the certificate's issuer matches at least one of the provided regular
expressions.


```go
func WithLogCertificateInfo(log bool) Option
```
WithLogCertificateInfo returns an option that configures the validator to
log certificate information to using ctxlog.Info.


```go
func WithRootCAs(rootCAs *x509.CertPool) Option
```
WithRootCAs returns an option that configures the validator to use the
supplied pool of root CAs for verification. WithRootCAs takes precedence
over WithCustomRootCAPEM.


```go
func WithTLSMinVersion(version uint16) Option
```
WithTLSMinVersion returns an option that configures the validator to check
that the TLS version used is at least the specified version.


```go
func WithValidForAtLeast(validFor time.Duration) Option
```
WithValidForAtLeast returns an option that configures the validator to check
that the certificate is valid for at least the specified duration.




### Type Validator
```go
type Validator struct {
	// contains filtered or unexported fields
}
```
Validator provides a way to validate TLS certificates.

### Functions

```go
func NewValidator(opts ...Option) *Validator
```
NewValidator returns a new Validator configured with the supplied options.



### Methods

```go
func (v *Validator) Validate(ctx context.Context, host, port string) error
```
Validate performs TLS validation for the given host and port. It may expand
the host to multiple IP addresses and will validate each one concurrently.







