# Package [cloudeng.io/webapp](https://pkg.go.dev/cloudeng.io/webapp?tab=doc)

```go
import cloudeng.io/webapp
```

Package webapp and its sub-packages provide support for building webapps.
This includes utility routines for managing http.Server instances,
generating self-signed TLS certificates etc. The sub-packages provide
support for managing the assets to be served, various forms of
authentication and common toolchains such as webpack. For production
purposes assets are built into the server's binary, but for development they
are built into the binary but can be overridden from a local filesystem
or from a running development server that manages those assets (eg.
a webpack dev server instance). This provides the flexibility for both
simple deployment of production servers and iterative development within the
same application.

An example/template can be found in cmd/webapp.

## Constants
### ACMEHTTP01Prefix, ACMEHTTP01HTTPPrefix, ACMEHTTP01ChiPrefix
```go
// ACMEHTTP01Prefix is the well-known prefix for ACME HTTP-01 challenges.
ACMEHTTP01Prefix = "/.well-known/acme-challenge/"
// ACMEHTTP01HTTPPrefix is the well-known prefix for ACME HTTP-01 challenges
// when used with http.ServeMux
ACMEHTTP01HTTPPrefix = ACMEHTTP01Prefix
// ACMEHTTP01ChiPrefix is the well-known prefix for ACME HTTP-01 challenges
// when used with chi.Router
ACMEHTTP01ChiPrefix = ACMEHTTP01Prefix + "*"

```

### PreferredTLSMinVersion
```go
PreferredTLSMinVersion = tls.VersionTLS13

```
PreferredTLSMinVersion is the preferred minimum TLS version for tls.Config
instances created by this package.



## Variables
### PreferredCipherSuites
```go
PreferredCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

```
PreferredCipherSuites is the list of preferred cipher suites for tls.Config
instances created by this package.

### PreferredCurves
```go
PreferredCurves = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
}

```
PreferredCurves is the list of preferred elliptic curves for tls.Config
instances created by this package.

### PreferredSignatureSchemes
```go
PreferredSignatureSchemes = []tls.SignatureScheme{
	tls.ECDSAWithP256AndSHA256,
	tls.ECDSAWithP384AndSHA384,
	tls.ECDSAWithP521AndSHA512,
}

```
PreferredSignatureSchemes is the list of preferred signature schemes
generally used for obtainint TLS certificates.



## Functions
### Func FindLeafPEM
```go
func FindLeafPEM(certsPEM []*pem.Block) ([]byte, *x509.Certificate, error)
```
FindLeafPEM searches the supplied PEM blocks for the leaf certificate and
returns its DER encoding along with the parsed x509.Certificate.

### Func GetConfigForClientNoSNI
```go
func GetConfigForClientNoSNI(matcher func(addr string) bool, getConfig func(*tls.ClientHelloInfo) (*tls.Config, error)) func(*tls.ClientHelloInfo) (*tls.Config, error)
```
GetConfigForClientNoSNI returns a function that can be used as the
GetConfigForClient callback in a tls.Config to allow connections from
addresses that match the provided matcher function that do not include
an SNI (Server Name Indication) in the TLS handshake. This is primarily
intended for use with load balancer health checks etc.

### Func HealthzHandler
```go
func HealthzHandler() http.Handler
```
HealthzHandler returns a handler that returns "ok" and a 200 status code.

### Func NewHTTPClient
```go
func NewHTTPClient(ctx context.Context, opts ...HTTPClientOption) (*http.Client, error)
```
NewHTTPClient creates a new HTTP client configured according to the
specified options.

### Func NewHTTPServer
```go
func NewHTTPServer(ctx context.Context, addr string, handler http.Handler) (net.Listener, *http.Server, error)
```
NewHTTPServer returns a new *http.Server using
netutil.ParseAddrDefaultPort(addr "http") to obtain the address to listen on
and NewHTTPServerOnly to create the server.

### Func NewHTTPServerOnly
```go
func NewHTTPServerOnly(ctx context.Context, addr string, handler http.Handler) *http.Server
```
NewHTTPServerOnly returns a new *http.Server whose address defaults to
":http" and with it's BaseContext set to the supplied context. ErrorLog is
set to log errors via the ctxlog package.

### Func NewTLSServer
```go
func NewTLSServer(ctx context.Context, addr string, handler http.Handler, cfg *tls.Config) (net.Listener, *http.Server, error)
```
NewTLSServer returns a new *http.Server using
netutil.ParseAddrDefaultPort(addr, "https") to obtain the address to listen
on and NewTLSServerOnly to create the server.

### Func NewTLSServerOnly
```go
func NewTLSServerOnly(ctx context.Context, addr string, handler http.Handler, cfg *tls.Config) *http.Server
```
NewTLSServerOnly returns a new *http.Server whose address defaults to
":https" and with it's BaseContext set to the supplied context and TLSConfig
set to the supplied config. ErrorLog is set to log errors via the ctxlog
package.

### Func ParseCertsPEM
```go
func ParseCertsPEM(pemData []byte) ([]*x509.Certificate, error)
```
ParseCertsPEM parses certificates from the provided PEM data.

### Func ParseCipherSuite
```go
func ParseCipherSuite(name string) (uint16, error)
```
ParseCipherSuite returns the cipher suite ID for the given name, as returned
by tls.CipherSuiteName, e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".
It returns an error if name does not match any cipher suite known to the
crypto/tls package, including its insecure ones.

### Func ParseCurveID
```go
func ParseCurveID(name string) (tls.CurveID, error)
```
ParseCurveID returns the tls.CurveID for the given name, as returned by
tls.CurveID.String(), e.g. "CurveP256" or "X25519". It returns an error if
name does not match any known curve/group ID.

### Func ParsePEM
```go
func ParsePEM(pemData []byte) (privateKeys, publicKeys, certs []*pem.Block)
```
ParsePEM parses private keys and certificates from the provided PEM data.

### Func ParsePrivateKeyDER
```go
func ParsePrivateKeyDER(der []byte) (crypto.Signer, error)
```
ParsePrivateKeyDER parses a DER encoded private key. It tries PKCS#1,
PKCS#8 and then SEC 1 for EC keys.

### Func ParseSignatureAlgorithm
```go
func ParseSignatureAlgorithm(name string) (x509.SignatureAlgorithm, error)
```
ParseSignatureAlgorithm returns the x509.SignatureAlgorithm for the given
name, as returned by x509.SignatureAlgorithm.String(), e.g. "SHA256-RSA" or
"Ed25519". It returns an error if name does not match any known signature
algorithm.

### Func ParseSignatureScheme
```go
func ParseSignatureScheme(name string) (tls.SignatureScheme, error)
```
ParseSignatureScheme returns the tls.SignatureScheme for the given name,
as returned by tls.SignatureScheme.String(), e.g. "ECDSAWithP256AndSHA256".
It returns an error if name does not match any known signature scheme.

### Func ParseTLSVersion
```go
func ParseTLSVersion(name string) (uint16, error)
```
ParseTLSVersion returns the TLS version constant for the given name,
as returned by tls.VersionName, e.g. "TLS 1.3". It also accepts a "0x0304"-
style hex value (the fallback format tls.VersionName itself returns for
versions it does not recognize) or a plain decimal number (e.g. "772"), for
backwards compatibility with configs that specify the raw version number.
It returns an error if name does not match any of these forms.

### Func ReadAndParseCertsPEM
```go
func ReadAndParseCertsPEM(ctx context.Context, fs file.ReadFileFS, pemFile string) ([]*x509.Certificate, error)
```
ReadAndParseCertsPEM loads certificates from the specified PEM file.

### Func ReadAndParsePrivateKeyPEM
```go
func ReadAndParsePrivateKeyPEM(ctx context.Context, fs file.ReadFileFS, pemFile string) (crypto.Signer, error)
```
ReadAndParsePrivateKeyPEM reads and parses a PEM encoded private key from
the specified file.

### Func ReadBodyLimit
```go
func ReadBodyLimit(r *http.Request, replace bool, limit int64) ([]byte, error)
```
ReadBodyLimit reads the request body with a size limit and returns it as
a byte slice. If the body exceeds the limit ReadBodyLimit will return an
http.MaxBytesError. If replace is true, the request body is replaced with a
new reader that returns the same byte slice.

### Func RedirectPort80
```go
func RedirectPort80(ctx context.Context, redirects ...Port80Redirect) error
```
RedirectPort80 starts an http.Server that will redirect port 80 to the
specified redirect targets. The server will run in the background until the
supplied context is canceled.

### Func RemoteAddrFromClientHello
```go
func RemoteAddrFromClientHello(hello *tls.ClientHelloInfo) string
```
RemoteAddrFromClientHello returns the remote address of the connection from
the provided ClientHelloInfo. If the ClientHelloInfo or its Conn field is
nil, it returns an empty string.

### Func SafePath
```go
func SafePath(path string) error
```
SafePath checks if the given path is safe for use as a filename screening
for control characters, windows device names, relative paths, paths (eg.
a/b is not allowed) etc.

### Func SerialNumberHex
```go
func SerialNumberHex(serial *big.Int) string
```
SerialNumberHex formats a serial number as a hex string with leading zeros.

### Func SerialNumberOpenSSL
```go
func SerialNumberOpenSSL(serial *big.Int) string
```
SerialNumberOpenSSL formats a serial number in the same way as OpenSSL does.

### Func ServeTLSWithShutdown
```go
func ServeTLSWithShutdown(ctx context.Context, ln net.Listener, srv *http.Server, grace time.Duration) error
```
ServeTLSWithShutdown is like ServeWithShutdown except for a TLS server.
Note that any TLS options must be configured prior to calling this function
via the TLSConfig field in http.Server. If srv.BaseContext is nil it will be
set to return ctx.

### Func ServeWithShutdown
```go
func ServeWithShutdown(ctx context.Context, ln net.Listener, srv *http.Server, grace time.Duration) error
```
ServeWithShutdown runs srv.ListenAndServe in background and then waits for
the context to be canceled. It will then attempt to shutdown the web server
within the specified grace period. If srv.BaseContext is nil it will be set
to return ctx.

### Func TLSConfigUsingCertFiles
```go
func TLSConfigUsingCertFiles(certFile, keyFile string) (*tls.Config, error)
```
TLSConfigUsingCertFiles returns a tls.Config configured with the certificate
read from the supplied files.

### Func TLSConfigUsingCertFilesFS
```go
func TLSConfigUsingCertFilesFS(ctx context.Context, store file.ReadFileFS, certFile, keyFile string) (*tls.Config, error)
```
TLSConfigUsingCertFilesFS returns a tls.Config configured with the
certificate read from the supplied files which are accessed via the
specified file.ReadFileFS.

### Func TLSConfigUsingCertStore
```go
func TLSConfigUsingCertStore(ctx context.Context, store file.ReadFileFS, cacheOpts ...CertServingCacheOption) (*tls.Config, error)
```
TLSConfigUsingCertStore returns a tls.Config configured with the
certificate obtained from the specified certificate store accessed via a
CertServingCache created with the supplied options.

### Func VerifyCertChain
```go
func VerifyCertChain(dnsname string, certs []*x509.Certificate, roots *x509.CertPool) ([][]*x509.Certificate, error)
```
VerifyCertChain verifies the supplied certificate chain using the provided
root certificates and verifies that the leaf certificate is valid for the
specified dnsname. It returns the verified chains on success.

### Func WaitForServers
```go
func WaitForServers(ctx context.Context, interval time.Duration, addrs ...string) error
```
WaitForServers waits for all supplied addresses to be available by
attempting to open a TCP connection to each address at the specified
interval.

### Func WaitForURLs
```go
func WaitForURLs(ctx context.Context, client *http.Client, interval time.Duration, urls ...string) error
```
WaitForURLs waits for all supplied URLs to be available by attempting to
perform HTTP GET requests to each URL at the specified interval.



## Types
### Type CertServingCache
```go
type CertServingCache struct {
	// contains filtered or unexported fields
}
```
CertServingCache implements an in-memory cache of TLS/SSL certificates
loaded from a backing store. Validation of the certificates is performed
on loading rather than every use. It provides a GetCertificate method that
can be used by tls.Config. A TTL (default of 6 hours) is used so that the
in-memory cache will reload certificates from the store on a periodic basis
(with some jitter) to allow for certificates to be refreshed.

### Functions

```go
func NewCertServingCache(_ context.Context, certStore file.ReadFileFS, opts ...CertServingCacheOption) *CertServingCache
```
NewCertServingCache returns a new instance of CertServingCache that uses the
supplied file.ReadFileFS. The supplied context is a placeholder for future
use and is not currently used. The GetCertificate method uses the context in
the tls.ClientHelloInfo to read the certificate from the store.



### Methods

```go
func (m *CertServingCache) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
```
GetCertificate can be assigned to tls.Config.GetCertificate.




### Type CertServingCacheOption
```go
type CertServingCacheOption func(*CertServingCache)
```
CertServingCacheOption represents options to NewCertServingCache.

### Functions

```go
func WithCertCacheAllowedHosts(hosts ...string) CertServingCacheOption
```
WithCertCacheAllowedHosts sets the allowed hosts that the cache will serve
certificates for.


```go
func WithCertCacheNowFunc(fn func() time.Time) CertServingCacheOption
```
WithCertCacheNowFunc sets the function used to obtain the current time.
This is generally only required for testing purposes.


```go
func WithCertCacheRootCAs(rootCAs *x509.CertPool) CertServingCacheOption
```
WithCertCacheRootCAs sets the rootCAs to be used when verifying the validity
of the certificate loaded from the back store.


```go
func WithCertCacheTTL(ttl time.Duration) CertServingCacheOption
```
WithCertCacheTTL sets the in-memory TTL beyond which cache entries are
refreshed. This is generally only required for testing purposes.




### Type CipherSuites
```go
type CipherSuites []uint16
```
CipherSuites is a list of TLS cipher suite names, e.g.
"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" as returned by tls.CipherSuiteName.
When unmarshaled from YAML it accepts a list of such names, plus the
special name "insecure" which expands to every cipher suite returned by
tls.InsecureCipherSuites, and converts them to the corresponding crypto/tls
constants.

### Methods

```go
func (c CipherSuites) MarshalYAML() (any, error)
```
MarshalYAML implements yaml.Marshaler.


```go
func (c CipherSuites) String() string
```
String implements fmt.Stringer, returning a comma separated list of the
cipher suite names in c, as returned by tls.CipherSuiteName.


```go
func (c *CipherSuites) UnmarshalYAML(node *yaml.Node) error
```
UnmarshalYAML implements yaml.Unmarshaler.




### Type CounterAdd
```go
type CounterAdd func(ctx context.Context, delta float64)
```
CounterAdd is a function that adds a delta to a counter metric.


### Type CounterInc
```go
type CounterInc func(ctx context.Context)
```
CounterInc is a function that increments a counter metric.


### Type CounterVecAdd
```go
type CounterVecAdd func(ctx context.Context, delta float64, labels ...string)
```
CounterVecAdd is a function that adds a delta to a counter metric with the
given labels.


### Type CounterVecInc
```go
type CounterVecInc func(ctx context.Context, labels ...string)
```
CounterVecInc is a function that increments a counter metric with the given
labels.


### Type HTTPClientOption
```go
type HTTPClientOption func(o *httpClientOptions)
```
HTTPClientOption is used to configure an HTTP client.

### Functions

```go
func WithCustomCAPEMFile(caPEMFile string) HTTPClientOption
```
WithCustomCAPEMFile configures the HTTP client to use the specified custom
CA PEM data as a root CA.


```go
func WithCustomCAPool(caPool *x509.CertPool) HTTPClientOption
```
WithCustomCAPool configures the HTTP client to use the specified custom CA
pool. It takes precedence over WithCustomCAPEMFile.


```go
func WithDNSServer(addr string) HTTPClientOption
```
WithDNSServer configures the HTTP client to send all of its DNS resolution
requests to the DNS server at the specified address, rather than using the
system's default resolver. addr may be a bare IP address, in which case the
standard DNS port (53) is used, or an address that includes an explicit
port.


```go
func WithTracingTransport(to ...httptracing.TraceRoundtripOption) HTTPClientOption
```
WithTracingTransport configures the HTTP client to use a tracing round
tripper with the specified options.




### Type HTTPServerConfig
```go
type HTTPServerConfig struct {
	Address  string        `yaml:"address,omitempty"`
	TLSCerts TLSCertConfig `yaml:"tls_certs,omitempty"`
}
```
HTTPServerConfig defines configuration for an http server.

### Methods

```go
func (hc HTTPServerConfig) TLSConfig() (*tls.Config, error)
```




### Type HTTPServerError
```go
type HTTPServerError string
```
HTTPServerError is an error that is returned by the HTTP server to the
client and logged using ctxlog. The value of the error is used to identify
the error in logs using the key 'error_src'. In addition, a random 64-bit
integer is generated for each error and included in the response body and
logs using the key 'error_id'.

### Methods

```go
func (e HTTPServerError) BadRequest(w http.ResponseWriter, r *http.Request, m string, args ...any)
```


```go
func (e HTTPServerError) Forbidden(w http.ResponseWriter, r *http.Request, m string, args ...any)
```


```go
func (e HTTPServerError) Internal(w http.ResponseWriter, r *http.Request, m string, args ...any)
```


```go
func (e HTTPServerError) NotFound(w http.ResponseWriter, r *http.Request, m string, args ...any)
```


```go
func (e HTTPServerError) SendAndLog(w http.ResponseWriter, r *http.Request, status int, m string, args ...any)
```
SendAndLog sends the error to the client and logs it using ctxlog.


```go
func (e HTTPServerError) Unauthorized(w http.ResponseWriter, r *http.Request, m string, args ...any)
```




### Type HTTPServerFlags
```go
type HTTPServerFlags struct {
	Address string `subcmd:"https,:8080,address to run https web server on"`
	TLSCertFlags
}
```
HTTPServerFlags defines commonly used flags for running an http server.
TLS certificates may be retrieved either from a local cert and key file as
specified by tls-cert and tls-key; this is generally used for testing or
when the domain certificates are available only as files. The altnerative,
preferred for production, source for TLS certificates is from a cache as
specified by tls-cert-cache-type and tls-cert-cache-name. The cache may be
on local disk, or preferably in some shared service such as Amazon's Secrets
Service.

### Methods

```go
func (cl HTTPServerFlags) HTTPServerConfig() HTTPServerConfig
```
HTTPServerConfig returns an HTTPServerConfig based on the supplied flags.




### Type Observe
```go
type Observe func(ctx context.Context, value float64)
```
Observe is a function that records a value for an observer metric.


### Type Port80Redirect
```go
type Port80Redirect struct {
	Pattern string
	Redirect
}
```
Port80Redirect is a Redirect that that will be registered using
http.ServeMux with the specified pattern.


### Type Redirect
```go
type Redirect struct {
	Description string         // description of the redirect, only used for logging
	Target      RedirectTarget // function that returns the target URL and HTTP status code
	Log         bool           // if true then log the redirect
}
```
Redirect defines a URL path prefix which will be redirected to the specified
target.

### Functions

```go
func RedirectAcmeHTTP01(host string) Redirect
```
RedirectAcmeHTTP01 returns a Redirect that will redirect ACME HTTP-01
challenges to the specified host.


```go
func RedirectToHTTPSPort(addr string) Redirect
```
RedirectToHTTPSPort returns a Redirect that will redirect to the specified
address using https but with the following defaults: - if addr does not
contain a host then the host from the request is used - if addr does not
contain a port then port 443 is used.



### Methods

```go
func (r Redirect) Handler() http.HandlerFunc
```
Handler returns a function that will redirect requests using the Target
function to determine the target URL and HTTP status code and will log the
redirect. It is provided for use with other middleware packages that expect
an http.Handler.




### Type RedirectTarget
```go
type RedirectTarget func(*http.Request) (string, int)
```
RedirectTarget is a function that given an http.Request returns the target
URL for the redirect and the HTTP status code to use. The request and in
particular the Request.URL should not be modified by RedirectTarget.

### Functions

```go
func LiteralRedirectTarget(to string, code int) RedirectTarget
```
LiteralRedirectTarget returns a RedirectTarget that always redirects to the
specified URL with the specified status code.




### Type ServeFSWithHeaders
```go
type ServeFSWithHeaders struct {
	// contains filtered or unexported fields
}
```
ServeFSWithHeaders is an http.Handler that serves files from an fs.FS with
specified headers for specific URL paths.

### Functions

```go
func NewServeFSWithHeaders(fs fs.FS, next http.Handler, rewrite func(string) string) *ServeFSWithHeaders
```
NewServeFSWithHeaders creates a new ServeFSWithHeaders handler that serves
files from the provided fs.FS. The urlpaths registered via SetHeaders are
used to look up which headers to apply; the optional rewrite function is
applied to the URL path at registration time to produce the FS file path.

A leading '/' is stripped from the (possibly rewritten) path so URL paths
like "/index.html" map naturally to FS paths like "index.html".

The next handler is called for any URL path for which SetHeaders has not
been called. If next is nil such requests are answered with 404 Not Found.



### Methods

```go
func (s *ServeFSWithHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request)
```


```go
func (s *ServeFSWithHeaders) SetHeaders(headers http.Header, urlpaths ...string)
```
SetHeaders registers headers for the given URL paths. The FS path for each
URL path is computed once here (applying rewrite if set, then stripping a
leading '/'), so ServeHTTP never derives a file path from request data.
If headers is empty the file is served via http.ServeFileFS without extra
headers.




### Type ServeWithHeaders
```go
type ServeWithHeaders struct {
	// contains filtered or unexported fields
}
```
ServeWithHeaders is an http.Handler that serves a byte slice with specified
headers and only supports GET requests to a specific URL path.

### Functions

```go
func NewServeWithHeaders(headers http.Header, data []byte, urlpath string) ServeWithHeaders
```
NewServeWithHeaders creates a new ServeWithHeaders handler.



### Methods

```go
func (s ServeWithHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request)
```
ServeHTTP serves the file with the specified headers. If the requested URL
path does not match the handler's URL path, it responds with 404 Not Found.


```go
func (s ServeWithHeaders) URLPath() string
```
URLPath returns the URL path that this handler serves.




### Type SignatureAlgorithms
```go
type SignatureAlgorithms []x509.SignatureAlgorithm
```
SignatureAlgorithms is a list of x509 signature algorithm names, e.g.
"SHA256-RSA" as returned by x509.SignatureAlgorithm.String(). When
unmarshaled from YAML it accepts a list of such names, plus the special
shortnames "rsa", "dsa", "ecdsa", "ed25519" and "rsa-pss" which each expand
to every algorithm of that type, and converts them to the corresponding
crypto/x509 constants.

### Methods

```go
func (s SignatureAlgorithms) MarshalYAML() (any, error)
```
MarshalYAML implements yaml.Marshaler.


```go
func (s SignatureAlgorithms) String() string
```
String implements fmt.Stringer, returning a comma separated
list of the signature algorithm names in s, as returned by
x509.SignatureAlgorithm.String().


```go
func (s *SignatureAlgorithms) UnmarshalYAML(node *yaml.Node) error
```
UnmarshalYAML implements yaml.Unmarshaler.




### Type TLSCertConfig
```go
type TLSCertConfig struct {
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
}
```
TLSCertConfig defines configuration for TLS certificates obtained from local
files.

### Methods

```go
func (tc TLSCertConfig) TLSConfig() (*tls.Config, error)
```
TLSConfig returns a tls.Config.




### Type TLSCertFlags
```go
type TLSCertFlags struct {
	CertFile string `subcmd:"tls-cert,,tls certificate file"`
	KeyFile  string `subcmd:"tls-key,,tls private key file"`
}
```
TLSCertFlags defines commonly used flags for obtaining TLS/SSL certificates.
Certificates may be obtained in one of two ways: from a cache of
certificates, or from local files.

### Methods

```go
func (cl TLSCertFlags) TLSCertConfig() TLSCertConfig
```
Config returns a TLSCertConfig based on the supplied flags.




### Type TLSCurves
```go
type TLSCurves []tls.CurveID
```
TLSCurves is a list of TLS curve/group names, e.g. "CurveP256" or "X25519"
as returned by tls.CurveID.String(). When unmarshaled from YAML it accepts
a list of such names and converts them to the corresponding crypto/tls
constants.

### Methods

```go
func (c TLSCurves) MarshalYAML() (any, error)
```
MarshalYAML implements yaml.Marshaler.


```go
func (c TLSCurves) String() string
```
String implements fmt.Stringer, returning a comma separated list of the
curve/group names in c, as returned by tls.CurveID.String().


```go
func (c *TLSCurves) UnmarshalYAML(node *yaml.Node) error
```
UnmarshalYAML implements yaml.Unmarshaler.




### Type TLSSignatureSchemes
```go
type TLSSignatureSchemes []tls.SignatureScheme
```
TLSSignatureSchemes is a list of TLS signature scheme names, e.g.
"ECDSAWithP256AndSHA256" as returned by tls.SignatureScheme.String().
When unmarshaled from YAML it accepts a list of such names and converts them
to the corresponding crypto/tls constants.

### Methods

```go
func (s TLSSignatureSchemes) MarshalYAML() (any, error)
```
MarshalYAML implements yaml.Marshaler.


```go
func (s TLSSignatureSchemes) String() string
```
String implements fmt.Stringer, returning a comma separated list of the
signature scheme names in s, as returned by tls.SignatureScheme.String().


```go
func (s *TLSSignatureSchemes) UnmarshalYAML(node *yaml.Node) error
```
UnmarshalYAML implements yaml.Unmarshaler.




### Type TLSVersion
```go
type TLSVersion uint16
```
TLSVersion is a single TLS version, e.g. "TLS 1.3" as returned by
tls.VersionName. When unmarshaled from YAML it accepts such a name,
or a "0x..." hex value for a version tls.VersionName does not recognize,
and converts it to the corresponding uint16 version number.

### Methods

```go
func (v TLSVersion) MarshalYAML() (any, error)
```
MarshalYAML implements yaml.Marshaler.


```go
func (v TLSVersion) String() string
```
String implements fmt.Stringer, returning the version name, as returned by
tls.VersionName.


```go
func (v *TLSVersion) UnmarshalYAML(node *yaml.Node) error
```
UnmarshalYAML implements yaml.Unmarshaler.




### Type TLSVersions
```go
type TLSVersions []uint16
```
TLSVersions is a list of TLS version names, e.g. "TLS 1.3" as returned by
tls.VersionName. When unmarshaled from YAML it accepts a list of such names,
or "0x..." hex values for versions tls.VersionName does not recognize,
and converts them to the corresponding uint16 version numbers.

### Methods

```go
func (v TLSVersions) MarshalYAML() (any, error)
```
MarshalYAML implements yaml.Marshaler.


```go
func (v TLSVersions) String() string
```
String implements fmt.Stringer, returning a comma separated list of the
version names in v, as returned by tls.VersionName.


```go
func (v *TLSVersions) UnmarshalYAML(node *yaml.Node) error
```
UnmarshalYAML implements yaml.Unmarshaler.






## Examples
### [ExampleServeWithShutdown](https://pkg.go.dev/cloudeng.io/webapp?tab=doc#example-ServeWithShutdown)

### [ExampleHTTPServerError](https://pkg.go.dev/cloudeng.io/webapp?tab=doc#example-HTTPServerError)




## External Markdown Files Included Here

### Code Review: jwtutil-config branch (main...jwtutil-config) (code_review.md)

Review level: **high** (recall-biased, 8-angle finder + 1-vote verification)

Scope: `webauth/jwtutil/{config_cookies,config_signer,jwk_impl,jwt_config,key_registry,
jwt_issuer,jwt_url,signer}.go` and their tests, plus small call-site updates in
`webauth/webauthn/passkeys` and `websec`. This branch replaces the old
`NewED25519Signer(priv, id)` API with a `keys.Info`/`keys.InMemoryKeyStore`-backed
key-management layer (`NewED25519KeyInfo`, `JWKKey`/`ED25519`, `JWTSignerConfig`,
`JWTVerifierConfig`, `JWTCookieSignerConfig`, `JWTCookieVerifierConfig`,
`CookieSigner`, `CookieVerifier`), and adds reserved-JWT-claim protection to both
the new cookie signer and the existing `JWTIssuer` handler.

`go build ./...`, `go vet ./...` and `go test ./webauth/... ./websec/...` all pass
on this branch, so every finding below is a latent/edge-case issue rather than a
build or existing-test failure.

#### Security review

A separate, dedicated security-focused pass (own sub-agent, ≥80%-confidence-of-exploitability
bar) covered the same files: reserved-claim injection is blocked (`isReservedClaim` in both
`config_cookies.go` and `jwt_issuer.go`); key-ID/algorithm binding is enforced (`keySetForKeys`
pins `kid`/`alg`, defeating algorithm-confusion/key-substitution attacks); audience/issuer
enforcement in `NewVerifier`/`NewCookieVerifier` is correct (requires at least one configured
audience to match, not all); cookies unconditionally set `Secure`/`HttpOnly`/`SameSite=Strict`;
key material is zeroed after use with correct `slices.Clone` handling around `jwk.Import`'s
non-cloning public-key path; Ed25519 keys are generated via `crypto/rand`. **No high-confidence
security vulnerability was found.**

Two sub-threshold (6/10 confidence) API-misuse footguns are noted for awareness only — not
exploitable via attacker input, only via a downstream implementer misusing a documented,
partial-guarantee API:
- **`JWTSignerConfig.Builder`** (`config_signer.go:265-272`) only sets the `exp` claim
  `if expiresIn > 0`; since `jwx/v3` doesn't require `exp` to be present, a direct caller passing
  a zero/unset duration gets a never-expiring token. (The hardened `CookieSigner.NewToken` path is
  unaffected — `JWTCookieSignerConfig.Validate` requires `Duration > 0`.)
- **`NewValidator`/`ValidatorForKeys`** (`config_signer.go:286-308`) intentionally skip
  issuer/audience checks (documented), but are built from the same `JWTVerifierConfig` as
  `NewVerifier`, so a naming mix-up could lead a caller to accept a signature-valid token meant
  for a different issuer/audience.

No action required for security; both footguns above are optional hardening only.

#### Findings (JSON)

All four findings below have been addressed and re-verified (`go build ./...`, `go vet ./...`,
and `go test ./webauth/... ./websec/...` all pass after the fixes):

```json
[
  {
    "file": "webauth/jwtutil/key_registry.go",
    "line": 104,
    "status": "fixed",
    "summary": "decodeBase64 only trims leading/trailing whitespace, not embedded newlines, so a base64 key value that spans multiple lines is rejected even though the package explicitly claims to support that case.",
    "failure_scenario": "An operator authors a signing/verification key in YAML using a wrapped literal block scalar (a common way to keep a long base64 token readable in a config file), e.g. `token: |\\n  QUJDRA==\\n  QUJDRA==`. bytes.TrimSpace only strips the outer whitespace, so the embedded '\\n' is passed straight into base64.StdEncoding.Decode, which returns \"illegal base64 data at input byte N\". ED25519.Signer/ED25519.PublicKey (and therefore JWTSignerConfig.NewSigner / verification key loading) reject an otherwise-valid key, and the failure only shows up once someone formats their YAML this way -- something the package's own TestDecodeBase64Whitespace claims to cover (\"whitespace or newlines (e.g. from YAML block scalars)\") but only actually exercises leading/trailing whitespace, not an embedded line break, so the gap is untested.",
    "fix": "decodeBase64 now strips all whitespace via bytes.Map + unicode.IsSpace instead of bytes.TrimSpace. TestDecodeBase64Whitespace extended to embed a newline in the middle of the encoded private key (simulating a wrapped YAML block scalar); TestConfigInvalidKeys's \"not base64 encoded\" negative case (\"this is not a key!\") still correctly fails to decode, since '!' remains an illegal base64 character after whitespace stripping."
  },
  {
    "file": "webauth/jwtutil/config_test.go",
    "line": 2076,
    "status": "fixed (by user, verified correct)",
    "summary": "TestPublicKeyFromKeyInfoErrors constructs keys.NewInfo(testKeyID, testKeyUser, nil) with the user and id arguments transposed (keys.NewInfo takes (user, id, token)), unlike the correct storeKey(ctx, spec, token, extra) helper used everywhere else in the same file.",
    "failure_scenario": "testKeyID (\"jwt-signing-key\") ends up in the User field and testKeyUser (\"tester\") ends up in the ID field of the resulting keys.Info. The test still passes today because PublicKeyFromKeyInfo never checks the identity against an expectation, but the mistake means the test isn't exercising the key identity it appears to be, and the same transposition pattern recurs in three other files added/touched by this branch (see below), suggesting it is a systematic copy/paste slip in the New(ED25519KeyInfo(user, id)/keys.NewInfo(user, id, token) migration rather than an isolated typo.",
    "fix": "Now keys.NewInfo(testKeyUser, testKeyID, nil), matching keys.NewInfo(user, id, token)."
  },
  {
    "file": "websec/localhost_test.go",
    "line": 471,
    "status": "fixed (websec/example_test.go was fixed by user; localhost_test.go and passkey_server_test.go were still unfixed and have now been fixed here)",
    "summary": "setupSigner calls jwtutil.NewED25519KeyInfo(\"test-key-id\", \"test-user\") with the arguments swapped relative to their names -- NewED25519KeyInfo(user, id) receives \"test-key-id\" as the user and \"test-user\" as the id, the opposite of what the variable names suggest was intended (and the opposite of the previous NewED25519Signer(priv, \"test-key-id\") call it replaces, which used \"test-key-id\" as the key ID).",
    "failure_scenario": "No test currently asserts on the resulting key's ID/User, so the swap is silent today. But it means the signing key that setupSigner produces is now keyed by ID \"test-user\" instead of \"test-key-id\": if a future test starts asserting a JWKS `kid` value, does a per-user key lookup, or copies this call as a template for a new test, it will silently pick up the wrong identifier. The identical transposition appears in websec/example_test.go:16 (`NewED25519KeyInfo(\"key\", \"user\")`) and webauth/webauthn/passkeys/passkey_server_test.go:98 (`NewED25519KeyInfo(\"pkid\", \"test-user\")`, which used to be the *key ID* \"pkid\" under the old NewED25519Signer(priv, \"pkid\") call and is now silently the *user*).",
    "fix": "websec/example_test.go -> NewED25519KeyInfo(\"user\", \"key\"). websec/localhost_test.go setupSigner -> NewED25519KeyInfo(\"test-user\", \"test-key-id\"). webauth/webauthn/passkeys/passkey_server_test.go -> NewED25519KeyInfo(\"test-user\", \"pkid\"), preserving \"pkid\" as the key ID as in the pre-migration behaviour."
  },
  {
    "file": "webauth/jwtutil/signer.go",
    "line": 27,
    "status": "fixed (by user, verified correct); the unrelated pre-existing build error in the same file (see fix note) has also now been fixed",
    "summary": "NewED25519Signer(priv, id) was removed with no replacement of the same shape, but webauth/webauthn/passkeys/run_test_server.go (a //go:build ignore demo/manual-test program) still calls jwtutil.NewED25519Signer(pubKey, privKey, \"pkid\") and is therefore permanently uncompilable even for its intended manual use (`go run run_test_server.go <host:port>`).",
    "failure_scenario": "That file already didn't compile before this branch (it passes 3 args to what was a 2-arg function), so `go build ./...`/CI were never affected either way, but this diff finishes removing any function of that name, so the file can no longer be trivially fixed by correcting the argument count -- it needs to be rewritten against NewED25519KeyInfo/ED25519{}.Signer (as the other three call sites in this diff were) or deleted. Left as-is, anyone who tries to run the passkeys demo server per its own doc comment gets a build failure with no obvious pointer to the new API.",
    "fix": "run_test_server.go now builds its key via jwtutil.NewED25519KeyInfo(\"user\", \"key\") + jwtutil.ED25519{}.Signer(ki), matching the pattern used elsewhere in this diff. Additionally fixed the separate, pre-existing (predates this branch) bug where webapp.NewTLSServer was called with 3 args (string, *http.ServeMux, *tls.Config) instead of its actual signature (context.Context, string, http.Handler, *tls.Config) -- the already-in-scope `ctx` is now passed as the first argument. `go build -o /dev/null ./webauth/webauthn/passkeys/run_test_server.go` now succeeds."
  }
]
```

#### Remediation plan

1. **Fix `decodeBase64` to tolerate embedded newlines/whitespace (key_registry.go).**
   - Strip *all* whitespace, not just the leading/trailing run, before decoding,
     e.g. `bytes.Map(func(r rune) rune { if unicode.IsSpace(r) { return -1 }; return r }(...))`
     or filter with `strings.Fields`/`bytes.ReplaceAll` for `\n`, `\r`, `\t`, and
     interior spaces.
   - Extend `TestDecodeBase64Whitespace` (config_test.go) with a case that embeds
     an internal newline (simulating a wrapped YAML literal block scalar) so the
     regression is caught going forward — the current test only covers
     leading/trailing whitespace despite its doc comment claiming block-scalar
     coverage.
   - Re-run `TestConfigSigningKeyEncoding`/`TestConfigInvalidKeys` to confirm the
     "not base64 encoded" negative case (which relies on illegal characters,
     including a space, being rejected) still fails as expected after loosening
     whitespace handling.

2. **Fix the transposed `user`/`id` arguments.**
   - `webauth/jwtutil/config_test.go`: change
     `keys.NewInfo(testKeyID, testKeyUser, nil)` to
     `keys.NewInfo(testKeyUser, testKeyID, nil)` in `TestPublicKeyFromKeyInfoErrors`.
   - `websec/example_test.go`: change `jwtutil.NewED25519KeyInfo("key", "user")`
     to `jwtutil.NewED25519KeyInfo("user", "key")` (or clearer literal names).
   - `websec/localhost_test.go` (`setupSigner`): change
     `jwtutil.NewED25519KeyInfo("test-key-id", "test-user")` to
     `jwtutil.NewED25519KeyInfo("test-user", "test-key-id")` so the key's ID
     matches what the variable name (and the pre-migration `NewED25519Signer(priv,
     "test-key-id")` call) implies.
   - `webauth/webauthn/passkeys/passkey_server_test.go`: change
     `jwtutil.NewED25519KeyInfo("pkid", "test-user")` to
     `jwtutil.NewED25519KeyInfo("test-user", "pkid")` to preserve "pkid" as the
     key ID, matching the original `NewED25519Signer(privKey, "pkid")` behaviour
     it replaces.
   - After fixing, grep the rest of the branch's `NewED25519KeyInfo(...)` call
     sites (config_test.go's own helpers are correct and can be used as the
     template) to confirm no other instance of the swap was missed.

3. **Repair or retire `run_test_server.go`.**
   - Preferred: update it to build a key via `jwtutil.NewED25519KeyInfo` +
     `jwtutil.ED25519{}.Signer(...)` (mirroring the fix already applied to
     `passkey_server_test.go` and `websec/example_test.go` in this same diff), or
     use `jwtutil.NewSignerFromContext`/`SignerForKey` for a more representative
     example of the new config-driven flow.
   - Alternative: if the demo is stale/unmaintained, delete it rather than leave
     dead, non-compiling example code referencing a removed API — the
     `//go:build ignore` tag means CI will never catch further drift.

4. **Document the `NewED25519Signer` removal as a breaking API change** in the
   branch's PR description/changelog (the README.md diff already documents the
   new API surface, but doesn't call out that `NewED25519Signer` is gone) so
   downstream consumers of `cloudeng.io/webapp/webauth/jwtutil` know to migrate
   to `NewED25519KeyInfo` + `NewSignerFromKeyInfo`/`ED25519{}.Signer`.

#### Notes on things that looked suspicious but checked out

- `NewCookieSigner` adds `signer.PublicKey()` to its internal verification
  `jwk.Set` without explicitly setting a `kid`, unlike `keySetForKeys` which
  does. This is safe: `jwk.Import`'s OKP `PublicKey()` path copies every field
  (including `kid`) from the private key it was derived from, so the key ID set
  by `NewSigner` on the private key survives onto the public key. Confirmed by
  reading `jwk/okp.go`'s `makeOKPPublicKey` and by the passing
  `TestCookieSignerAndVerifier`/`TestCookieValidationTimeSkew` tests.
- `ED25519.Signer` decodes the private key into a buffer that is zeroed via a
  deferred `cleanup()` after `jwk.Import` runs. This does not corrupt the
  imported key because `ed25519.PrivateKey.Seed()`/`.Public()` (called inside
  `jwk.Import`'s OKP private-key path) copy the bytes rather than aliasing the
  input slice — unlike the public-key import path, which the code correctly
  works around with an explicit `slices.Clone` (see the comment in
  `ED25519.PublicKey`).
- `Verifier.validateOptions` clones `v.opts` before appending per-call
  validators (`append(slices.Clone(v.opts), validators...)`), which correctly
  avoids a data race across concurrent `Validate` calls that would otherwise be
  possible if `append` reused `v.opts`'s backing array.


