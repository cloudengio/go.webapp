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

### Code Review: `jwtutil-config` vs `main` (code_review.md)

#### 1. Executive Summary

This code review evaluates the complete git diff between branch `jwtutil-config` and `main` across all 27 modified files. The branch introduces a comprehensive cryptographic key management architecture (`keys.Info`/`keys.InMemoryKeyStore`-backed), configuration-driven signers and validators (`JWTSignerConfig`, `JWTValidatorConfig`, `JWTCookieSignerConfig`, `JWTCookieValidatorConfig`), cookie-based issuance and verification (`CookieSigner`, `CookieVerifier`), and refactored HTTP security integration in `websec` and `webauthn/passkeys`.

All package test suites (`go test ./...`) pass and `golangci-lint` reports 0 issues. However, an in-depth review of the diff revealed **10 findings** across logic, performance, security, memory hygiene, and API ergonomics:
- **1 High-Severity Finding**: `validator.Parse` in `jwt_validator.go` fails to pass `jwt.WithValidate(false)`, which prematurely validates tokens, silently ignores clock skew (`jwt.WithAcceptableSkew`) in `ParseAndValidate`, and doubles token validation latency on every request.
- **2 Medium-Severity Findings**: Tokens issued by `CookieSigner` and `JWTSignerConfig.Builder` can lack an expiration claim (`exp`) because `JWTSignerConfig.Duration` has no default and is unvalidated; `JWTCookieConfig.Validate()` strictly forbids host-only cookies (empty domain) and empty paths, conflicting with standard cookie security practices and `SetDefaults`.
- **7 Low / Advisory Findings**: Inconsistent `Verifier` vs `Validator` terminology in cookie APIs; backward compatibility breaks (`WithClaim` and `NewED25519Signer` removed); `kid` missing from `PublicKeyFromKeyInfo`; lack of public key derivation fallback from private keys; un-zeroed heap slice in `decodeBase64`; lost request context in `websec` logs; and accidental inclusion of `code_review.md` in root `README.md`.

**No code fixes have been applied in this review step.**

---

#### 2. Findings Matrix

| ID | Category | Severity | File(s) & Lines | Status | Summary |
|---|---|---|---|---|---|
| **LOG-1** | Logic & Perf | **High** | [`jwt_validator.go:44-46`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_validator.go#L44-L46) | **Fixed** | `validator.Parse` omits `jwt.WithValidate(false)`, causing `ParseAndValidate` to ignore `WithAcceptableSkew` / `WithClock` and validating valid tokens twice. |
| **SEC-1** | Security | **Medium** | [`jwt_config.go:40, 91-102`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_config.go#L40), [`config_signer.go:40-45`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/config_signer.go#L40-L45) | **Fixed** | `JWTSignerConfig.Duration` defaults to 0 and is unvalidated, issuing never-expiring JWTs when cookie duration is configured alone or duration is omitted. |
| **LOG-2** | Logic & Security | **Medium** | [`jwt_config.go:20-34`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_config.go#L20-L34) | **Fixed** | `JWTCookieConfig.Validate()` requires `Domain != ""` and `Path != ""`, rejecting secure host-only cookies and contradicting `SetDefaults("", "/", 0)`. |
| **API-1** | API Ergonomics | **Low** | [`config_cookies.go:99, 181, 189`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/config_cookies.go#L99) | **Fixed** | Mismatched naming convention: `JWTCookieValidatorConfig` has `NewCookieVerifier` returning `*CookieVerifier`, and `JWTCookieSignerConfig` has `VerifierConfig()`. |
| **API-2** | Backward Compat | **Low** | [`jwt_issuer.go:100`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_issuer.go#L100) | Deferred | `WithClaim(key, value)` was removed in favor of `WithClaims(map)`, breaking existing callers setting single claims. |
| **API-3** | Backward Compat | **Low** | [`signer.go:1-120`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/signer.go) (deleted) | Deferred | `NewED25519Signer(priv, id)` was removed, breaking external callers holding raw `ed25519.PrivateKey` instances. |
| **ROB-1** | Robustness | **Low** | [`jwk_impl.go:74-110`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwk_impl.go#L74-L110) | **Fixed** | `ED25519.PublicKey` does not set `kid` on returned `jwk.Key`, causing verification failure if `PublicKeyFromKeyInfo` is added to a `jwk.Set` directly. |
| **ROB-2** | Robustness | **Low** | [`jwk_impl.go:78-81`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwk_impl.go#L78-L81) | **Fixed** | `ED25519.PublicKey` errors if `extra.PublicKey == ""` even when `info.Token()` contains the 64-byte private key from which the public key is trivially derivable. |
| **SEC-2** | Memory Hygiene | **Low** | [`key_registry.go:140-158`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/key_registry.go#L140-L158) | **Fixed** | `decodeBase64` leaves heap-allocated `trimmed` slice containing ASCII private key base64 data un-zeroed in memory after `cleanup()`. |
| **OBS-1** | Observability | **Low** | [`websec/localhost.go:352, 355, 376`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/websec/localhost.go#L352) | Deferred | Logging calls inside HTTP handler dropped `r.Context()`, discarding request trace IDs and span IDs. |

---

#### 3. Detailed Findings

##### LOG-1: `validator.Parse` Omits `jwt.WithValidate(false)`, Breaking Clock Skew in `ParseAndValidate` and Doubling Validation Latency
- **Location**: [`webauth/jwtutil/jwt_validator.go:44-46`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_validator.go#L44-L46)
- **Problem**:
  In `jwt_validator.go`:
  ```go
  func (v validator) Parse(_ context.Context, tokenBytes []byte) (jwt.Token, error) {
      return jwt.Parse(tokenBytes, jwt.WithKeySet(v.set))
  }
  ```
  In `jwx/v3/jwt`, `jwt.Parse` runs automatic validation by default (`jwt.Validate` against `time.Now()` with 0 clock skew).
- **Failure Scenario**:
  1. A caller invokes `validator.ParseAndValidate(ctx, tokenBytes, jwt.WithAcceptableSkew(time.Minute))`.
  2. `v.ParseAndValidate` first calls `v.Parse(ctx, tokenBytes)`.
  3. `v.Parse` runs `jwt.Parse` without `jwt.WithValidate(false)`. If the token expired 5 seconds ago, `v.Parse` immediately fails with `"exp" not satisfied: token is expired`.
  4. Execution never reaches `v.Validate(ctx, token, validators...)`. The caller's `jwt.WithAcceptableSkew(time.Minute)` is completely ignored.
  5. Furthermore, when a token is valid, `v.Parse` fully validates the claims once, and `v.Validate` validates them a second time, doubling token validation CPU cost on every request.
- **Contrast**:
  Both [`config_cookies.go:217-219`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/config_cookies.go#L217-L219) (`CookieVerifier.Parse`) and [`config_test.go:128-130`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/config_test.go#L128-L130) (`testVerifier.Parse`) explicitly pass `jwt.WithValidate(false)` and document:
  *"Parse verifies the signature of token and returns it without validating any of its claims, which is left to Validate so that opts (including any allowance for clock skew) are applied instead of jwt.Parse's own defaults."*
- **Recommended Fix**:
  In [`jwt_validator.go:45`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_validator.go#L45), change to:
  ```go
  return jwt.Parse(tokenBytes, jwt.WithKeySet(v.set), jwt.WithValidate(false))
  ```

---

##### SEC-1: `JWTSignerConfig.Duration` Has No Default and Is Unvalidated, Issuing Never-Expiring JWTs
- **Location**: [`webauth/jwtutil/jwt_config.go:40, 91-102`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_config.go#L40), [`config_signer.go:40-45`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/config_signer.go#L40-L45), [`config_cookies.go:129-130`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/config_cookies.go#L129-L130)
- **Problem**:
  In `JWTSignerConfig`:
  ```go
  Duration time.Duration `yaml:"jwt_duration" doc:"duration,24h,validity duration of the issued JWT"`
  ```
  The struct tag documentation indicates a 24h default, but YAML/Go unmarshaling does not apply default values from doc tags, and `JWTSignerConfig.Validate()` does not enforce `Duration > 0`.
  In `JWTSignerConfig.Builder`:
  ```go
  if expiresIn <= 0 {
      expiresIn = c.Duration
  }
  if expiresIn > 0 {
      builder.Expiration(now.Add(expiresIn))
  }
  ```
- **Failure Scenario**:
  In `JWTCookieSignerConfig`, `JWTCookieConfig.Duration` (cookie `Max-Age`) is validated > 0, but `JWTSignerConfig.Duration` is not. In standard YAML configurations such as `ExampleJWTCookieSignerConfig`:
  ```yaml
  cookie:
    name: session_token
    duration: 8h
  jwt_issuer: auth.example.com
  jwt_audience: [app.example.com]
  ```
  `JWTSignerConfig.Duration` is 0. When `CookieSigner.Issue` is called, it calls `NewToken(subject, claims)` which executes `cs.cfg.Builder(0)`. Because `expiresIn` is 0 and `c.Duration` is 0, **no `exp` claim is added to the JWT**. The browser cookie expires in 8 hours, but the JWT itself never expires. If extracted from the cookie (or sent to API endpoints), it remains valid indefinitely.
- **Recommended Fix**:
  1. In `JWTCookieSignerConfig.NewCookieSigner`, if `c.JWTSignerConfig.Duration == 0`, default it to `c.JWTCookieConfig.Duration`.
  2. In `JWTSignerConfig.Builder`, if `expiresIn <= 0` and `c.Duration <= 0`, default to `24 * time.Hour` (matching the documented default), or require `Duration > 0` in `JWTSignerConfig.Validate()`.

---

##### LOG-2: `JWTCookieConfig.Validate()` Forbids Host-Only Cookies and Redundantly Requires Path
- **Location**: [`webauth/jwtutil/jwt_config.go:20-34`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_config.go#L20-L34)
- **Problem**:
  `JWTCookieConfig.Validate()` enforces:
  ```go
  if c.Domain == "" {
      return fmt.Errorf("cookie domain is required")
  }
  if c.Path == "" {
      return fmt.Errorf("cookie path is required")
  }
  ```
- **Failure Scenario**:
  1. In RFC 6265, an omitted `Domain` attribute creates a "host-only" cookie (the cookie is never sent to subdomains). Host-only cookies are a security best practice for web applications to protect against subdomain takeover or cross-subdomain attacks. Requiring `Domain != ""` forces operators to expose cookies across all subdomains.
  2. `NewCookieSigner` and `NewCookieVerifier` both call `c.ScopeAndDuration = c.SetDefaults("", "/", 0)`, which automatically defaults `Path` to `"/"`. Requiring `Path != ""` prior to `SetDefaults` prevents relying on standard default behavior.
  3. Because `JWTCookieConfig.Validate()` has these flaws, neither `JWTCookieSignerConfig.Validate()` nor `JWTCookieValidatorConfig.Validate()` call `c.JWTCookieConfig.Validate()`, leading to inconsistent validation paths.
- **Recommended Fix**:
  Update `JWTCookieConfig.Validate()`:
  - Remove `if c.Domain == ""` check to allow host-only cookies.
  - Allow empty `Path` (defaulting to `"/"` via `SetDefaults`) or require it only when `SetDefaults` is not used.
  - Have `JWTCookieSignerConfig.Validate()` and `JWTCookieValidatorConfig.Validate()` invoke `c.JWTCookieConfig.Validate()`.

---

##### API-1: Mismatched `Verifier` vs `Validator` Terminology
- **Location**: [`webauth/jwtutil/config_cookies.go:99, 181, 189`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/config_cookies.go#L99), [`jwt_config.go:106`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_config.go#L106)
- **Problem**:
  Branch `jwtutil-config` renamed `JWTVerifierConfig` -> `JWTValidatorConfig`, `NewVerifier` -> `NewValidator`, and `VerifierForKeys` -> `ValidatorForKeys` to standardize on `Validator`.
  However, in `config_cookies.go`:
  - Struct is `JWTCookieValidatorConfig`, but its constructor is `NewCookieVerifier`.
  - Type returned is `*CookieVerifier`.
  - Helper method on `JWTCookieSignerConfig` is `VerifierConfig()`, but its return type is `JWTCookieValidatorConfig`.
- **Recommended Fix**:
  - Add type alias `type CookieValidator = CookieVerifier`.
  - Add constructor `func (c JWTCookieValidatorConfig) NewCookieValidator(...) (*CookieValidator, error)`.
  - Add method `func (c JWTCookieSignerConfig) ValidatorConfig() JWTCookieValidatorConfig`.
  - Retain `CookieVerifier`, `NewCookieVerifier`, and `VerifierConfig` for compatibility.

---

##### API-2: Removal of `WithClaim(key, value)`
- **Location**: [`webauth/jwtutil/jwt_issuer.go:100`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_issuer.go#L100)
- **Problem**:
  `WithClaim(key string, value any)` was removed in commit `1d5c4b0`, leaving only `WithClaims(map[string]any)`. Setting a single claim is the most frequent use case (e.g. `jwtutil.WithClaim("role", "admin")`). Removing it breaks existing call sites.
- **Recommended Fix**:
  Restore `WithClaim` as a convenience wrapper:
  ```go
  // WithClaim adds or replaces a custom claim in issued tokens. If key is a
  // reserved standard JWT claim, NewJWTIssuer returns ErrReservedClaim.
  func WithClaim(key string, value any) JWTIssuerOption {
      return WithClaims(map[string]any{key: value})
  }
  ```

---

##### API-3: Removal of `NewED25519Signer(priv, id)`
- **Location**: [`webauth/jwtutil/signer.go`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/signer.go) (deleted)
- **Problem**:
  Deleting `signer.go` dropped `NewED25519Signer(priv ed25519.PrivateKey, id string) (Signer, error)` from the public API. Callers possessing raw `ed25519.PrivateKey` objects (e.g. from KMS or secret stores) cannot easily construct a `Signer` without synthetic `keys.Info` overhead.
- **Recommended Fix**:
  Add `NewED25519Signer` to [`jwt_signer.go`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_signer.go):
  ```go
  func NewED25519Signer(priv ed25519.PrivateKey, id string) (Signer, error) {
      jwkKey, err := jwk.Import(priv)
      if err != nil {
          return nil, err
      }
      return NewSigner(jwkKey, id, jwa.EdDSA())
  }
  ```

---

##### ROB-1: `PublicKeyFromKeyInfo` Does Not Set `kid` on `jwk.Key`
- **Location**: [`webauth/jwtutil/jwk_impl.go:74-110`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwk_impl.go#L74-L110), [`key_registry.go:98-104`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/key_registry.go#L98-L104)
- **Problem**:
  `ED25519.Signer` sets `jwk.KeyIDKey` from `info.KeySpec().ID`. `ED25519.PublicKey` does not set `KeyIDKey`, relying on `KeySetForKeys` to set it.
  If a caller uses `PublicKeyFromKeyInfo(ctx, info)` directly and adds it to a `jwk.Set`, JWT verification fails because the public key lacks a `kid` matching the token header.
- **Recommended Fix**:
  In `ED25519.PublicKey`, if `info.KeySpec().ID != ""`, set `jwkKey.Set(jwk.KeyIDKey, info.KeySpec().ID)`.

---

##### ROB-2: `ED25519.PublicKey` Errors When `extra.PublicKey` Is Empty Even if Private Key Is Present
- **Location**: [`webauth/jwtutil/jwk_impl.go:78-81`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwk_impl.go#L78-L81)
- **Problem**:
  An Ed25519 private key is 64 bytes and inherently contains the 32-byte public key. If `extra.PublicKey` is empty in `keys.Info`, `ED25519.PublicKey` immediately returns an error rather than extracting the public key from the private key token.
- **Recommended Fix**:
  If `extra.PublicKey == ""` and `info.Token()` contains 64 bytes of private key material, extract `ed25519.PrivateKey(decoded).Public()` as a fallback before returning an error.

---

##### SEC-2: Un-zeroed Heap Slice in `decodeBase64`
- **Location**: [`webauth/jwtutil/key_registry.go:140-158`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/key_registry.go#L140-L158)
- **Problem**:
  `decodeBase64` allocates `trimmed := bytes.Map(...)` on the heap to filter whitespace. While `cleanup()` zeroes `decoded`, `trimmed` (which contains ASCII base64 private key data) remains un-zeroed in memory until garbage collected.
- **Recommended Fix**:
  In `cleanup()`, also zero `trimmed`:
  ```go
  cleanup := func() {
      for i := range decoded {
          decoded[i] = 0
      }
      for i := range trimmed {
          trimmed[i] = 0
      }
  }
  ```

---

##### OBS-1: Context Dropped From Logging in `websec/localhost.go`
- **Location**: [`websec/localhost.go:352, 355, 376`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/websec/localhost.go#L352)
- **Problem**:
  Logging calls inside HTTP request processing were switched from `WarnContext(r.Context(), ...)` to `Warn(...)`. This discards contextual trace IDs and request metadata from log entries.
- **Recommended Fix**:
  Revert to `h.opts.logger.WarnContext(r.Context(), ...)` in `verifyJWT` and `denyWithStatus`.

---

#### 4. Step-by-Step Remediation Plan

##### Step 1: Fix Core Validator Parsing & Skew Handling (LOG-1)
1. In [`webauth/jwtutil/jwt_validator.go`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_validator.go#L44-L46), add `jwt.WithValidate(false)` to `jwt.Parse` call in `validator.Parse`.
2. Add a test case in `jwtutil_test.go` verifying that `Validator.ParseAndValidate` correctly honors `jwt.WithAcceptableSkew` on expired tokens.

##### Step 2: Prevent Never-Expiring Tokens (SEC-1)
1. In [`webauth/jwtutil/config_cookies.go:76-89`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/config_cookies.go#L76-L89), in `NewCookieSigner`, if `c.JWTSignerConfig.Duration == 0`, default it to `c.JWTCookieConfig.Duration`.
2. In [`webauth/jwtutil/config_signer.go:40-45`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/config_signer.go#L40-L45), in `JWTSignerConfig.Builder`, if `expiresIn <= 0` and `c.Duration <= 0`, default `expiresIn = 24 * time.Hour`.
3. Add a unit test verifying that `CookieSigner.Issue` with only `cookie.duration` sets the `exp` claim on the generated token.

##### Step 3: Correct Cookie Configuration Validation (LOG-2)
1. In [`webauth/jwtutil/jwt_config.go:20-34`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_config.go#L20-L34), remove `c.Domain == ""` check and allow empty `c.Path` (delegating to `SetDefaults`).
2. Update `JWTCookieSignerConfig.Validate()` and `JWTCookieValidatorConfig.Validate()` to call `c.JWTCookieConfig.Validate()`.
3. Update `TestJWTCookieConfigValidate` in `config_test.go` to verify that empty domain produces valid host-only cookies.

##### Step 4: Harmonize Naming Across Cookie and Validator APIs (API-1)
1. In [`webauth/jwtutil/config_cookies.go`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/config_cookies.go), define `type CookieValidator = CookieVerifier`.
2. Add `func (c JWTCookieValidatorConfig) NewCookieValidator(...) (*CookieValidator, error)`.
3. Add `func (c JWTCookieSignerConfig) ValidatorConfig() JWTCookieValidatorConfig`.
4. Keep `CookieVerifier`, `NewCookieVerifier`, and `VerifierConfig` for backward compatibility.

##### Step 5: Restore Backward-Compatible Convenience APIs (API-2, API-3)
1. In [`webauth/jwtutil/jwt_issuer.go`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_issuer.go), restore `WithClaim(key string, value any) JWTIssuerOption`.
2. In [`webauth/jwtutil/jwt_signer.go`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwt_signer.go), restore `NewED25519Signer(priv ed25519.PrivateKey, id string) (Signer, error)`.
3. Add tests verifying both functions.

##### Step 6: Harden Key Management (ROB-1, ROB-2, SEC-2)
1. In [`webauth/jwtutil/jwk_impl.go`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/jwk_impl.go), set `jwk.KeyIDKey` in `ED25519.PublicKey` when `info.KeySpec().ID != ""`.
2. In `ED25519.PublicKey`, if `extra.PublicKey == ""` but `info.Token()` contains private key bytes, derive public key from private key.
3. In [`webauth/jwtutil/key_registry.go:148-154`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/webauth/jwtutil/key_registry.go#L148-L154), zero `trimmed` in `cleanup()`.

##### Step 7: Fix Request Context in Logger (OBS-1)
1. In [`websec/localhost.go`](file:///Users/cnicolaou/LocalOnly/dev/github.com/cloudengio/go.webapp/websec/localhost.go), change `h.opts.logger.Warn` back to `h.opts.logger.WarnContext(r.Context(), ...)`.

##### Step 8: Regenerate Documentation and Verify
1. Run `gomarkdown --overwrite ./webauth/jwtutil`.
2. Run `go test -v -count=1 ./...` across all packages.
3. Run `golangci-lint run -E gocyclo -E gocognit ./...`.


