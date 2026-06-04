# Package [cloudeng.io/webapp/testwebapp](https://pkg.go.dev/cloudeng.io/webapp/testwebapp?tab=doc)

```go
import cloudeng.io/webapp/testwebapp
```


## Variables
### ErrGoGetUnexpectedError, ErrGoGetPathNotFound, ErrGoGetNotFound, ErrGoGetContentMismatch
```go
ErrGoGetUnexpectedError = errors.New("go-get unexpected error")
ErrGoGetPathNotFound = errors.New("go-get path not found")
ErrGoGetNotFound = errors.New("go-get meta tag not found")
ErrGoGetContentMismatch = errors.New("go-get meta tag content mismatch")

```

### ErrRedirectUnexpectedError, ErrRedirectPathNotFound, ErrRedirectTargetMismatch, ErrRedirectStatusCodeMismatch
```go
ErrRedirectUnexpectedError = errors.New("redirect unexpected error")
ErrRedirectPathNotFound = errors.New("redirect path not found")
ErrRedirectTargetMismatch = errors.New("redirect target mismatch")
ErrRedirectStatusCodeMismatch = errors.New("redirect status code mismatch")

```

### ErrCheckStatusUnexpectedError, ErrCheckStatusCodeMismatch
```go
ErrCheckStatusUnexpectedError = errors.New("check status unexpected error")
ErrCheckStatusCodeMismatch = errors.New("check status code mismatch")

```

### ErrTLSSpecUnexpectedError, ErrTLSInvalidSerialNumbers, ErrTLSInvalidValidFor, ErrTLSInvalidIssuer
```go
ErrTLSSpecUnexpectedError = errors.New("tls unexpected error")
ErrTLSInvalidSerialNumbers = errors.New("tls invalid serial numbers")
ErrTLSInvalidValidFor = errors.New("tls invalid duration")
ErrTLSInvalidIssuer = errors.New("tls invalid issuer")

```



## Functions
### Func ClientMaxRedirects
```go
func ClientMaxRedirects(client *http.Client, maxRedirects int) *http.Client
```
ClientMaxRedirects returns a copy of the given client that follows up to
maxRedirects redirects.

### Func ClientNoRedirect
```go
func ClientNoRedirect(client *http.Client) *http.Client
```
ClientNoRedirect returns a copy of the given client that does not follow
redirects.



## Types
### Type CheckStatus
```go
type CheckStatus struct {
	// contains filtered or unexported fields
}
```
CheckStatus validates that a set of URLs return a given status code after
following up to a configurable number of redirects.

### Functions

```go
func NewCheckStatus(specs ...CheckStatusSpec) *CheckStatus
```
NewCheckStatus creates a new CheckStatus for the given specs.



### Methods

```go
func (c *CheckStatus) Run(ctx context.Context, client *http.Client) error
```




### Type CheckStatusSpec
```go
type CheckStatusSpec struct {
	URL       string `yaml:"url" json:"url"`
	Code      int    `yaml:"code" json:"code"`
	Redirects int    `yaml:"redirects" json:"redirects"`
}
```
CheckStatusSpec represents a specification for a status check after
following redirects.

### Functions

```go
func GenerateCheckStatusSpecs(urls []string, code int, redirects int) []CheckStatusSpec
```
GenerateCheckStatusSpecs generates a slice of CheckStatusSpec for the given
URLs, status code and number of redirects.




### Type GoGetTest
```go
type GoGetTest struct {
	// contains filtered or unexported fields
}
```
GoGetTest can be used to validate go-get meta tags for a set of import
paths.

### Functions

```go
func NewGoGetTest(specs ...goget.Spec) *GoGetTest
```



### Methods

```go
func (g GoGetTest) Run(ctx context.Context, client *http.Client) error
```




### Type HealthzSpec
```go
type HealthzSpec struct {
	URL             string        `yaml:"url" json:"url"`
	Interval        time.Duration `yaml:"interval" json:"interval"`
	Timeout         time.Duration `yaml:"timeout" json:"timeout"`
	NumHealthChecks int           `yaml:"num_health_checks" json:"num_health_checks"`
}
```


### Type HealthzTest
```go
type HealthzTest struct {
	// contains filtered or unexported fields
}
```
HealthzTest can be used to validate /healthz endpoints.

### Functions

```go
func NewHealthzTest(specs ...HealthzSpec) *HealthzTest
```



### Methods

```go
func (h HealthzTest) Run(ctx context.Context, client *http.Client) error
```




### Type MetricsReporter
```go
type MetricsReporter func(ctx context.Context, client *http.Client, url string, expectedMetrics []string) (found, missing []string, err error)
```


### Type MetricsSpec
```go
type MetricsSpec struct {
	URL         string   `yaml:"url,omitempty"`
	MetricNames []string `yaml:"names,omitempty"`
}
```


### Type MetricsTest
```go
type MetricsTest struct {
	// contains filtered or unexported fields
}
```
MetricsTest can be used to validate /metrics endpoints.

### Functions

```go
func NewMetricsTest(reporter MetricsReporter, specs ...MetricsSpec) *MetricsTest
```



### Methods

```go
func (m MetricsTest) Run(ctx context.Context, client *http.Client) error
```




### Type RedirectSpec
```go
type RedirectSpec struct {
	URL    string `yaml:"url" json:"url"`
	Target string `yaml:"target" json:"target"`
	Code   int    `yaml:"code" json:"code"`
}
```
RedirectSpec represents a specification for a redirect test.


### Type RedirectTest
```go
type RedirectTest struct {
	// contains filtered or unexported fields
}
```
RedirectTest can be used to validate redirects for a set of URLs.

### Functions

```go
func NewRedirectTest(redirects ...RedirectSpec) *RedirectTest
```
NewRedirectTest creates a new RedirectTest. The client's CheckRedirect
will be overridden to stop at the first redirect so that each hop can be
inspected.



### Methods

```go
func (r RedirectTest) Run(ctx context.Context, client *http.Client) error
```




### Type TLSSpec
```go
type TLSSpec struct {
	Host               string        `yaml:"host"`
	Port               string        `yaml:"port"`
	ExpandDNSNames     bool          `yaml:"expand-dns-names"`     // see tlsvalidate.WithExpandDNSNames
	CheckSerialNumbers bool          `yaml:"check-serial-numbers"` // see tlsvalidate.WithCheckSerialNumbers
	ValidFor           time.Duration `yaml:"valid-for"`            // see tlsvalidate.WithValidForAtLeast
	TLSMinVersion      uint16        `yaml:"tls-min-version"`      // see tlsvalidate.WithTLSMinVersion
	IssuerREs          []string      `yaml:"issuer-res"`           // see tlsvalidate.WithIssuerRegexps
	CustomCAPEM        string        `yaml:"custom-ca-pem"`        // used tlsvalidate.WithCustomRootCAPEM
	// contains filtered or unexported fields
}
```
TLSSpec represents a specification for a TLS test.

### Functions

```go
func LetsEncryptTLSSpec() TLSSpec
```


```go
func WithCustomCAPEMFile(s []TLSSpec, pemFile string) []TLSSpec
```
WithCustomCAPEMFile sets the custom CA PEM file for all specs if not already
set in each/any spec.




### Type TLSTest
```go
type TLSTest struct {
	// contains filtered or unexported fields
}
```
TLSTest can be used to validate TLS certificates for a set of hosts.

### Functions

```go
func NewTLSTest(specs ...TLSSpec) *TLSTest
```



### Methods

```go
func (t *TLSTest) Run(ctx context.Context) error
```







