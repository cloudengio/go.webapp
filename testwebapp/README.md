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

### ErrTLSSpecUnexpectedError, ErrTLSInvalidSerialNumbers, ErrTLSInvalidValidFor, ErrTLSInvalidIssuer
```go
ErrTLSSpecUnexpectedError = errors.New("tls unexpected error")
ErrTLSInvalidSerialNumbers = errors.New("tls invalid serial numbers")
ErrTLSInvalidValidFor = errors.New("tls invalid duration")
ErrTLSInvalidIssuer = errors.New("tls invalid issuer")

```



## Types
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
func NewGoGetTest(tlsClient *http.Client, specs ...goget.Spec) *GoGetTest
```



### Methods

```go
func (g GoGetTest) Run(ctx context.Context) error
```




### Type HealthzTest
```go
type HealthzTest struct {
	// contains filtered or unexported fields
}
```

### Functions

```go
func NewHealthzTest(client *http.Client, healthcheckURL string, interval time.Duration, numHealthChecks int) *HealthzTest
```



### Methods

```go
func (h HealthzTest) Run(ctx context.Context) error
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
func NewRedirectTest(client *http.Client, redirects ...RedirectSpec) *RedirectTest
```
NewRedirectTest creates a new RedirectTest, it if client.CheckRedirect is
nil, it will be set to http.ErrUseLastResponse to ensure that redirects are
not followed.



### Methods

```go
func (r RedirectTest) Run(ctx context.Context) error
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
	// contains filtered or unexported fields
}
```
TLSSpec represents a specification for a TLS test.


### Type TLSTest
```go
type TLSTest struct {
	// contains filtered or unexported fields
}
```
TLSTest can be used to validate TLS certificates for a set of hosts.

### Functions

```go
func NewTLSTest(client *http.Client, specs ...TLSSpec) *TLSTest
```



### Methods

```go
func (t *TLSTest) Run(ctx context.Context) error
```







