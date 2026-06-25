# Package [cloudeng.io/webapp/testwebapp](https://pkg.go.dev/cloudeng.io/webapp/testwebapp?tab=doc)

```go
import cloudeng.io/webapp/testwebapp
```


## Variables
### ErrNavigateUnexpectedError, ErrNavigateElementNotFound
```go
ErrNavigateUnexpectedError = errors.New("click unexpected error")
ErrNavigateElementNotFound = errors.New("click element not found")

```

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

### Func DrainRelayURL
```go
func DrainRelayURL[T any](ctx context.Context, client *http.Client, relayURL string, timeout time.Duration) ([]T, error)
```
DrainRelayURL collects all payloads from relayURL, decoding each as T.
It uses timeout as an idle deadline: after receiving a payload it resets the
timer, so a short queue returns quickly. It returns when no payload arrives
within timeout or ctx is cancelled.



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




### Type NavigateOption
```go
type NavigateOption func(*navigateTestOptions)
```
NavigateOption represents options to configure NavigationTest.

### Functions

```go
func WithContextOptions(opts ...chromedp.ContextOption) NavigateOption
```
WithContextOptions appends options to the chromedp context.


```go
func WithElementTimeout(timeout time.Duration) NavigateOption
```
WithElementTimeout sets the timeout for waiting for each individual DOM
element.


```go
func WithExecAllocatorOptions(opts ...chromedp.ExecAllocatorOption) NavigateOption
```
WithExecAllocatorOptions appends options to the Chrome allocator.


```go
func WithSelectorActions(selector string, actions ...chromedp.Action) NavigateOption
```
WithSelectorActions registers chromedp actions to run after WaitVisible
for the given selector. If no actions are registered for a selector, only
WaitVisible is performed. Call this option once per selector that requires
additional interaction (e.g. chromedp.Click).


```go
func WithSuppressedCertErrorsFor(certs ...*x509.Certificate) NavigateOption
```
WithSuppressedCertErrorsFor configures Chrome to suppress certificate errors
for connections whose chain includes one of the provided CA certificates.
Intended for testing against servers using locally issued certificates such
as those from the Pebble ACME test server.


```go
func WithTimeout(timeout time.Duration) NavigateOption
```
WithTimeout sets the overall timeout for the click test execution (including
startup and navigation).


```go
func WithUserDataDir(dir string) NavigateOption
```
WithUserDataDir sets the user data directory for Chrome.




### Type NavigationSpec
```go
type NavigationSpec struct {
	URL               string         `yaml:"url"`
	Selectors         []string       `yaml:"selectors"`
	Action            SelectorAction `yaml:"action"`
	SequentialActions bool           `yaml:"sequential_actions"`
}
```
NavigationSpec represents a specification for verifying and interacting
with elements on a URL. Action is applied to every selector in Selectors;
use WithSelectorActions to override the action for individual selectors.
By default all selectors are waited on concurrently; set SequentialActions
to true when the actions have ordering dependencies (e.g. clicking one
element causes another to appear).


### Type NavigationTest
```go
type NavigationTest struct {
	// contains filtered or unexported fields
}
```
NavigationTest can be used to validate pages by navigating to a URL,
waiting for DOM elements to exist/be visible, and optionally acting on them.

### Functions

```go
func NewNavigationTest(specs []NavigationSpec, opts ...NavigateOption) *NavigationTest
```
NewNavigationTest creates a new NavigationTest with the given specs and
options.



### Methods

```go
func (c *NavigationTest) Run(ctx context.Context) error
```
Run executes the NavigationTest specifications. It runs the specs
concurrently and uses chromedp via chromedputil to control the browser.




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




### Type SelectorAction
```go
type SelectorAction string
```
SelectorAction is an enum of the actions that can be performed on a DOM
element after it becomes visible. Use WithSelectorActions for actions not
covered by this enum (e.g. right-click via MouseClickNode).

### Constants
### SelectorActionNone, SelectorActionClick, SelectorActionDoubleClick
```go
// SelectorActionNone waits for the element to be visible but performs no
// further action. This is the default when no action is specified.
SelectorActionNone SelectorAction = ""
// SelectorActionClick performs a single left click on the element.
SelectorActionClick SelectorAction = "click"
// SelectorActionDoubleClick performs a double left click on the element.
SelectorActionDoubleClick SelectorAction = "double_click"

```



### Methods

```go
func (a SelectorAction) MarshalYAML() (any, error)
```


```go
func (a *SelectorAction) UnmarshalYAML(value *yaml.Node) error
```




### Type TLSSpec
```go
type TLSSpec struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`

	CustomDNSServer string `yaml:"custom-dns-server" doc:"custom DNS server to use for resolving hostnames, if empty the system resolver is used"` // custom DNS server to use for resolving hostnames, if empty the system resolver is used

	ExpandDNSNames     bool          `yaml:"expand-dns-names" doc:"see tlsvalidate.WithExpandDNSNames"`                                                              // see tlsvalidate.WithExpandDNSNames
	CheckSerialNumbers bool          `yaml:"check-serial-numbers" doc:"see tlsvalidate.WithCheckSerialNumbers"`                                                      // see tlsvalidate.WithCheckSerialNumbers
	ValidFor           time.Duration `yaml:"valid-for" doc:"see tlsvalidate.WithValidForAtLeast"`                                                                    // see tlsvalidate.WithValidForAtLeast
	TLSMinVersion      uint16        `yaml:"tls-min-version" doc:"see tlsvalidate.WithTLSMinVersion"`                                                                // see tlsvalidate.WithTLSMinVersion
	IssuerREs          []string      `yaml:"issuer-res" doc:"see tlsvalidate.WithIssuerRegexps"`                                                                     // see tlsvalidate.WithIssuerRegexps
	CustomCAPEM        string        `yaml:"custom-ca-pem" doc:"used tlsvalidate.WithCustomRootCAPEM"`                                                               // used tlsvalidate.WithCustomRootCAPEM
	CustomCAPEMOnly    bool          `yaml:"custom-ca-pem-only" doc:"if true, only the custom CA PEM file is used, otherwise it's appended to the system cert pool"` // if true, only the custom CA PEM file is used, otherwise it's appended to the system cert pool
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




### Type WebhookRoundTripSpec
```go
type WebhookRoundTripSpec struct {
	DeliveryURL string `yaml:"delivery_url" doc:"URL that the webhook payload is delivered to"`
	RelayURL    string `yaml:"relay_url" doc:"URL that the relayed result is read from"`
}
```
WebhookRoundTripSpec defines a single webhook round-trip test: a signed
payload is delivered to DeliveryURL and the relayed result is read back from
RelayURL and compared to the original payload. The signer for each delivery
URL is looked up from the map passed to NewWebhookRoundTripTest.


### Type WebhookRoundTripTest
```go
type WebhookRoundTripTest struct {
	// contains filtered or unexported fields
}
```
WebhookRoundTripTest validates webhook relay round-trips for a set of specs.

### Functions

```go
func NewWebhookRoundTripTest(signers map[string]operations.Signer, specs ...WebhookRoundTripSpec) *WebhookRoundTripTest
```
NewWebhookRoundTripTest creates a new WebhookRoundTripTest. signers maps
each delivery URL to the operations.Signer used to sign payloads for that
endpoint; a nil or missing entry means the request is sent unsigned.



### Methods

```go
func (w *WebhookRoundTripTest) Run(ctx context.Context, client *http.Client) error
```







