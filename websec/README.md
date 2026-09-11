# Package [cloudeng.io/webapp/websec](https://pkg.go.dev/cloudeng.io/webapp/websec?tab=doc)

```go
import cloudeng.io/webapp/websec
```

Package websec provides HTTP security middleware for web applications.
In particular, it offers NewLocalhostHandler to enforce security controls
for HTTP/HTTPS endpoints bound to 127.0.0.1 or ::1, defending against
non-loopback connections, DNS rebinding attacks, cross-site browser
requests, and framing/MIME-sniffing vulnerabilities.

## Constants
### DenialNonLoopback, DenialInvalidHost, DenialCrossSite, DenialInvalidJWT
```go
DenialNonLoopback = "non-loopback"
DenialInvalidHost = "invalid-host"
DenialCrossSite = "cross-site"
DenialInvalidJWT = "invalid-jwt"

```
Denial reason constants used as label values for the denial metric.



## Functions
### Func DenialMetricValues
```go
func DenialMetricValues() []string
```
DenialMetricValues is an alias for MetricsDenialValues.

### Func MetricsColumns
```go
func MetricsColumns() []string
```
MetricsColumns returns the list of column/label names used for the denial
metric.

### Func MetricsDenialValues
```go
func MetricsDenialValues() []string
```
MetricsDenialValues returns the list of values used for the "reason" label
of the denial metric.

### Func NewHandler
```go
func NewHandler(next http.Handler, opts ...Option) http.Handler
```
NewHandler is an alias for NewLocalhostHandler.

### Func NewLocalHost
```go
func NewLocalHost(next http.Handler, opts ...Option) http.Handler
```
NewLocalHost is an alias for NewLocalhostHandler.

### Func NewLocalhostHandler
```go
func NewLocalhostHandler(next http.Handler, opts ...Option) http.Handler
```
NewLocalhostHandler wraps next with security controls designed for services
bound to 127.0.0.1 or ::1. By default, it enforces loopback connections,
validates Host headers against DNS rebinding, blocks cross-site browser
requests, and sets defensive response headers.



## Types
### Type Option
```go
type Option func(o *options)
```
Option configures the security handler.

### Functions

```go
func WithAllowedHosts(hosts ...string) Option
```
WithAllowedHosts configures the allowed Host header values for DNS rebinding
defense. If not specified, defaults to "127.0.0.1", "localhost", and "::1".


```go
func WithAllowedOrigins(origins ...string) Option
```
WithAllowedOrigins permits specific external or non-loopback origins to make
cross-origin requests (e.g. a dev UI on https://trusted-partner.local or an
external web client).


```go
func WithAllowedPorts(ports ...int) Option
```
WithAllowedPorts restricts the Host header and destination port to specific
port numbers (e.g. 8080).


```go
func WithBlockCrossSiteRequests(block bool) Option
```
WithBlockCrossSiteRequests enables or disables blocking requests initiated
cross-site by local web browsers (inspecting Sec-Fetch-Site, Origin,
and Referer). Defaults to true.


```go
func WithCounterVec(counter webapp.CounterVecInc) Option
```
WithCounterVec configures a CounterVecInc metric that is incremented
whenever a request is rejected, with the denial reason supplied as a label
value (one of MetricsDenialValues).


```go
func WithCounterVecAdd(counter webapp.CounterVecAdd) Option
```
WithCounterVecAdd configures a CounterVecAdd metric for request denials.
At handler initialization, all denial reason labels from MetricsDenialValues
are initialized with delta 0, and incremented by 1 on each denial.


```go
func WithCounters(counter webapp.CounterVecInc) Option
```
WithCounters is an alias for WithCounterVec.


```go
func WithCustomResponseHeaders(headers map[string]string) Option
```
WithCustomResponseHeaders overrides or extends default response security
headers.


```go
func WithEnforceLoopback(enforce bool) Option
```
WithEnforceLoopback toggles raw socket RemoteAddr loopback verification.
Defaults to true.


```go
func WithJWTContextKey(key string) Option
```
WithJWTContextKey sets the key that a validated token is stored under in the
request context, for retrieval with jwtutil.TokenFromContext. It defaults
to the name of the cookie, so this is needed where the two should differ,
such as when the name of the cookie is not one the rest of the application
should have to know.


```go
func WithJWTCookie(cookieName string, validator jwtutil.Validator, claimKey string, claimValue any) Option
```
WithJWTCookie enables JWT validation for requests presented in a cookie.
It verifies that the cookie named cookieName contains a JWT that validator
accepts and that contains claimKey == claimValue. If cookieName is empty,
it defaults to "auth_token".

The validated token is stored in the request context under the name of the
cookie unless WithJWTContextKey says otherwise. WithJWTCookieName can be
used to set the cookie name separately from this option.


```go
func WithJWTCookieName(name string) Option
```
WithJWTCookieName sets the name of the cookie that carries the JWT,
overriding the name given to WithJWTCookie. An empty name is ignored,
since a cookie has to be named something.


```go
func WithLogger(logger *slog.Logger) Option
```
WithLogger sets the structured logger for security event logging.


```go
func WithMetrics(metrics webapp.CounterVecInc) Option
```
WithMetrics is an alias for WithCounterVec.


```go
func WithSecurityHeaders(enable bool) Option
```
WithSecurityHeaders toggles whether defensive HTTP response headers
(X-Frame-Options, CSP, nosniff, no-store) are injected. Defaults to true.






## Examples
### [ExampleNewLocalhostHandler](https://pkg.go.dev/cloudeng.io/webapp/websec?tab=doc#example-NewLocalhostHandler)




