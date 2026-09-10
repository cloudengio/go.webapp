# Package [cloudeng.io/webapp/websec](https://pkg.go.dev/cloudeng.io/webapp/websec?tab=doc)

```go
import cloudeng.io/webapp/websec
```

Package websec provides HTTP security middleware for web applications.
In particular, it offers NewLocalhostHandler to enforce security controls
for HTTP/HTTPS endpoints bound to 127.0.0.1 or ::1, defending against
non-loopback connections, DNS rebinding attacks, cross-site browser
requests, and framing/MIME-sniffing vulnerabilities.

Package websec provides HTTP security middleware for web applications.

## Functions
### Func NewHandler
```go
func NewHandler(next http.Handler, opts ...Option) http.Handler
```
NewHandler is an alias for NewLocalhostHandler.

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
WithAllowedOrigins permits specific origins to make cross-origin requests
(e.g. a local dev UI on http://localhost:3000 calling an API on :8080).


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
func WithCounters(total, nonLoopback, invalidHost, crossSite webapp.CounterInc) Option
```
WithCounters configures metric counters for all rejection types: - total:
incremented on any rejected request - nonLoopback: incremented when the
client remote address is not loopback - invalidHost: incremented when the
Host header is invalid (DNS rebinding) - crossSite: incremented when a
cross-site browser request is blocked


```go
func WithCrossSiteCounter(counter webapp.CounterInc) Option
```
WithCrossSiteCounter configures a counter callback invoked when a request is
rejected because it was initiated cross-site by a browser.


```go
func WithCustomResponseHeaders(headers map[string]string) Option
```
WithCustomResponseHeaders overrides or extends default response security
headers.


```go
func WithDeniedCounter(counter webapp.CounterInc) Option
```
WithDeniedCounter configures a counter callback invoked when a request is
rejected for any reason (total denials).


```go
func WithEnforceLoopback(enforce bool) Option
```
WithEnforceLoopback toggles raw socket RemoteAddr loopback verification.
Defaults to true.


```go
func WithInvalidHostCounter(counter webapp.CounterInc) Option
```
WithInvalidHostCounter configures a counter callback invoked when a request
is rejected due to an invalid Host header.


```go
func WithLogger(logger *slog.Logger) Option
```
WithLogger sets the structured logger for security event logging.


```go
func WithNonLoopbackCounter(counter webapp.CounterInc) Option
```
WithNonLoopbackCounter configures a counter callback invoked when a request
is rejected because the remote client address is not loopback.


```go
func WithSecurityHeaders(enable bool) Option
```
WithSecurityHeaders toggles whether defensive HTTP response headers
(X-Frame-Options, CSP, nosniff, no-store) are injected. Defaults to true.







