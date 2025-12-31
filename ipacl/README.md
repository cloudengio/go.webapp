# Package [cloudeng.io/webapp/ipacl](https://pkg.go.dev/cloudeng.io/webapp/ipacl?tab=doc)

```go
import cloudeng.io/webapp/ipacl
```


## Functions
### Func NewACLHandler
```go
func NewACLHandler(handler http.Handler, acl *ACL, opts ...Option) http.Handler
```
NewACLHandler creates a new http.Handler that enforces the given ACL. If
the request's remote IP address is not allowed by the ACL, a 403 Forbidden
response is returned, otherwise the request is passed to the given handler.

### Func RemoteAddrExtractor
```go
func RemoteAddrExtractor(r *http.Request) (netip.Addr, error)
```
RemoteAddrExtractor returns the remote IP address from an HTTP request.
It is the default AddressExtractor and is suitable for when a server is
directly exposed to the internet.

### Func XForwardedForExtractor
```go
func XForwardedForExtractor(r *http.Request) (netip.Addr, error)
```
XForwardedForExtractor returns the IP address from the X-Forwarded-For
header. It uses the first IP address in the list.



## Types
### Type ACL
```go
type ACL struct {
	// contains filtered or unexported fields
}
```
ACL represents an IP address access control list.

### Functions

```go
func NewACL(addrs ...string) (*ACL, error)
```
NewACL creates a new ACL from a list of IP addresses or CIDR prefixes. Each
entry in the addrs slice can be either a single IP address or a CIDR prefix.
If a single IP address is provided, it is treated as a /32 (for IPv4) or
/128 (for IPv6) prefix.



### Methods

```go
func (a *ACL) Allowed(ip netip.Addr) bool
```
Allowed returns whether the given IP address is allowed by the ACL.




### Type AddressExtractor
```go
type AddressExtractor func(r *http.Request) (netip.Addr, error)
```
AddressExtractor represents a function that extracts an IP address from an
HTTP request.


### Type Option
```go
type Option func(o *options)
```
Option represents an option for NewACLHandler.

### Functions

```go
func WithAddressExtractor(extractor AddressExtractor) Option
```
WithAddressExtractor returns an Option that sets the AddressExtractor.







