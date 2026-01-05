# Package [cloudeng.io/webapp/ipacl](https://pkg.go.dev/cloudeng.io/webapp/ipacl?tab=doc)

```go
import cloudeng.io/webapp/ipacl
```


## Functions
### Func NewHandler
```go
func NewHandler(handler http.Handler, allow, deny Contains, opts ...Option) http.Handler
```
NewHandler creates a new http.Handler that enforces allow and deny ACLs.
The deny ACL takes precedence over the allow ACL. If no ACLs are supplied
then the handler allows all requests. If the remote IP cannot be determined
or parsed then the request is denied. If the request's remote IP address is
not allowed by the ACL, a 403 Forbidden response is returned, otherwise the
request is passed to the given handler.

### Func RemoteAddrExtractor
```go
func RemoteAddrExtractor(r *http.Request) (string, netip.Addr, error)
```
RemoteAddrExtractor returns the remote IP address from an HTTP request.
It is the default AddressExtractor and is suitable for when a server is
directly exposed to the internet.

### Func XForwardedForExtractor
```go
func XForwardedForExtractor(r *http.Request) (string, netip.Addr, error)
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
func (a *ACL) Contains(ip netip.Addr) bool
```
Contains returns whether the given IP address is allowed by the ACL.




### Type AddressExtractor
```go
type AddressExtractor func(r *http.Request) (string, netip.Addr, error)
```
AddressExtractor represents a function that extracts an IP address from an
HTTP request.


### Type Config
```go
type Config struct {
	Addresses []string `yaml:"addresses" cmd:"list of ip addresses or cidr prefixes"`
	Direct    bool     `yaml:"direct" cmd:"set to true to use the requests.RemoteAddr"`   // Use the requests.RemoteAddr
	Proxy     bool     `yaml:"proxy" cmd:"set to true to use the X-Forwarded-For header"` // Use the X-Forwarded-For header
}
```
Config represents an IP address access control list configuration.

### Methods

```go
func (c Config) AddressExtractor() (AddressExtractor, error)
```
AddressExtractor returns an Option that sets the AddressExtractor.


```go
func (c Config) NewACL() (*ACL, error)
```
NewACL creates a new ACL from the given configuration.




### Type Contains
```go
type Contains func(ip netip.Addr) bool
```
Contains represents a function that returns whether the given IP address is
in the ACL.


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


```go
func WithCounters(deniedCounter, notAllowedCounter, errorCounter webapp.CounterInc) Option
```
WithCounters returns an Option that sets three Counters: 1. one that is
incremented when a request is denied because the IP address is in the deny
ACL 2. one that is incremented if the address is not in the allow ACL 3.
one that is incremented on error







