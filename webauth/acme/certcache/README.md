# Package [cloudeng.io/webapp/webauth/acme/certcache](https://pkg.go.dev/cloudeng.io/webapp/webauth/acme/certcache?tab=doc)

```go
import cloudeng.io/webapp/webauth/acme/certcache
```

Package certcache provides support for working with autocert caches with
persistent backing stores for storing and distributing certificates.

## Variables
### ErrReadonlyCache, ErrLocalOperation, ErrBackingOperation, ErrLockFailed
```go
ErrReadonlyCache = errors.New("readonly cache")
ErrLocalOperation = errors.New("local operation")
ErrBackingOperation = errors.New("backing store operation")
ErrLockFailed = errors.New("lock acquisition failed")

```

### ErrCacheMiss
```go
ErrCacheMiss = autocert.ErrCacheMiss

```
ErrCacheMiss is the same as autocert.ErrCacheMiss



## Functions
### Func HasReadonlyOption
```go
func HasReadonlyOption(opts []Option) bool
```
HasReadonlyOption returns true if the supplied options include the
WithReadonly option set to true.

### Func IsAcmeAccountKey
```go
func IsAcmeAccountKey(name string) bool
```
IsAcmeAccountKey returns true if the specified name is for an ACME account
private key.

### Func IsLocalName
```go
func IsLocalName(name string, allowRSAKeys bool) bool
```
IsLocalName returns true if the specified name is for local-only data such
as ACME client private keys or http-01 challenge tokens. If allowRSAKeys is
false, RSA keys are considered local-only and are never written to backing
stores since they are intended for legacy clients only.

### Func MetricsColumns
```go
func MetricsColumns() []string
```
MetricsColumns returns the list of columns that will be used for metric.
Name represents the cache key name and operation represents the operation
performed

### Func MetricsOperationValues
```go
func MetricsOperationValues() []string
```
MetricsOperationValues returns the list of values that will be used for the
"operation" label of the metric.

### Func ParseRevocationReason
```go
func ParseRevocationReason(reason string) (acme.CRLReasonCode, error)
```
ParseRevocationReason parses the supplied revocation reason string and
returns the corresponding acme.CRLReasonCode.

### Func RefreshCertificate
```go
func RefreshCertificate(_ context.Context, mgr *autocert.Manager, host string) (*tls.Certificate, error)
```
RefreshCertificate attempts to refresh the certificate for the specified
host using the provided autocert.Manager by simulating a TLS ClientHello
for the specified host. It prefers to use the PreferredCipherSuites and
PreferredSignatureSchemes defined in webapp package to force the use of
ECDSA certificates rather than RSA.

### Func WrapHostPolicyNoPort
```go
func WrapHostPolicyNoPort(existing autocert.HostPolicy) autocert.HostPolicy
```
WrapHostPolicyNoPort wraps an existing autocert.HostPolicy to strip any port
information from the host before passing it to the existing policy. This is
required when running in a test environment where well-known/hardwired ports
(80, 443) are not used.



## Types
### Type CachingStore
```go
type CachingStore struct {
	// contains filtered or unexported fields
}
```
CachingStore implements a 'caching store' that intergrates with autocert.
It provides an instance of autocert.Cache that will store certificates in
'backing' store, but use the local file system for temporary/private data
such as the ACME client's private key. This allows for certificates to be
shared across multiple hosts by using a distributed 'backing' store such as
AWS' secretsmanager. In addition, certificates may be extracted safely on
the host that manages them programmatically.

### Functions

```go
func NewCachingStore(localDir string, backingStore StoreFS, opts ...Option) (*CachingStore, error)
```
NewCachingStore returns an instance of autocert.Cache that will store
certificates in 'backing' store, but use the local file system for
temporary/private data such as the ACME client's private key. This allows
for certificates to be shared across multiple hosts by using a distributed
'backing' store such as AWS' secretsmanager. Certificates may be extracted
safely for use by other servers. CachingStore implements autocert.Cache.



### Methods

```go
func (dc *CachingStore) Delete(ctx context.Context, name string) error
```
Delete implements autocert.Cache.


```go
func (dc *CachingStore) Get(ctx context.Context, name string) ([]byte, error)
```
Get implements autocert.Cache.


```go
func (dc *CachingStore) GetAccountKey(ctx context.Context) (crypto.Signer, error)
```
GetAccountKey retrieves the ACME account private key from the cache.


```go
func (dc *CachingStore) Put(ctx context.Context, name string, data []byte) error
```
Put implements autocert.Cache.


```go
func (dc *CachingStore) ReadFile(name string) ([]byte, error)
```
Implement file.ReadfileFS“


```go
func (dc *CachingStore) ReadFileCtx(ctx context.Context, name string) ([]byte, error)
```
Implement file.ReadfileFS


```go
func (dc *CachingStore) WriteFile(name string, data []byte, perm fs.FileMode) error
```
Implement file.WritefileFS


```go
func (dc *CachingStore) WriteFileCtx(ctx context.Context, name string, data []byte, _ fs.FileMode) error
```
Implement file.WritefileFS




### Type Option
```go
type Option func(o *options)
```

### Functions

```go
func WithAllowRSAKeys(allow bool) Option
```
WithAllowRSAKeys sets whether RSA keys are allowed to be used for ACME
account keys. By default, RSA keys are not allowed since they are not
intended for legacy clients only.


```go
func WithLogger(logger *slog.Logger) Option
```
WithLogger sets the logger to use for logging cache operations. This is
the only way to set a logger since the context passed used when invoking
autocert.Cache methods is derived from context.Background() and cannot be
otherwise specified.


```go
func WithMetrics(metrics webapp.CounterVecInc) Option
```
WithMetrics sets the metrics to use for logging cache operations.


```go
func WithReadonly(readonly bool) Option
```
WithReadonly sets whether the caching store is readonly.


```go
func WithSaveAccountKey(name string) Option
```
WithSaveAccountKey sets whether ACME account keys are to be saved to the
backing store using the specified name.




### Type StoreFS
```go
type StoreFS interface {
	ReadFile(name string) ([]byte, error)
	ReadFileCtx(ctx context.Context, name string) ([]byte, error)
	WriteFileCtx(ctx context.Context, name string, data []byte, perm fs.FileMode) error
	Delete(ctx context.Context, name string) error
}
```
StoreFS defines an interface that combines reading, writing and deleting
files and is used to create an acme/autocert cache.

### Functions

```go
func NewLocalStore(dir string) (StoreFS, error)
```







