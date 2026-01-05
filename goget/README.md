# Package [cloudeng.io/webapp/goget](https://pkg.go.dev/cloudeng.io/webapp/goget?tab=doc)

```go
import cloudeng.io/webapp/goget
```


## Types
### Type Spec
```go
type Spec struct {
	ImportPath string `yaml:"import" cmd:"import path" json:"import"`
	Content    string `yaml:"content" cmd:"content of the go-get meta tag" json:"content"`
	// contains filtered or unexported fields
}
```
Spec represents a go-get meta tag specification. From
https://go.dev/ref/mod#serving-from-proxy "The tag’s content must contain
the repository root path, the version control system, and the URL, separated
by spaces. See Finding a repository for a module path for details.

### Methods

```go
func (s *Spec) Hostname() string
```
Hostname returns the hostname component of the import path. Use
SplitHostnamePath to perform the split if Spec was not unmarshalled from
YAML.


```go
func (s *Spec) NewHandler(next http.Handler) (http.Handler, error)
```
NewHandler creates a new http.Handler for a given go-get specification
and returns the path that the handler should be registered at, without the
trailing slash. The returned handler will call the provided next handler if
the request is not a go-get request.


```go
func (s *Spec) Path() string
```
Path returns the path component of the import path. Use SplitHostnamePath to
perform the split if Spec was not unmarshalled from YAML.


```go
func (s *Spec) SplitHostnamePath() error
```
SplitHostnamePath splits the import path into the hostname and path
components. The path component will have any trailing slash removed. Use the
Hostname and Path methods to retrieve the components.


```go
func (s Spec) String() string
```


```go
func (s *Spec) UnmarshalYAML(value *yaml.Node) error
```







