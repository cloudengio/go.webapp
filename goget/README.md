# Package [cloudeng.io/webapp/goget](https://pkg.go.dev/cloudeng.io/webapp/goget?tab=doc)

```go
import cloudeng.io/webapp/goget
```


## Functions
### Func RegisterHandlers
```go
func RegisterHandlers(mux webapp.ServeMux, next http.Handler, specs []Spec) error
```
RegisterHandlers creates and registers appropriate HTTP handlers for the
provided go-get specifications. If next is nil, http.NotFoundHandler is
used.



## Types
### Type Spec
```go
type Spec struct {
	ImportPath string `yaml:"import" cmd:"import path" json:"import"`
	Content    string `yaml:"content" cmd:"content of the go-get meta tag" json:"content"`
}
```
Spec represents a go-get meta tag specification. From
https://go.dev/ref/mod#serving-from-proxy "The tag’s content must contain
the repository root path, the version control system, and the URL, separated
by spaces. See Finding a repository for a module path for details.

### Methods

```go
func (s Spec) String() string
```







