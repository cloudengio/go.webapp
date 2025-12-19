# Package [cloudeng.io/webapp/goget](https://pkg.go.dev/cloudeng.io/webapp/goget?tab=doc)

```go
import cloudeng.io/webapp/goget
```


## Types
### Type Handler
```go
type Handler struct {
	// contains filtered or unexported fields
}
```
Handler implements an HTTP handler that serves go-get meta tags based on the
supplied specifications.

### Functions

```go
func NewHandler(specs []Spec) (*Handler, error)
```
NewHandler creates a new Handler instance for the provided specifications.


```go
func NewHandlerFromFS(fsys fs.ReadFileFS, path string) (*Handler, error)
```
NewHandlerFromFS creates a new Handler instance by loading specifications
from the specified file path within the provided fs.ReadFileFS. The file
should contain a list YAML-formatted specifications as follows:

  - import: "example.com/my/module" vcs: "git" repo: "github.com/user/repo"



### Methods

```go
func (h *Handler) GoGetHandler(next http.Handler) http.Handler
```
GoGetHandler returns an http.Handler that serves go-get meta tags for
requests that include the "go-get=1" query parameter and match one of the
defined specifications. If the query parameter is not present, the request
is passed to the next handler. A 404 is returned if no specification
matches.




### Type Spec
```go
type Spec struct {
	ImportPath string `yaml:"import" cmd:"import path"`
	Content    string `yaml:"content" cmd:"content of the go-get meta tag"`
	// contains filtered or unexported fields
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







