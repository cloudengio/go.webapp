# Package [cloudeng.io/webapp/cssutil](https://pkg.go.dev/cloudeng.io/webapp/cssutil?tab=doc)

```go
import cloudeng.io/webapp/cssutil
```

Package cssutil provides utilities for working with CSS classes in
HTML documents, including support for generating Tailwind CSS safelist
configurations.

## Functions
### Func ParseHTMLClasses
```go
func ParseHTMLClasses(readers ...io.Reader) ([]string, error)
```
ParseHTMLClasses parses one or more HTML documents and returns a sorted,
deduplicated slice of all CSS class names referenced in class attributes
across all documents.

### Func ParseHTMLClassesFS
```go
func ParseHTMLClassesFS(fsys fs.FS, names ...string) ([]string, error)
```
ParseHTMLClassesFS opens each name from fsys and calls ParseHTMLClasses with
all of the resulting readers.

### Func TailwindSourceInline
```go
func TailwindSourceInline(classes []string) string
```
TailwindSourceInline returns a Tailwind CSS v4 @source inline directive
containing the provided class names. The directive instructs Tailwind to
generate CSS for all listed classes regardless of whether they appear in
scanned source files.




