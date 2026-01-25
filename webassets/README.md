# Package [cloudeng.io/webapp/webassets](https://pkg.go.dev/cloudeng.io/webapp/webassets?tab=doc)

```go
import cloudeng.io/webapp/webassets
```


## Functions
### Func NewAssets
```go
func NewAssets(prefix string, fsys fs.FS, opts ...AssetsOption) fs.FS
```
NewAssets returns an fs.FS that is configured to be optional reloaded from
the local filesystem or to be served directly from the supplied fs.FS.
The EnableReloading option is used to enable reloading. Prefix is prepended
to all names passed to the supplied fs.FS, which is typically obtained via
go:embed. See RelativeFS for more details.

### Func NewSameFileHTTPFilesystem
```go
func NewSameFileHTTPFilesystem(fs fs.FS, filename string) http.FileSystem
```
NewSameFileHTTPFilesystem returns a new SameFileHTTPFilesystem that always
returns the specified filename when opened.

### Func RelativeFS
```go
func RelativeFS(prefix string, fs fs.FS) fs.FS
```
RelativeFS wraps the supplied FS so that prefix is prepended to all of
the paths fetched from it. This is generally useful when working with
webservers where the FS containing files is created from 'assets/...' but
the URL path to access them is at the root. So /index.html can be mapped to
assets/index.html.



## Types
### Type AssetsFlags
```go
type AssetsFlags struct {
	ReloadEnable    bool   `subcmd:"reload-enable,false,'if set, newer local filesystem versions of embedded asset files will be used'"`
	ReloadNew       bool   `subcmd:"reload-new-files,true,'if set, files that only exist on the local filesystem may be used'"`
	ReloadRoot      string `subcmd:"reload-root,$PWD,'the filesystem location that contains assets to be used in preference to embedded ones. This is generally set to the directory that the application was built in to allow for updated versions of the original embedded assets to be used. It defaults to the current directory. For external/production use this will generally refer to a different directory.'"`
	ReloadLogging   bool   `subcmd:"reload-logging,false,set to enable logging"`
	ReloadDebugging bool   `subcmd:"reload-debugging,false,set to enable debug logging"`
}
```
AssetsFlags represents the flags used to control loading of assets from the
local filesystem to override those original embedded in the application
binary.

### Methods

```go
func (f AssetsFlags) Config() Config
```
Config converts AssetsFlags to Config.




### Type AssetsOption
```go
type AssetsOption func(a *assets)
```
AssetsOption represents an option to NewAssets.

### Functions

```go
func OptionsFromFlags(rf *AssetsFlags) []AssetsOption
```
OptionsFromFlags parses AssetsFlags to determine the options to be passed to
NewAssets()


```go
func WithLogger(logger *slog.Logger) AssetsOption
```


```go
func WithReloading(location string, after time.Time, loadNew bool) AssetsOption
```
WithReloading enables reloading of assets from the specified location
if they have changed since 'after'; loadNew controls whether new files,
ie. those that exist only in location, are loaded as opposed. See
cloudeng.io/io/reloadfs.




### Type Config
```go
type Config struct {
	ReloadEnable bool   `yaml:"reload_enable" doc:"if set, newer local filesystem versions of embedded asset files will be used"`
	ReloadNew    bool   `yaml:"reload_new" doc:"if set, files that only exist on the local filesystem may be used"`
	ReloadRoot   string `yaml:"reload_root" doc:"the filesystem location that contains assets to be used in preference to embedded ones. This is generally set to the directory that the application was built in to allow for updated versions of the original embedded assets to be used."`
}
```
Config represents the configuration used to control loading of assets from
the local filesystem to override those original embedded in the application
binary.

### Methods

```go
func (c Config) Options() []AssetsOption
```
Options converts Config to AssetsOption. If ReloadRoot is empty it defaults
to the current directory, if not empty, os.ExpandEnv is called to expand
environment variables.




### Type SameFileHTTPFilesystem
```go
type SameFileHTTPFilesystem struct {
	// contains filtered or unexported fields
}
```
SameFileHTTPFilesystem is an http.FileSystem that always returns the same
file regardless of the name used to open it. It is typically used to serve
index.html, or any other single file regardless of the requested path, eg:

http.Handle("/", http.FileServer(SameFileHTTPFilesystem(assets,
"index.html")))

### Methods

```go
func (sff *SameFileHTTPFilesystem) Open(string) (http.File, error)
```
Open implements http.FileSystem.







