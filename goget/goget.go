// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package goget

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"cloudeng.io/webapp"

	"gopkg.in/yaml.v3"
)

var metaTemplate = template.Must(template.New("go-import").Parse(`<html><head><meta name="go-import" content="{{.Content}}"></head><body>{{.Content}}</body></html>`))

// Spec represents a go-get meta tag specification.
// From https://go.dev/ref/mod#serving-from-proxy
// "The tag’s content must contain the repository root path, the version control
// system, and the URL, separated by spaces. See Finding a repository for a module
// path for details.
type Spec struct {
	ImportPath     string `yaml:"import" cmd:"import path" json:"import"`
	Content        string `yaml:"content" cmd:"content of the go-get meta tag" json:"content"`
	hostname, path string // cached split of ImportPath
}

// Hostname returns the hostname component of the import path.
// Use SplitHostnamePath to perform the split if Spec was not
// unmarshalled from YAML.
func (s *Spec) Hostname() string {
	return s.hostname
}

// Path returns the path component of the import path.
// Use SplitHostnamePath to perform the split if Spec was not
// unmarshalled from YAML.
func (s *Spec) Path() string {
	return s.path
}

func (s *Spec) UnmarshalYAML(value *yaml.Node) error {
	type specAlias Spec
	if err := value.Decode((*specAlias)(s)); err != nil {
		return err
	}
	return s.SplitHostnamePath()
}

func (s Spec) String() string {
	return fmt.Sprintf("%s?go-get=1 content=%q", s.ImportPath, s.Content)
}

// SplitHostnamePath splits the import path into the hostname and
// path components. The path component will have any trailing slash
// removed. Use the Hostname and Path methods to retrieve the components.
func (s *Spec) SplitHostnamePath() error {
	importPath := s.ImportPath
	if !strings.Contains(importPath, "://") {
		importPath = "https://" + importPath
	}
	u, err := url.Parse(importPath)
	if err != nil {
		return err
	}
	s.hostname = u.Hostname()
	s.path = strings.TrimSuffix(u.Path, "/")
	return nil
}

type handler struct {
	host    string
	path    string // no trailing slash
	content string
	fb      http.Handler
	counter webapp.CounterInc
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("go-get") != "1" {
		h.fb.ServeHTTP(w, r) //nolint:errcheck
		return
	}
	if strings.TrimSuffix(r.URL.Path, "/") != h.path {
		h.fb.ServeHTTP(w, r) //nolint:errcheck
		return
	}
	if hn := r.URL.Hostname(); len(hn) != 0 && hn != h.host {
		h.fb.ServeHTTP(w, r) //nolint:errcheck
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(h.content)) //nolint:errcheck
	if h.counter != nil {
		h.counter(r.Context())
	}
}

// Option is used to configure the creation and registration of go-get handlers.
type Option func(*options)

type options struct {
	counter webapp.CounterInc
}

// WithCounter configures the handler to increment the provided metric
// when a go-get request is handled.
func WithCounter(counter webapp.CounterInc) Option {
	return func(o *options) {
		o.counter = counter
	}
}

// NewHandler creates a new http.Handler for a given go-get specification and
// returns the path that the handler should be registered at, without
// the trailing slash. The returned handler will call the provided next
// handler if the request is not a go-get request. Take care to set the
// appropriate next handler for the root path "/".
// The go-get redirect will be served if go-get=1 is present in the query
// parameters and the request path matches the path component of the import
// path. If the request includes a host name, it must match the hostname
// component of the import path.
func (s *Spec) NewHandler(next http.Handler, opts ...Option) (http.Handler, error) {
	if next == nil {
		next = http.NotFoundHandler()
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	var out strings.Builder
	if err := metaTemplate.Execute(&out, s); err != nil {
		return nil, err
	}
	handler := handler{
		host:    s.hostname,
		path:    s.path,
		content: out.String(),
		fb:      next,
		counter: o.counter,
	}
	return handler, nil
}
