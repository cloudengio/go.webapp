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
)

var metaTemplate = template.Must(template.New("go-import").Parse(`<html><head><meta name="go-import" content="{{.Content}}"></head><body>{{.Content}}</body></html>`))

// Spec represents a go-get meta tag specification.
// From https://go.dev/ref/mod#serving-from-proxy
// "The tag’s content must contain the repository root path, the version control
// system, and the URL, separated by spaces. See Finding a repository for a module
// path for details.
type Spec struct {
	ImportPath string `yaml:"import" cmd:"import path" json:"import"`
	Content    string `yaml:"content" cmd:"content of the go-get meta tag" json:"content"`
}

func (s Spec) String() string {
	return fmt.Sprintf("%s?go-get=1 content=%q", s.ImportPath, s.Content)
}

// SplitHostnamePath splits the import path into the hostname and
// path components. The path component will have any trailing slash
// removed.
func (s Spec) SplitHostnamePath() (string, string, error) {
	importPath := s.ImportPath
	if !strings.Contains(importPath, "://") {
		importPath = "https://" + importPath
	}
	u, err := url.Parse(importPath)
	if err != nil {
		return "", "", err
	}
	return u.Hostname(), strings.TrimSuffix(u.Path, "/"), nil
}

type handler struct {
	host    string
	path    string // no trailing slash
	content string
	fb      http.Handler
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("go-get") != "1" {
		h.fb.ServeHTTP(w, r) //nolint:errcheck
		return
	}
	if r.URL.Hostname() != h.host {
		h.fb.ServeHTTP(w, r) //nolint:errcheck
		return
	}
	if strings.TrimSuffix(r.URL.Path, "/") != h.path {
		h.fb.ServeHTTP(w, r) //nolint:errcheck
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(h.content)) //nolint:errcheck
}

// Option is used to configure the creation and registration of go-get handlers.
type Option func(*options)

type options struct {
	rootHandler http.Handler
}

// WithRootHandler configures the go-get handler to use the provided
// handler for requests to the root "/" path. It is often the case
// that the root path will be handled differently to all other
// go-get paths.
func WithRootHandler(next http.Handler) Option {
	return func(o *options) {
		o.rootHandler = next
	}
}

// NewHandler creates a new http.Handler for a given go-get specification and
// returns the path that the handler should be registered at, without
// the trailing slash. The returned handler will call the provided next
// handler if the request is not a go-get request. It will increment the
// optional counter metric if the request is a go-get request.
func (s Spec) NewHandler(next http.Handler, opts ...Option) (http.Handler, string, error) {
	if next == nil {
		next = http.NotFoundHandler()
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	host, path, err := s.SplitHostnamePath()
	if err != nil {
		return nil, "", err
	}
	if path == "" && o.rootHandler != nil {
		next = o.rootHandler
	}
	var out strings.Builder
	if err := metaTemplate.Execute(&out, s); err != nil {
		return nil, "", err
	}
	handler := handler{
		host:    host,
		path:    path,
		content: out.String(),
		fb:      next,
	}
	return handler, path, nil
}
