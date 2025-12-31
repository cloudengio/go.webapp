// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package goget

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"

	"cloudeng.io/webapp"
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

type handler struct {
	host    string
	content string
	fb      http.Handler
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqHost := r.Host
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		reqHost = host
	}
	if r.FormValue("go-get") != "1" || reqHost != h.host {
		h.fb.ServeHTTP(w, r) //nolint:errcheck
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(h.content)) //nolint:errcheck
}

// RegisterHandlers creates and registers appropriate
// HTTP handlers for the provided go-get specifications.
// If next is nil, http.NotFoundHandler is used.
func RegisterHandlers(mux webapp.ServeMux, next http.Handler, specs []Spec) error {
	if next == nil {
		next = http.NotFoundHandler()
	}
	var out strings.Builder
	for _, spec := range specs {
		importPath := spec.ImportPath
		if !strings.Contains(importPath, "://") {
			importPath = "https://" + importPath
		}
		u, err := url.Parse(importPath)
		if err != nil {
			return err
		}
		out.Reset()
		if err := metaTemplate.Execute(&out, spec); err != nil {
			return err
		}
		handler := handler{
			host:    u.Hostname(),
			content: out.String(),
			fb:      next,
		}
		ns := strings.TrimSuffix(u.Path, "/")
		mux.Handle(ns+"/", handler)
		if len(ns) == 0 {
			// An empty path will be redirected to /
			continue
		}
		mux.Handle(ns, handler)
	}
	return nil
}
