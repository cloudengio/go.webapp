// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"io/fs"
	"net/http"
	"strconv"
	"sync"

	"cloudeng.io/logging/ctxlog"
)

// ServeWithHeaders is an http.Handler that serves a byte slice with specified headers
// and only supports GET requests to a specific URL path.
type ServeWithHeaders struct {
	headers http.Header
	data    []byte
	urlpath string
}

// NewServeWithHeaders creates a new ServeWithHeaders handler.
func NewServeWithHeaders(headers http.Header, data []byte, urlpath string) ServeWithHeaders {
	return ServeWithHeaders{headers: headers, data: data, urlpath: urlpath}
}

// URLPath returns the URL path that this handler serves.
func (s ServeWithHeaders) URLPath() string {
	return s.urlpath
}

// ServeHTTP serves the file with the specified headers. If the requested
// URL path does not match the handler's URL path, it responds with 404 Not Found.
func (s ServeWithHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != s.urlpath {
		http.NotFound(w, r)
		return
	}
	for k, vs := range s.headers {
		w.Header().Del(k)
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(s.data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.data)
}

// ServeFSWithHeaders is an http.Handler that serves files from an fs.FS with specified
// headers for specific URL paths.
type ServeFSWithHeaders struct {
	mu      sync.Mutex
	headers map[string]http.Header
	fs      fs.FS
	next    http.Handler
	rewrite func(string) string
}

// NewServeFSWithHeaders creates a new ServeFSWithHeaders handler that serves
// files from the provided fs.FS. The urlpaths registered via SetHeaders are
// used to look up which headers to apply; the optional rewrite function is
// applied to the URL path after the lookup to produce the FS file path.
//
// When serving with custom headers, a leading '/' is stripped from the
// (possibly rewritten) path before reading from the FS, so URL paths like
// "/index.html" map naturally to FS paths like "index.html" without needing
// a rewrite function.
//
// When SetHeaders is called with an empty header map the file is served via
// http.ServeFileFS, which receives the path before stripping. In that case
// the rewrite function must handle any necessary path transformation (e.g.
// stripping the leading '/').
//
// The next handler is called for any URL path for which SetHeaders has not
// been called. If next is nil such requests are answered with 404 Not Found.
func NewServeFSWithHeaders(fs fs.FS, next http.Handler, rewrite func(string) string) *ServeFSWithHeaders {
	return &ServeFSWithHeaders{headers: make(map[string]http.Header), fs: fs, next: next, rewrite: rewrite}
}

// SetHeaders sets the headers to be used when serving the file at the specified URL path.
// If SetHeaders is not called for a URL path then the file will not be served and
// the next handler will be called instead. If SetHeaders is called with an empty header, the
// file will be served usng http.ServeFileFS without setting any additional headers.
func (s *ServeFSWithHeaders) SetHeaders(headers http.Header, urlpaths ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, path := range urlpaths {
		s.headers[path] = headers
	}
}

func (s *ServeFSWithHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	headers, ok := s.headers[r.URL.Path]
	s.mu.Unlock()
	if !ok {
		if s.next != nil {
			s.next.ServeHTTP(w, r)
		}
		http.NotFound(w, r)
		return
	}
	path := r.URL.Path
	if s.rewrite != nil {
		path = s.rewrite(r.URL.Path)
	}
	if len(headers) == 0 {
		http.ServeFileFS(w, r, s.fs, path)
		return
	}
	for k, vs := range headers {
		w.Header().Del(k)
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if path[0] == '/' {
		path = path[1:]
	}
	data, err := fs.ReadFile(s.fs, path)
	if err != nil {
		ctxlog.Error(r.Context(), "ServeWithHeaders", "URL.Path", r.URL.Path, "Rewritten", path, "error", err)
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
