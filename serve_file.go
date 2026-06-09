// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"io/fs"
	"net/http"
	"strconv"
	"strings"
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

// fsEntry holds the pre-computed FS path and response headers for a registered URL path.
type fsEntry struct {
	headers http.Header
	fsPath  string // leading '/' stripped; ready for fs.ReadFile and http.ServeFileFS
}

// ServeFSWithHeaders is an http.Handler that serves files from an fs.FS with specified
// headers for specific URL paths.
type ServeFSWithHeaders struct {
	mu      sync.Mutex
	entries map[string]fsEntry
	fs      fs.FS
	next    http.Handler
	rewrite func(string) string
}

// NewServeFSWithHeaders creates a new ServeFSWithHeaders handler that serves
// files from the provided fs.FS. The urlpaths registered via SetHeaders are
// used to look up which headers to apply; the optional rewrite function is
// applied to the URL path at registration time to produce the FS file path.
//
// A leading '/' is stripped from the (possibly rewritten) path so URL paths
// like "/index.html" map naturally to FS paths like "index.html".
//
// The next handler is called for any URL path for which SetHeaders has not
// been called. If next is nil such requests are answered with 404 Not Found.
func NewServeFSWithHeaders(fs fs.FS, next http.Handler, rewrite func(string) string) *ServeFSWithHeaders {
	return &ServeFSWithHeaders{entries: make(map[string]fsEntry), fs: fs, next: next, rewrite: rewrite}
}

// SetHeaders registers headers for the given URL paths. The FS path for each
// URL path is computed once here (applying rewrite if set, then stripping a
// leading '/'), so ServeHTTP never derives a file path from request data.
// If headers is empty the file is served via http.ServeFileFS without extra headers.
func (s *ServeFSWithHeaders) SetHeaders(headers http.Header, urlpaths ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, urlpath := range urlpaths {
		fsPath := urlpath
		if s.rewrite != nil {
			fsPath = s.rewrite(urlpath)
		}
		fsPath = strings.TrimPrefix(fsPath, "/")
		s.entries[urlpath] = fsEntry{headers: headers, fsPath: fsPath}
	}
}

func (s *ServeFSWithHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	entry, ok := s.entries[r.URL.Path] // r.URL.Path used only as a lookup key
	s.mu.Unlock()
	if !ok {
		if s.next != nil {
			s.next.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	if len(entry.headers) == 0 {
		http.ServeFileFS(w, r, s.fs, entry.fsPath)
		return
	}
	for k, vs := range entry.headers {
		w.Header().Del(k)
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	data, err := fs.ReadFile(s.fs, entry.fsPath)
	if err != nil {
		ctxlog.Error(r.Context(), "ServeWithHeaders", "URL.Path", r.URL.Path, "fsPath", entry.fsPath, "error", err)
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
