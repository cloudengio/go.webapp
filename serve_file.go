// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"io/fs"
	"net/http"
	"strconv"

	"cloudeng.io/logging/ctxlog"
)

// ServeWithHeaders is an http.Handler that serves a file with specified headers.
type ServeWithHeaders struct {
	headers  http.Header
	fs       fs.FS
	filename string
	urlpath  string
}

// NewServeWithHeaders creates a new ServeWithHeaders handler.
func NewServeWithHeaders(headers http.Header, fs fs.FS, filename, urlpath string) ServeWithHeaders {
	return ServeWithHeaders{headers: headers, fs: fs, filename: filename, urlpath: urlpath}
}

// URLPath returns the URL path that this handler serves.
func (s ServeWithHeaders) URLPath() string {
	return s.urlpath
}

// ServeHTTP serves the file with the specified headers. If the requested
// URL path does not match the handler's URL path, it responds with 404 Not Found.
func (s ServeWithHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	data, err := fs.ReadFile(s.fs, s.filename)
	if err != nil {
		ctxlog.Error(r.Context(), "ServeWithHeaders", "filename", s.filename, "error", err)
		http.Error(w, "failed to read file", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
