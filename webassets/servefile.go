// Copyright 2020 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webassets

import (
	"io/fs"
	"net/http"
)

// SameFileHTTPFilesystem is an http.FileSystem that always returns the same
// file regardless of the name used to open it. It is typically used
// to serve index.html, or any other single file regardless of
// the requested path, eg:
//
// http.Handle("/", http.FileServer(SameFileHTTPFilesystem(assets, "index.html")))
type SameFileHTTPFilesystem struct {
	filename string
	fs       http.FileSystem
}

// NewSameFileHTTPFilesystem returns a new SameFileHTTPFilesystem that always returns
// the specified filename when opened.
func NewSameFileHTTPFilesystem(fs fs.FS, filename string) http.FileSystem {
	return &SameFileHTTPFilesystem{
		filename: filename,
		fs:       http.FS(fs),
	}
}

// Open implements http.FileSystem.
func (sff *SameFileHTTPFilesystem) Open(string) (http.File, error) {
	return sff.fs.Open(sff.filename)
}
