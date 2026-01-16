// Copyright 2020 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webassets

import (
	"io/fs"
	"log/slog"
	"path"
)

type relative struct {
	prefix string
	fs     fs.FS
	logger *slog.Logger
}

// Open implements fs.FS.
func (r *relative) Open(name string) (fs.File, error) {
	full := path.Join(r.prefix, name)
	f, err := r.fs.Open(full)
	if err != nil {
		r.logger.Error("failed to open", "name", name, "path", full, "error", err)
		return nil, err
	}
	return f, nil
}

// RelativeFS wraps the supplied FS so that prefix is prepended
// to all of the paths fetched from it. This is generally useful
// when working with webservers where the FS containing files
// is created from 'assets/...' but the URL path to access them
// is at the root. So /index.html can be mapped to assets/index.html.
func RelativeFS(prefix string, fs fs.FS) fs.FS {
	return relativeFS(prefix, fs, nil)
}

func relativeFS(prefix string, fs fs.FS, logger *slog.Logger) *relative {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("pkg", "webapp/webassets.relativeFS")
	return &relative{prefix: prefix, fs: fs, logger: logger}
}
