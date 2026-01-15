// Copyright 2025cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webassets_test

import (
	"io"
	"testing"
	"testing/fstest"

	"cloudeng.io/webapp/webassets"
)

func TestSameFileHTTPFilesystem(t *testing.T) {
	const filename = "index.html"
	const content = "Hello World"
	fs := fstest.MapFS{
		filename:    {Data: []byte(content)},
		"other.txt": {Data: []byte("Other")},
	}

	sfs := webassets.NewSameFileHTTPFilesystem(fs, filename)

	testCases := []string{
		"/",
		"/index.html",
		"/other",
		"/random/path",
		"file",
	}

	for _, tc := range testCases {
		f, err := sfs.Open(tc)
		if err != nil {
			t.Errorf("%q: failed to open: %v", tc, err)
			continue
		}

		got, err := io.ReadAll(f)
		if err != nil {
			t.Errorf("%q: failed to read: %v", tc, err)
			f.Close()
			continue
		}

		if string(got) != content {
			t.Errorf("%q: got %q, want %q", tc, string(got), content)
		}

		stat, err := f.Stat()
		if err != nil {
			t.Errorf("%q: failed to stat: %v", tc, err)
			f.Close()
			continue
		}
		if stat.Name() != filename {
			t.Errorf("%q: got name %q, want %q", tc, stat.Name(), filename)
		}
		f.Close()
	}
}

func TestSameFileHTTPFilesystemError(t *testing.T) {
	const filename = "missing.html"
	fs := fstest.MapFS{} // Empty FS
	sfs := webassets.NewSameFileHTTPFilesystem(fs, filename)

	_, err := sfs.Open("/")
	if err == nil {
		t.Error("expected error, got nil")
	}
}
