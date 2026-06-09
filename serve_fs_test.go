// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"cloudeng.io/webapp"
)

func serveFSServe(t *testing.T, s *webapp.ServeFSWithHeaders, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func checkServeFSStatus(t *testing.T, resp *httptest.ResponseRecorder, want int) {
	t.Helper()
	if got := resp.Code; got != want {
		t.Errorf("status: got %v, want %v", got, want)
	}
}

func checkServeFSHeader(t *testing.T, resp *httptest.ResponseRecorder, key, want string) {
	t.Helper()
	if got := resp.Header().Get(key); got != want {
		t.Errorf("%s: got %q, want %q", key, got, want)
	}
}

func checkServeFSBody(t *testing.T, resp *httptest.ResponseRecorder, want string) {
	t.Helper()
	body := resp.Body.String()
	if got := body; got != want {
		t.Errorf("body: got %q, want %q", got, want)
	}
}

func testServeFSRegisteredWithHeaders(t *testing.T, fsys fstest.MapFS) {
	t.Helper()
	s := webapp.NewServeFSWithHeaders(fsys, nil, nil)
	s.SetHeaders(http.Header{
		"Content-Type":  {"text/html; charset=utf-8"},
		"Cache-Control": {"no-cache"},
	}, "/index.html")

	resp := serveFSServe(t, s, http.MethodGet, "/index.html")
	checkServeFSStatus(t, resp, http.StatusOK)
	checkServeFSHeader(t, resp, "Content-Type", "text/html; charset=utf-8")
	checkServeFSHeader(t, resp, "Cache-Control", "no-cache")
	checkServeFSBody(t, resp, "<html>hello</html>")
}

func testServeFSRegisteredEmptyHeaders(t *testing.T, fsys fstest.MapFS) {
	t.Helper()
	stripSlash := func(p string) string { return strings.TrimPrefix(p, "/") }
	s := webapp.NewServeFSWithHeaders(fsys, nil, stripSlash)
	s.SetHeaders(http.Header{}, "/about.html")

	resp := serveFSServe(t, s, http.MethodGet, "/about.html")
	checkServeFSStatus(t, resp, http.StatusOK)
	checkServeFSBody(t, resp, "<html>about</html>")
}

func testServeFSMultiplePathsSameHeaders(t *testing.T, fsys fstest.MapFS) {
	t.Helper()
	s := webapp.NewServeFSWithHeaders(fsys, nil, nil)
	s.SetHeaders(http.Header{"X-Frame-Options": {"DENY"}}, "/index.html", "/about.html")

	for _, tc := range []struct{ path, body string }{
		{"/index.html", "<html>hello</html>"},
		{"/about.html", "<html>about</html>"},
	} {
		resp := serveFSServe(t, s, http.MethodGet, tc.path)
		checkServeFSStatus(t, resp, http.StatusOK)
		checkServeFSHeader(t, resp, "X-Frame-Options", "DENY")
		checkServeFSBody(t, resp, tc.body)
	}
}

func testServeFSUnregisteredNoNext(t *testing.T, fsys fstest.MapFS) {
	t.Helper()
	s := webapp.NewServeFSWithHeaders(fsys, nil, nil)
	resp := serveFSServe(t, s, http.MethodGet, "/missing.html")
	checkServeFSStatus(t, resp, http.StatusNotFound)
}

func testServeFSUnregisteredWithNext(t *testing.T, fsys fstest.MapFS) {
	t.Helper()
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	s := webapp.NewServeFSWithHeaders(fsys, next, nil)
	w := httptest.NewRecorder()
	serveFSServe(t, s, http.MethodGet, "/missing.html")
	if !nextCalled {
		t.Error("expected next handler to be called")
	}
	if got, want := w.Code, http.StatusOK; got != want {
		t.Errorf("status: got %v, want %v", got, want)
	}
}

func testServeFSRewritePath(t *testing.T, fsys fstest.MapFS) {
	t.Helper()
	rewrite := func(path string) string {
		if path == "/page" {
			return "about.html"
		}
		return path
	}
	s := webapp.NewServeFSWithHeaders(fsys, nil, rewrite)
	s.SetHeaders(http.Header{"Content-Type": {"text/html"}}, "/page")

	resp := serveFSServe(t, s, http.MethodGet, "/page")
	checkServeFSStatus(t, resp, http.StatusOK)
	checkServeFSBody(t, resp, "<html>about</html>")
}

func testServeFSFileNotFound(t *testing.T, fsys fstest.MapFS) {
	t.Helper()
	s := webapp.NewServeFSWithHeaders(fsys, nil, nil)
	s.SetHeaders(http.Header{"Content-Type": {"text/html"}}, "/ghost")

	resp := serveFSServe(t, s, http.MethodGet, "/ghost")
	checkServeFSStatus(t, resp, http.StatusNotFound)
}

func TestServeFSWithHeaders(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": {Data: []byte("<html>hello</html>")},
		"about.html": {Data: []byte("<html>about</html>")},
	}

	t.Run("RegisteredWithHeaders", func(t *testing.T) { testServeFSRegisteredWithHeaders(t, fsys) })
	t.Run("RegisteredEmptyHeaders", func(t *testing.T) { testServeFSRegisteredEmptyHeaders(t, fsys) })
	t.Run("MultiplePathsSameHeaders", func(t *testing.T) { testServeFSMultiplePathsSameHeaders(t, fsys) })
	t.Run("UnregisteredNoNext", func(t *testing.T) { testServeFSUnregisteredNoNext(t, fsys) })
	t.Run("UnregisteredWithNext", func(t *testing.T) { testServeFSUnregisteredWithNext(t, fsys) })
	t.Run("RewritePath", func(t *testing.T) { testServeFSRewritePath(t, fsys) })
	t.Run("FileNotFound", func(t *testing.T) { testServeFSFileNotFound(t, fsys) })
}
