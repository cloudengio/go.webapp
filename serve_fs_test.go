// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"cloudeng.io/webapp"
)

func TestServeFSWithHeaders(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": {Data: []byte("<html>hello</html>")},
		"about.html": {Data: []byte("<html>about</html>")},
	}

	t.Run("RegisteredWithHeaders", func(t *testing.T) {
		// rewrite is nil: ServeHTTP strips the leading '/' automatically before
		// reading from the FS, so "/index.html" maps to "index.html".
		s := webapp.NewServeFSWithHeaders(fsys, nil, nil)
		s.SetHeaders(http.Header{
			"Content-Type":  {"text/html; charset=utf-8"},
			"Cache-Control": {"no-cache"},
		}, "/index.html")

		req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		if got, want := resp.StatusCode, http.StatusOK; got != want {
			t.Errorf("status: got %v, want %v", got, want)
		}
		if got, want := resp.Header.Get("Content-Type"), "text/html; charset=utf-8"; got != want {
			t.Errorf("Content-Type: got %q, want %q", got, want)
		}
		if got, want := resp.Header.Get("Cache-Control"), "no-cache"; got != want {
			t.Errorf("Cache-Control: got %q, want %q", got, want)
		}
		body, _ := io.ReadAll(resp.Body)
		if got, want := string(body), "<html>hello</html>"; got != want {
			t.Errorf("body: got %q, want %q", got, want)
		}
	})

	t.Run("RegisteredEmptyHeaders", func(t *testing.T) {
		// Empty headers → delegates to http.ServeFileFS, which receives the path
		// before ServeHTTP strips the leading '/'. The rewrite function must
		// strip it explicitly so the FS path is valid.
		// Also uses about.html because http.ServeFileFS unconditionally redirects
		// any path ending in "/index.html".
		stripSlash := func(p string) string { return strings.TrimPrefix(p, "/") }
		s := webapp.NewServeFSWithHeaders(fsys, nil, stripSlash)
		s.SetHeaders(http.Header{}, "/about.html")

		req := httptest.NewRequest(http.MethodGet, "/about.html", nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusOK; got != want {
			t.Errorf("status: got %v, want %v", got, want)
		}
		body, _ := io.ReadAll(w.Result().Body)
		if got, want := string(body), "<html>about</html>"; got != want {
			t.Errorf("body: got %q, want %q", got, want)
		}
	})

	t.Run("MultiplePathsSameHeaders", func(t *testing.T) {
		s := webapp.NewServeFSWithHeaders(fsys, nil, nil)
		s.SetHeaders(http.Header{"X-Frame-Options": {"DENY"}}, "/index.html", "/about.html")

		for _, tc := range []struct{ path, want string }{
			{"/index.html", "<html>hello</html>"},
			{"/about.html", "<html>about</html>"},
		} {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
			if got := w.Code; got != http.StatusOK {
				t.Errorf("%s status: got %v, want %v", tc.path, got, http.StatusOK)
			}
			if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("%s X-Frame-Options: got %q, want DENY", tc.path, got)
			}
			body, _ := io.ReadAll(w.Result().Body)
			if got := string(body); got != tc.want {
				t.Errorf("%s body: got %q, want %q", tc.path, got, tc.want)
			}
		}
	})

	t.Run("UnregisteredNoNext", func(t *testing.T) {
		s := webapp.NewServeFSWithHeaders(fsys, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/missing.html", nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusNotFound; got != want {
			t.Errorf("status: got %v, want %v", got, want)
		}
	})

	t.Run("UnregisteredWithNext", func(t *testing.T) {
		var nextCalled bool
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})
		s := webapp.NewServeFSWithHeaders(fsys, next, nil)

		req := httptest.NewRequest(http.MethodGet, "/missing.html", nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)

		if !nextCalled {
			t.Error("expected next handler to be called")
		}
	})

	t.Run("RewritePath", func(t *testing.T) {
		// Rewrite maps the logical URL /page to the file about.html.
		// The rewrite result has no leading '/', so the automatic strip is a no-op.
		rewrite := func(path string) string {
			if path == "/page" {
				return "about.html"
			}
			return path
		}
		s := webapp.NewServeFSWithHeaders(fsys, nil, rewrite)
		s.SetHeaders(http.Header{"Content-Type": {"text/html"}}, "/page")

		req := httptest.NewRequest(http.MethodGet, "/page", nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusOK; got != want {
			t.Errorf("status: got %v, want %v", got, want)
		}
		body, _ := io.ReadAll(w.Result().Body)
		if got, want := string(body), "<html>about</html>"; got != want {
			t.Errorf("body: got %q, want %q", got, want)
		}
	})

	t.Run("FileNotFound", func(t *testing.T) {
		// Path is registered but resolves to a file that doesn't exist in the FS.
		// No rewrite needed: the automatic '/' strip turns "/ghost" into "ghost",
		// which is not present in the FS.
		s := webapp.NewServeFSWithHeaders(fsys, nil, nil)
		s.SetHeaders(http.Header{"Content-Type": {"text/html"}}, "/ghost")

		req := httptest.NewRequest(http.MethodGet, "/ghost", nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)

		if got, want := w.Code, http.StatusNotFound; got != want {
			t.Errorf("status: got %v, want %v", got, want)
		}
	})
}
