// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package goget_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"cloudeng.io/webapp/goget"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoGetHandler(t *testing.T) {
	specs := []goget.Spec{
		{
			ImportPath: "example.com/mod",
			VCS:        "git",
			RepoURL:    "https://github.com/example/mod",
		},
	}

	h := &goget.Handler{Specs: specs}

	// 1. Match: go-get=1 query param and prefix match
	t.Run("Match", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/mod?go-get=1", nil)
		w := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `<meta name="go-import" content="example.com/mod git https://github.com/example/mod">`)
	})

	// 2. No Match: go-get != 1
	t.Run("NoMatch_QueryParam", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/mod", nil)
		w := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.True(t, nextCalled)
	})

	// 3. No Match: import path mismatch
	t.Run("NoMatch_Path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/other?go-get=1", nil)
		w := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.True(t, nextCalled)
	})

	// 4. Sub-package match
	t.Run("Match_SubPackage", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/mod/sub?go-get=1", nil)
		w := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `<meta name="go-import" content="example.com/mod git https://github.com/example/mod">`)
	})
}

func TestNewHandlerFromFS(t *testing.T) {
	// Mock FS
	mockFS := fstest.MapFS{
		"config.yaml": {
			Data: []byte(`- import: example.com/foo
  vcs: git
  repo: https://github.com/example/foo
- import: example.com/bar
  vcs: svn
  repo: https://github.com/example/bar
`),
		},
		"bad.yaml": {
			Data: []byte(`invalid yaml content`),
		},
	}

	t.Run("Success", func(t *testing.T) {
		h, err := goget.NewHandlerFromFS(mockFS, "config.yaml")
		require.NoError(t, err)
		require.NotNil(t, h)
		assert.Len(t, h.Specs, 2)
		assert.Equal(t, "example.com/foo", h.Specs[0].ImportPath)
		assert.Equal(t, "git", h.Specs[0].VCS)
		assert.Equal(t, "example.com/bar", h.Specs[1].ImportPath)
	})

	t.Run("FileNotFound", func(t *testing.T) {
		h, err := goget.NewHandlerFromFS(mockFS, "missing.yaml")
		assert.Error(t, err)
		assert.Nil(t, h)
	})

	t.Run("InvalidYAML", func(t *testing.T) {
		h, err := goget.NewHandlerFromFS(mockFS, "bad.yaml")
		assert.Error(t, err)
		assert.Nil(t, h)
	})
}
