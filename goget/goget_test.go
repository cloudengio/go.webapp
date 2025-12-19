// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package goget

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoGetHandler(t *testing.T) {
	specs := []Spec{
		{
			ImportPath: "example.com/mod",
			Content:    "example.com/mod git https://github.com/example/mod",
		},
		{
			ImportPath: "example.com/another/",
			Content:    "example.com/another git https://github.com/example/another",
		},
	}

	h, err := NewHandler(specs)
	require.NoError(t, err)

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

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	})

	// 4. Sub-package match
	t.Run("Match_SubPackage", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/another/sub?go-get=1", nil)
		w := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `<meta name="go-import" content="example.com/another git https://github.com/example/another">`)
	})

	// 5. No Match: partial prefix but not a sub-package
	t.Run("NoMatch_PartialPrefix", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/module?go-get=1", nil)
		w := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	})
}

func TestNewHandlerFromFS(t *testing.T) {
	// Mock FS
	mockFS := fstest.MapFS{
		"config.yaml": {
			Data: []byte(`- import: example.com/foo
  content: example.com/foo git https://github.com/example/foo
- import: example.com/bar
  content: example.com/bar svn https://github.com/example/bar
`),
		},
		"bad.yaml": {
			Data: []byte(`invalid yaml content`),
		},
	}

	t.Run("Success", func(t *testing.T) {
		h, err := NewHandlerFromFS(mockFS, "config.yaml")
		require.NoError(t, err)
		require.NotNil(t, h)
		assert.Len(t, h.specs, 2)
		assert.Equal(t, "example.com/foo", h.specs[0].ImportPath)
		assert.Equal(t, "example.com/foo git https://github.com/example/foo", h.specs[0].Content)
		assert.Equal(t, "example.com/bar", h.specs[1].ImportPath)
	})

	t.Run("FileNotFound", func(t *testing.T) {
		h, err := NewHandlerFromFS(mockFS, "missing.yaml")
		assert.Error(t, err)
		assert.Nil(t, h)
	})

	t.Run("InvalidYAML", func(t *testing.T) {
		h, err := NewHandlerFromFS(mockFS, "bad.yaml")
		assert.Error(t, err)
		assert.Nil(t, h)
	})
}

func TestNewHandler(t *testing.T) {
	t.Run("ValidSpecs", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				Content:    "example.com/pkg git https://github.com/user/pkg",
			},
			{
				ImportPath: "example.com/mod/",
				Content:    "example.com/mod git https://github.com/user/mod",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)
		require.NotNil(t, h)
		require.Len(t, h.specs, 2)
		// Check that trailing slash is handled and specs are sorted by length desc
		assert.Equal(t, "example.com/pkg/", h.specs[0].importPathWithSlash)
		assert.Equal(t, "example.com/mod/", h.specs[1].importPathWithSlash)
		assert.Equal(t, "example.com/mod", h.specs[1].ImportPath)
	})

	t.Run("EmptyImportPath", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "",
				Content:    "example.com git https://github.com/user/pkg",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)
		require.NotNil(t, h)
		assert.Equal(t, "/", h.specs[0].importPathWithSlash)
	})
}

func TestGoGetHandlerEdgeCases(t *testing.T) {
	t.Run("ExactMatch", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/exact",
				Content:    "example.com/exact git https://github.com/user/exact",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/exact?go-get=1", nil)
		w := httptest.NewRecorder()
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "example.com/exact")
	})

	t.Run("DifferentHosts", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				Content:    "example.com/pkg git https://github.com/user/pkg",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://other.com/pkg?go-get=1", nil)
		w := httptest.NewRecorder()
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("CaseSensitiveMatching", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/PKG",
				Content:    "example.com/PKG git https://github.com/user/pkg",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/pkg?go-get=1", nil)
		w := httptest.NewRecorder()
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("RootPath", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com",
				Content:    "example.com git https://github.com/user/repo",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com?go-get=1", nil)
		w := httptest.NewRecorder()
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "example.com")
	})

	t.Run("RootPathWithSlash", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com",
				Content:    "example.com git https://github.com/user/repo",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/?go-get=1", nil)
		w := httptest.NewRecorder()
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("DeepSubPackage", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				Content:    "example.com/pkg git https://github.com/user/pkg",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/pkg/sub/deep/nested?go-get=1", nil)
		w := httptest.NewRecorder()
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "example.com/pkg")
	})

	t.Run("PartialHostMatch", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				Content:    "example.com/pkg git https://github.com/user/pkg",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://sub.example.com/pkg?go-get=1", nil)
		w := httptest.NewRecorder()
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("MultipleSpecs_LongestMatch", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				Content:    "example.com/pkg git https://github.com/user/pkg",
			},
			{
				ImportPath: "example.com/pkg/sub",
				Content:    "example.com/pkg/sub git https://github.com/user/sub",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/pkg/sub?go-get=1", nil)
		w := httptest.NewRecorder()
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		// Should match the most specific spec (longest prefix).
		body := w.Body.String()
		assert.Contains(t, body, "example.com/pkg/sub git https://github.com/user/sub")
	})

	t.Run("EmptyQueryValue", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				Content:    "example.com/pkg git https://github.com/user/pkg",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/pkg?go-get=", nil)
		w := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.True(t, nextCalled)
	})

	t.Run("QueryValueNotOne", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				Content:    "example.com/pkg git https://github.com/user/pkg",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/pkg?go-get=0", nil)
		w := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		h.GoGetHandler(next).ServeHTTP(w, req)

		assert.True(t, nextCalled)
	})
}
