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
			VCS:        "git",
			RepoURL:    "https://github.com/example/mod",
		},
		{
			ImportPath: "example.com/another/",
			VCS:        "git",
			RepoURL:    "https://github.com/example/another",
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
		h, err := NewHandlerFromFS(mockFS, "config.yaml")
		require.NoError(t, err)
		require.NotNil(t, h)
		assert.Len(t, h.specs, 2)
		assert.Equal(t, "example.com/foo", h.specs[0].ImportPath)
		assert.Equal(t, "git", h.specs[0].VCS)
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
				VCS:        "git",
				RepoURL:    "https://github.com/user/pkg",
			},
			{
				ImportPath: "example.com/mod/",
				VCS:        "git",
				RepoURL:    "https://github.com/user/mod",
			},
		}
		h, err := NewHandler(specs)
		require.NoError(t, err)
		require.NotNil(t, h)
		assert.Len(t, h.specs, 2)
		// Check that trailing slash is normalized
		assert.Equal(t, "example.com/pkg/", h.specs[0].importPathWithSlash)
		assert.Equal(t, "example.com/mod/", h.specs[1].importPathWithSlash)
		assert.Equal(t, "example.com/mod", h.specs[1].ImportPath)
	})

	t.Run("InvalidRepoURL", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				VCS:        "git",
				RepoURL:    "not a valid url",
			},
		}
		h, err := NewHandler(specs)
		assert.Error(t, err)
		assert.Nil(t, h)
	})

	t.Run("InvalidScheme", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				VCS:        "git",
				RepoURL:    "ftp://github.com/user/pkg",
			},
		}
		h, err := NewHandler(specs)
		assert.Error(t, err)
		assert.Nil(t, h)
		assert.Contains(t, err.Error(), "invalid scheme")
	})

	t.Run("NoHost", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				VCS:        "git",
				RepoURL:    "https:///path/to/repo",
			},
		}
		h, err := NewHandler(specs)
		assert.Error(t, err)
		assert.Nil(t, h)
		assert.Contains(t, err.Error(), "no host")
	})

	t.Run("QueryParamsInURL", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				VCS:        "git",
				RepoURL:    "https://github.com/user/pkg?foo=bar",
			},
		}
		h, err := NewHandler(specs)
		assert.Error(t, err)
		assert.Nil(t, h)
		assert.Contains(t, err.Error(), "must not contain query parameters")
	})

	t.Run("UnsupportedVCS", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				VCS:        "cvs",
				RepoURL:    "https://github.com/user/pkg",
			},
		}
		h, err := NewHandler(specs)
		assert.Error(t, err)
		assert.Nil(t, h)
		assert.Contains(t, err.Error(), "unsupported VCS")
	})

	t.Run("SupportedVCS", func(t *testing.T) {
		vcsList := []string{"git", "hg", "svn", "bzr"}
		for _, vcs := range vcsList {
			t.Run(vcs, func(t *testing.T) {
				specs := []Spec{
					{
						ImportPath: "example.com/pkg",
						VCS:        vcs,
						RepoURL:    "https://github.com/user/pkg",
					},
				}
				h, err := NewHandler(specs)
				require.NoError(t, err)
				require.NotNil(t, h)
			})
		}
	})

	t.Run("SupportedSchemes", func(t *testing.T) {
		schemes := []string{"https", "http", "ssh", "git"}
		for _, scheme := range schemes {
			t.Run(scheme, func(t *testing.T) {
				specs := []Spec{
					{
						ImportPath: "example.com/pkg",
						VCS:        "git",
						RepoURL:    scheme + "://github.com/user/pkg",
					},
				}
				h, err := NewHandler(specs)
				require.NoError(t, err)
				require.NotNil(t, h)
			})
		}
	})
}
