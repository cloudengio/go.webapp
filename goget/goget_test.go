// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package goget

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func registerHandlers(mux *http.ServeMux, next http.Handler, specs []Spec) error {
	for _, spec := range specs {
		handler, path, err := spec.NewHandler(next)
		if err != nil {
			return err
		}
		mux.Handle(path+"/", handler)
		if len(path) == 0 {
			// An empty path will be redirected to /
			continue
		}
		mux.Handle(path, handler)
	}
	return nil
}

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

	mux := http.NewServeMux()
	nextCalled := false
	nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		nextCalled = true
	})
	err := registerHandlers(mux, nextHandler, specs)
	require.NoError(t, err)

	// 1. Match: go-get=1 query param and prefix match
	t.Run("Match", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/mod?go-get=1", nil)
		w := httptest.NewRecorder()
		nextCalled = false
		mux.ServeHTTP(w, req)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `<meta name="go-import" content="example.com/mod git https://github.com/example/mod">`)
	})

	// 2. No Match: go-get != 1
	t.Run("NoMatch_QueryParam", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/mod", nil)
		w := httptest.NewRecorder()
		nextCalled = false
		mux.ServeHTTP(w, req)

		assert.True(t, nextCalled)
	})

	// 3. No Match: import path mismatch
	t.Run("NoMatch_Path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/other?go-get=1", nil)
		w := httptest.NewRecorder()
		nextCalled = false
		mux.ServeHTTP(w, req)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	})

	// 4. No Match: partial prefix but not a sub-package
	t.Run("NoMatch_PartialPrefix", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/module?go-get=1", nil)
		w := httptest.NewRecorder()
		nextCalled = false
		mux.ServeHTTP(w, req)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
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
		mux := http.NewServeMux()
		err := registerHandlers(mux, nil, specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/exact?go-get=1", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "example.com/exact")
	})

	t.Run("ExactMatchWithPort", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/exact",
				Content:    "example.com/exact git https://github.com/user/exact",
			},
		}
		mux := http.NewServeMux()
		err := registerHandlers(mux, nil, specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "https://example.com:8080/exact?go-get=1", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

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
		mux := http.NewServeMux()
		err := registerHandlers(mux, nil, specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://other.com/pkg?go-get=1", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("CaseSensitiveMatching", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/PKG",
				Content:    "example.com/PKG git https://github.com/user/pkg",
			},
		}
		mux := http.NewServeMux()
		err := registerHandlers(mux, nil, specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/pkg?go-get=1", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("RootPath", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com",
				Content:    "example.com git https://github.com/user/repo",
			},
		}
		mux := http.NewServeMux()
		err := registerHandlers(mux, nil, specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com?go-get=1", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMovedPermanently, w.Code)
		assert.Equal(t, "/?go-get=1", w.Header().Get("Location"))
	})

	t.Run("RootPathWithSlash", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com",
				Content:    "example.com git https://github.com/user/repo",
			},
		}
		mux := http.NewServeMux()
		err := registerHandlers(mux, nil, specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/?go-get=1", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("PartialHostMatch", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				Content:    "example.com/pkg git https://github.com/user/pkg",
			},
		}
		mux := http.NewServeMux()
		err := registerHandlers(mux, nil, specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://sub.example.com/pkg?go-get=1", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

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
		mux := http.NewServeMux()
		err := registerHandlers(mux, nil, specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/pkg/sub?go-get=1", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

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
		mux := http.NewServeMux()
		nextCalled := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})
		err := registerHandlers(mux, next, specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/pkg?go-get=", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.True(t, nextCalled)
	})

	t.Run("QueryValueNotOne", func(t *testing.T) {
		specs := []Spec{
			{
				ImportPath: "example.com/pkg",
				Content:    "example.com/pkg git https://github.com/user/pkg",
			},
		}
		mux := http.NewServeMux()
		nextCalled := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})
		err := registerHandlers(mux, next, specs)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/pkg?go-get=0", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.True(t, nextCalled)
	})
}
