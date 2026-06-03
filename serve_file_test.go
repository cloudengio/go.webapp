// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloudeng.io/webapp"
)

type mockReadFileFS struct {
	files map[string][]byte
}

func (m *mockReadFileFS) ReadFile(name string) ([]byte, error) {
	return m.ReadFileCtx(context.Background(), name)
}

func (m *mockReadFileFS) ReadFileCtx(_ context.Context, name string) ([]byte, error) {
	if data, ok := m.files[name]; ok {
		return data, nil
	}
	return nil, &mockNotFoundError{name}
}

func (m *mockReadFileFS) Open(_ string) (fs.File, error) {
	return nil, errors.New("Open not implemented")
}

type mockNotFoundError struct{ name string }

func (e *mockNotFoundError) Error() string { return "not found: " + e.name }

func TestServeWithHeaders(t *testing.T) {
	const content = "icon-data"
	const filename = "favicon.ico"
	const urlpath = "/favicon.ico"

	fs := &mockReadFileFS{files: map[string][]byte{filename: []byte(content)}}
	h := webapp.NewServeWithHeaders(http.Header{
		"Content-Type":  {"image/x-icon"},
		"Cache-Control": {"public, max-age=86400"},
	}, fs, filename, urlpath)

	if got, want := h.URLPath(), urlpath; got != want {
		t.Errorf("URLPath: got %q, want %q", got, want)
	}

	// Matching path returns 200 with headers and body.
	req := httptest.NewRequest(http.MethodGet, urlpath, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("status: got %v, want %v", got, want)
	}
	if got, want := resp.Header.Get("Content-Type"), "image/x-icon"; got != want {
		t.Errorf("Content-Type: got %q, want %q", got, want)
	}
	if got, want := resp.Header.Get("Cache-Control"), "public, max-age=86400"; got != want {
		t.Errorf("Cache-Control: got %q, want %q", got, want)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), content; got != want {
		t.Errorf("body: got %q, want %q", got, want)
	}

	// Wrong path returns 404.
	req = httptest.NewRequest(http.MethodGet, "/other", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if got, want := w.Result().StatusCode, http.StatusNotFound; got != want {
		t.Errorf("wrong path: got %v, want %v", got, want)
	}
}

func TestServeWithHeaders_FileNotFound(t *testing.T) {
	fs := &mockReadFileFS{files: map[string][]byte{}}
	h := webapp.NewServeWithHeaders(http.Header{"Content-Type": {"image/x-icon"}}, fs, "missing.ico", "/favicon.ico")

	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if got, want := w.Result().StatusCode, http.StatusInternalServerError; got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
