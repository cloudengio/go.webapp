// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloudeng.io/webapp/testwebapp"
)

func TestVerifyRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/perm", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/target", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/temp", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/relative", http.StatusFound)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := srv.Client()

	t.Run("Success", func(t *testing.T) {
		specs := []testwebapp.RedirectSpec{
			{
				URL:    srv.URL + "/perm",
				Target: "https://example.com/target",
				Code:   http.StatusMovedPermanently,
			},
			{
				// Note: http.Redirect helper normalizes relative paths if needed,
				// but usually writes "Location: /relative".
				// However, standard library might make it absolute?
				// Let's verify what http.Redirect sends. It sends what you give it.
				// But VerifyRedirect checks Header.Get("Location") == Target.
				// So we should match exactly.
				URL:    srv.URL + "/temp",
				Target: "/relative",
				Code:   http.StatusFound,
			},
		}

		rt := testwebapp.NewRedirectTest(specs...)
		if err := rt.Run(t.Context(), client); err != nil {
			t.Errorf("expected success, got %v", err)
		}
	})

	t.Run("Error_CodeMismatch", func(t *testing.T) {
		spec := testwebapp.RedirectSpec{
			URL:    srv.URL + "/perm",
			Target: "https://example.com/target",
			Code:   http.StatusFound, // Expecting 302, getting 301
		}
		rt := testwebapp.NewRedirectTest(spec)
		err := rt.Run(t.Context(), client)
		if err == nil || !errors.Is(err, testwebapp.ErrRedirectStatusCodeMismatch) {
			t.Errorf("expected ErrRedirectStatusCodeMismatch, got %v", err)
		}
	})

	t.Run("Error_TargetMismatch", func(t *testing.T) {
		spec := testwebapp.RedirectSpec{
			URL:    srv.URL + "/perm",
			Target: "https://example.com/WRONG",
			Code:   http.StatusMovedPermanently,
		}
		rt := testwebapp.NewRedirectTest(spec)
		err := rt.Run(t.Context(), client)
		if err == nil || !errors.Is(err, testwebapp.ErrRedirectTargetMismatch) {
			t.Errorf("expected ErrRedirectTargetMismatch, got %v", err)
		}
	})

	t.Run("Error_Unexpected", func(t *testing.T) {
		// connect to invalid port
		spec := testwebapp.RedirectSpec{
			URL:    "http://127.0.0.1:0/invalid",
			Target: "any",
			Code:   301,
		}
		rt := testwebapp.NewRedirectTest(spec)
		err := rt.Run(t.Context(), client)
		if err == nil || !errors.Is(err, testwebapp.ErrRedirectUnexpectedError) {
			t.Errorf("expected ErrRedirectUnexpectedError, got %v", err)
		}
	})
}
