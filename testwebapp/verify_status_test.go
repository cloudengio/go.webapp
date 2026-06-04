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

func TestCheckStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	mux.HandleFunc("/redir2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/redir", http.StatusFound)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := srv.Client()

	t.Run("DirectOK", func(t *testing.T) {
		cs := testwebapp.NewCheckStatus(testwebapp.CheckStatusSpec{
			URL:       srv.URL + "/ok",
			Code:      http.StatusOK,
			Redirects: 0,
		})
		if err := cs.Run(t.Context(), client); err != nil {
			t.Errorf("expected success, got %v", err)
		}
	})

	t.Run("StopAtRedirect", func(t *testing.T) {
		// Redirects:0 means don't follow — expect the 302 itself.
		cs := testwebapp.NewCheckStatus(testwebapp.CheckStatusSpec{
			URL:       srv.URL + "/redir",
			Code:      http.StatusFound,
			Redirects: 0,
		})
		if err := cs.Run(t.Context(), client); err != nil {
			t.Errorf("expected success, got %v", err)
		}
	})

	t.Run("FollowOneRedirect", func(t *testing.T) {
		// Redirects:1 follows one hop — /redir -> /ok, expect 200.
		cs := testwebapp.NewCheckStatus(testwebapp.CheckStatusSpec{
			URL:       srv.URL + "/redir",
			Code:      http.StatusOK,
			Redirects: 1,
		})
		if err := cs.Run(t.Context(), client); err != nil {
			t.Errorf("expected success, got %v", err)
		}
	})

	t.Run("StopMidChain", func(t *testing.T) {
		// Redirects:1 follows one hop — /redir2 -> /redir (stopped), expect 302.
		cs := testwebapp.NewCheckStatus(testwebapp.CheckStatusSpec{
			URL:       srv.URL + "/redir2",
			Code:      http.StatusFound,
			Redirects: 1,
		})
		if err := cs.Run(t.Context(), client); err != nil {
			t.Errorf("expected success, got %v", err)
		}
	})

	t.Run("FollowChain", func(t *testing.T) {
		// Redirects:2 follows both hops — /redir2 -> /redir -> /ok, expect 200.
		cs := testwebapp.NewCheckStatus(testwebapp.CheckStatusSpec{
			URL:       srv.URL + "/redir2",
			Code:      http.StatusOK,
			Redirects: 2,
		})
		if err := cs.Run(t.Context(), client); err != nil {
			t.Errorf("expected success, got %v", err)
		}
	})

	t.Run("MultipleSpecs", func(t *testing.T) {
		cs := testwebapp.NewCheckStatus(
			testwebapp.CheckStatusSpec{URL: srv.URL + "/ok", Code: http.StatusOK, Redirects: 0},
			testwebapp.CheckStatusSpec{URL: srv.URL + "/redir", Code: http.StatusOK, Redirects: 1},
		)
		if err := cs.Run(t.Context(), client); err != nil {
			t.Errorf("expected success, got %v", err)
		}
	})

	t.Run("CodeMismatch", func(t *testing.T) {
		cs := testwebapp.NewCheckStatus(testwebapp.CheckStatusSpec{
			URL:       srv.URL + "/ok",
			Code:      http.StatusNotFound,
			Redirects: 0,
		})
		err := cs.Run(t.Context(), client)
		if !errors.Is(err, testwebapp.ErrCheckStatusCodeMismatch) {
			t.Errorf("expected ErrCheckStatusCodeMismatch, got %v", err)
		}
	})

	t.Run("UnexpectedError", func(t *testing.T) {
		cs := testwebapp.NewCheckStatus(testwebapp.CheckStatusSpec{
			URL:       "http://127.0.0.1:0/invalid",
			Code:      http.StatusOK,
			Redirects: 0,
		})
		err := cs.Run(t.Context(), client)
		if !errors.Is(err, testwebapp.ErrCheckStatusUnexpectedError) {
			t.Errorf("expected ErrCheckStatusUnexpectedError, got %v", err)
		}
	})
}
