// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloudeng.io/webapp"
)

func TestHealthzHandler(t *testing.T) {
	handler := webapp.HealthzHandler()
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(body), "ok\n"; got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
