package testwebapp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cloudeng.io/webapp/testwebapp"
)

func TestVerifyHealthz(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok\n")
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := server.Client()
	ht := testwebapp.NewHealthzTest(client, server.URL+"/healthz", time.Millisecond, 1)

	if err := ht.Run(t.Context()); err != nil {
		t.Fatalf("healthz check failed: %v", err)
	}
}

func TestVerifyHealthz_Failures(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz-error", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal server error")
	})
	mux.HandleFunc("/healthz-bad-body", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "not ok")
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	client := server.Client()

	t.Run("status_error", func(t *testing.T) {
		ht := testwebapp.NewHealthzTest(client, server.URL+"/healthz-error", time.Millisecond, 1)
		err := ht.Run(t.Context())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "unexpected status code: 500") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("body_error", func(t *testing.T) {
		ht := testwebapp.NewHealthzTest(client, server.URL+"/healthz-bad-body", time.Millisecond, 1)
		err := ht.Run(t.Context())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "unexpected body") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}
