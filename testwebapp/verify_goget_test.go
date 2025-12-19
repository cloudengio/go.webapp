package testwebapp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cloudeng.io/webapp/goget"
	"cloudeng.io/webapp/testwebapp"
)

func TestVerifyGoGet(t *testing.T) {
	spec := goget.Spec{
		ImportPath: "cloudeng.io/cmdutil",
		Content:    "cloudeng.io git https://github.com/cloudengio/go.pkgs",
	}
	client := &http.Client{}
	ggt := testwebapp.NewGoGetTest(client, spec)
	if err := ggt.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func mod1Handler(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("go-get") == "1" {
		w.Write([]byte(`<html><head><meta name="go-import" content="example.com/mod git https://github.com/example/mod"></head></html>`))
		return
	}
	w.Write([]byte("ok"))
}

func TestVerifyGoGet_Local(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/mod", mod1Handler)

	tlsServer := httptest.NewTLSServer(mux)
	defer tlsServer.Close()

	tlsClient := tlsServer.Client()

	importPath := strings.TrimPrefix(tlsServer.URL, "https://") + "/mod"

	t.Run("Error_NotFound", func(t *testing.T) {
		spec := goget.Spec{
			ImportPath: strings.TrimPrefix(tlsServer.URL, "https://") + "/missing",
			Content:    "example.com/mod git https://github.com/example/mod",
		}
		ggt := testwebapp.NewGoGetTest(tlsClient, spec)
		if err := ggt.Run(t.Context()); err == nil || !errors.Is(err, testwebapp.ErrGoGetPathNotFound) {
			t.Errorf("expected error for 404, got %v", err)
		}
	})

	t.Run("Error_ContentMismatch", func(t *testing.T) {
		spec := goget.Spec{
			ImportPath: importPath,
			Content:    "example.com/mod git https://github.com/example/WRONG",
		}
		ggt := testwebapp.NewGoGetTest(tlsClient, spec)
		if err := ggt.Run(t.Context()); err == nil || !errors.Is(err, testwebapp.ErrGoGetContentMismatch) {
			t.Errorf("expected error for content mismatch, got %v", err)
		}
	})

	t.Run("Error_MissingMeta", func(t *testing.T) {
		// Handler that returns 200 but no meta tag
		mux.HandleFunc("/nometa", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<html><body>No meta tag here</body></html>"))
		})
		spec := goget.Spec{
			ImportPath: strings.TrimPrefix(tlsServer.URL, "https://") + "/nometa",
			Content:    "whatever",
		}
		ggt := testwebapp.NewGoGetTest(tlsClient, spec)
		if err := ggt.Run(t.Context()); err == nil || !errors.Is(err, testwebapp.ErrGoGetNotFound) {
			t.Errorf("expected error for missing meta tag, got %v", err)
		}
	})
}
