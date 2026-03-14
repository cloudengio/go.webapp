package webapp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"cloudeng.io/webapp"
)

func TestHTTPServerError(t *testing.T) {
	errSrc := webapp.HTTPServerError("test-error-source")

	cases := []struct {
		name   string
		call   func(w http.ResponseWriter, r *http.Request, m string, args ...any)
		status int
		text   string
	}{
		{"Unauthorized", errSrc.Unauthorized, http.StatusUnauthorized, "Unauthorized"},
		{"Forbidden", errSrc.Forbidden, http.StatusForbidden, "Forbidden"},
		{"NotFound", errSrc.NotFound, http.StatusNotFound, "Not Found"},
		{"Internal", errSrc.Internal, http.StatusInternalServerError, "Internal Server Error"},
		{"BadRequest", errSrc.BadRequest, http.StatusBadRequest, "Bad Request"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			w := httptest.NewRecorder()

			tc.call(w, req, "test message", "arg1", "val1")

			res := w.Result()
			if got, want := res.StatusCode, tc.status; got != want {
				t.Errorf("got %v, want %v", got, want)
			}

			body := w.Body.String()
			
			if !strings.HasPrefix(body, tc.text) {
				t.Errorf("got %v, want prefix %v", body, tc.text)
			}

			matched, _ := regexp.MatchString(tc.text+` \([0-9a-f]+\)\n`, body)
			if !matched {
				t.Errorf("expected body to match format '%s (hex_id)\\n', got: %v", tc.text, body)
			}
		})
	}
}

func TestHTTPServerErrorSendAndLog(t *testing.T) {
	errSrc := webapp.HTTPServerError("custom-error-source")

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	errSrc.SendAndLog(w, req, http.StatusTeapot, "I'm a teapot msg", "arg1", "val1")

	res := w.Result()
	if got, want := res.StatusCode, http.StatusTeapot; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	body := w.Body.String()
	text := http.StatusText(http.StatusTeapot)
	if !strings.HasPrefix(body, text) {
		t.Errorf("got %v, want prefix %v", body, text)
	}

	matched, _ := regexp.MatchString(text+` \([0-9a-f]+\)\n`, body)
	if !matched {
		t.Errorf("expected body to match format '%s (hex_id)\\n', got: %v", text, body)
	}
}

func ExampleHTTPServerError() {
	var err webapp.HTTPServerError = "my-component"

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	err.NotFound(w, req, "the page was not found", "user_id", 123)

	res := w.Result()
	fmt.Printf("Status: %d\n", res.StatusCode)

	body := w.Body.String()
	if strings.HasPrefix(body, "Not Found (") {
		fmt.Println("Body format is correct")
	}

	// Output:
	// Status: 404
	// Body format is correct
}
