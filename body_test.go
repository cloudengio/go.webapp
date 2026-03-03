package webapp_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cloudeng.io/webapp"
)

func TestReadBodyLimit(t *testing.T) {
	tests := []struct {
		name              string
		body              string
		limit             int64
		replace           bool
		wantBody          []byte
		wantMaxBytesError bool
		wantErr           bool
		verifyAfter       bool
	}{
		{
			name:        "within limit, replace false",
			body:        "hello world",
			limit:       100,
			replace:     false,
			wantBody:          []byte("hello world"),
			wantMaxBytesError: false,
			wantErr:           false,
			verifyAfter:       true, // Should be empty
		},
		{
			name:        "within limit, replace true",
			body:        "hello world",
			limit:       100,
			replace:     true,
			wantBody:          []byte("hello world"),
			wantMaxBytesError: false,
			wantErr:           false,
			verifyAfter:       true, // Should be re-readable
		},
		{
			name:        "exact limit",
			body:        "0123456789",
			limit:       10,
			replace:     true,
			wantBody:          []byte("0123456789"),
			wantMaxBytesError: false,
			wantErr:           false,
			verifyAfter:       true,
		},
		{
			name:        "exceeds limit",
			body:        "0123456789a",
			limit:       10,
			replace:     false,
			wantBody:          nil,
			wantMaxBytesError: true,
			wantErr:           true,
			verifyAfter:       false,
		},
		{
			name:        "empty body",
			body:        "",
			limit:       10,
			replace:     true,
			wantBody:          []byte(""),
			wantMaxBytesError: false,
			wantErr:           false,
			verifyAfter:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			gotBody, err := webapp.ReadBodyLimit(req, tt.replace, tt.limit)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if tt.wantMaxBytesError {
					var maxBytesErr *http.MaxBytesError
					if !errors.As(err, &maxBytesErr) {
						t.Errorf("expected *http.MaxBytesError, got %T: %v", err, err)
					}
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if !bytes.Equal(gotBody, tt.wantBody) {
				t.Errorf("got body = %q, want %q", gotBody, tt.wantBody)
			}

			if err == nil && tt.verifyAfter {
				afterBody, afterErr := io.ReadAll(req.Body)
				if afterErr != nil {
					t.Fatalf("failed to read body after: %v", afterErr)
				}
				if tt.replace {
					if !bytes.Equal(afterBody, tt.wantBody) {
						t.Errorf("after replacement, got body = %q, want %q", afterBody, tt.wantBody)
					}
				} else {
					if len(afterBody) > 0 {
						t.Errorf("without replacement, expected empty body after read, got %q", afterBody)
					}
				}
			}
		})
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestReadBodyLimit_ReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", errReader{})
	_, err := webapp.ReadBodyLimit(req, false, 100)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		t.Fatal("expected generic read error, got MaxBytesError")
	}
}
