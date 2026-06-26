// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cloudeng.io/webapp/testwebapp"
)

// plainTextMetricsReporter checks whether each expected metric name appears
// as a substring in the plain-text response body.
func plainTextMetricsReporter(_ context.Context, client *http.Client, url string, expectedMetrics []string) (found, missing []string, err error) {
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	text := string(body)
	for _, name := range expectedMetrics {
		if strings.Contains(text, name) {
			found = append(found, name)
		} else {
			missing = append(missing, name)
		}
	}
	return found, missing, nil
}

func metricsServer(metrics ...string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for _, m := range metrics {
			fmt.Fprintf(w, "%s 0\n", m)
		}
	}))
}

func TestMetricsTest(t *testing.T) {
	srv := metricsServer("http_requests_total", "http_request_duration_seconds")
	defer srv.Close()

	mt := testwebapp.NewMetricsTest(plainTextMetricsReporter,
		testwebapp.MetricsSpec{
			URL:         srv.URL + "/metrics",
			MetricNames: []string{"http_requests_total", "http_request_duration_seconds"},
		},
	)
	if err := mt.Run(t.Context(), srv.Client()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMetricsTest_MissingMetrics(t *testing.T) {
	srv := metricsServer("http_requests_total")
	defer srv.Close()

	mt := testwebapp.NewMetricsTest(plainTextMetricsReporter,
		testwebapp.MetricsSpec{
			URL:         srv.URL + "/metrics",
			MetricNames: []string{"http_requests_total", "http_request_duration_seconds"},
		},
	)
	err := mt.Run(t.Context(), srv.Client())
	if err == nil {
		t.Fatal("expected error for missing metrics, got nil")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("expected 'missing' in error, got: %v", err)
	}
}

func TestMetricsTest_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	mt := testwebapp.NewMetricsTest(plainTextMetricsReporter,
		testwebapp.MetricsSpec{
			URL:         srv.URL + "/metrics",
			MetricNames: []string{"some_metric"},
		},
	)
	err := mt.Run(t.Context(), srv.Client())
	if err == nil {
		t.Fatal("expected error for server error response, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected '500' in error, got: %v", err)
	}
}

func TestMetricsSpecString(t *testing.T) {
	spec := testwebapp.MetricsSpec{
		URL:         "http://example.com/metrics",
		MetricNames: []string{"requests_total", "errors_total"},
	}
	got := spec.String()
	for _, want := range []string{"url: http://example.com/metrics", "requests_total", "errors_total"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, want it to contain %q", got, want)
		}
	}
}

func TestMetricsTest_NilReporter(t *testing.T) {
	mt := testwebapp.NewMetricsTest(nil,
		testwebapp.MetricsSpec{URL: "http://localhost/metrics", MetricNames: []string{"x"}},
	)
	if err := mt.Run(t.Context(), http.DefaultClient); err == nil {
		t.Fatal("expected error for nil reporter, got nil")
	}
}

func TestMetricsTest_NoSpecs(t *testing.T) {
	mt := testwebapp.NewMetricsTest(plainTextMetricsReporter)
	if err := mt.Run(t.Context(), http.DefaultClient); err != nil {
		t.Fatalf("expected no error for empty specs, got: %v", err)
	}
}

func TestMetricsTest_MultipleSpecs(t *testing.T) {
	srv1 := metricsServer("alpha_total")
	defer srv1.Close()
	srv2 := metricsServer("beta_total", "gamma_total")
	defer srv2.Close()

	mt := testwebapp.NewMetricsTest(plainTextMetricsReporter,
		testwebapp.MetricsSpec{URL: srv1.URL + "/metrics", MetricNames: []string{"alpha_total"}},
		testwebapp.MetricsSpec{URL: srv2.URL + "/metrics", MetricNames: []string{"beta_total", "gamma_total"}},
	)
	if err := mt.Run(t.Context(), srv1.Client()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
