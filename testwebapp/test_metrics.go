// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp

import (
	"context"
	"fmt"
	"net/http"

	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/sync/errgroup"
)

// MetricsTest can be used to validate /metrics endpoints.
type MetricsTest struct {
	reporter MetricsReporter
	specs    []MetricsSpec
}

type MetricsSpec struct {
	URL         string   `yaml:"url,omitempty"`
	MetricNames []string `yaml:"names,omitempty"`
}

type MetricsReporter func(ctx context.Context, client *http.Client, url string, expectedMetrics []string) (found, missing []string, err error)

func NewMetricsTest(reporter MetricsReporter, specs ...MetricsSpec) *MetricsTest {
	return &MetricsTest{
		reporter: reporter,
		specs:    specs,
	}
}

func (m MetricsTest) Run(ctx context.Context, client *http.Client) error {
	ctxlog.Info(ctx, "metrics: starting", "num_specs", len(m.specs))
	if len(m.specs) == 0 {
		return nil
	}
	if m.reporter == nil {
		return fmt.Errorf("metrics reporter is nil")
	}
	client = newClient(client)
	var g errgroup.T
	for _, metric := range m.specs {
		g.Go(func() error {
			found, missing, err := m.reporter(ctx, client, metric.URL, metric.MetricNames)
			if err != nil {
				ctxlog.Error(ctx, "metrics", "spec", metric, "success", false, "error", err)
				return fmt.Errorf("error checking metrics existence at %v: %v", metric.URL, err)
			}
			if len(missing) > 0 {
				err := fmt.Errorf("some expected metrics for url %v were missing: %v", metric.URL, missing)
				ctxlog.Error(ctx, "metrics", "spec", metric, "success", false, "error", err)
				return err
			}
			ctxlog.Info(ctx, "metrics", "spec", metric, "found", found, "success", true)
			return nil
		})
	}
	return g.Wait()
}
