// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/sync/errgroup"
)

var (
	ErrCheckStatusUnexpectedError = errors.New("check status unexpected error")
	ErrCheckStatusCodeMismatch    = errors.New("check status code mismatch")
)

// CheckStatusSpec represents a specification for a status check after following redirects.
type CheckStatusSpec struct {
	URL       string `yaml:"url" json:"url"`
	Code      int    `yaml:"code" json:"code"`
	Redirects int    `yaml:"redirects" json:"redirects"`
}

// CheckStatus validates that a set of URLs return a given status code after
// following up to a configurable number of redirects.
type CheckStatus struct {
	specs []CheckStatusSpec
}

// NewCheckStatus creates a new CheckStatus for the given specs.
func NewCheckStatus(specs ...CheckStatusSpec) *CheckStatus {
	return &CheckStatus{specs: specs}
}

func (c *CheckStatus) Run(ctx context.Context, client *http.Client) error {
	var g errgroup.T
	for _, spec := range c.specs {
		g.Go(func() error {
			err := c.verify(ctx, spec, client)
			if err != nil {
				ctxlog.Error(ctx, "check-status", "spec", spec, "success", false, "error", err)
				return fmt.Errorf("%v: %w", spec, err)
			}
			ctxlog.Info(ctx, "check-status", "spec", spec, "success", true)
			return nil
		})
	}
	return g.Wait()
}

func (c *CheckStatus) verify(ctx context.Context, spec CheckStatusSpec, client *http.Client) error {
	local := *client
	maxRedirects := spec.Redirects
	local.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", spec.URL, nil)
	if err != nil {
		return fmt.Errorf("error: %v: %w", err, ErrCheckStatusUnexpectedError)
	}
	resp, err := local.Do(req) //nolint:gosec // G107 is too restrictive here
	if err != nil {
		return fmt.Errorf("error: %v: %w", err, ErrCheckStatusUnexpectedError)
	}
	defer resp.Body.Close()
	if resp.StatusCode != spec.Code {
		return fmt.Errorf("status code: %v, want: %v: %w", resp.StatusCode, spec.Code, ErrCheckStatusCodeMismatch)
	}
	return nil
}

// GenerateCheckStatusSpecs generates a slice of CheckStatusSpec for the
// given URLs, status code and number of redirects.
func GenerateCheckStatusSpecs(urls []string, code int, redirects int) []CheckStatusSpec {
	specs := make([]CheckStatusSpec, len(urls))
	for i, url := range urls {
		specs[i] = CheckStatusSpec{
			URL:       url,
			Code:      code,
			Redirects: redirects,
		}
	}
	return specs
}
