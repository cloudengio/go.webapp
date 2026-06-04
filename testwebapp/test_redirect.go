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
	ErrRedirectUnexpectedError    = errors.New("redirect unexpected error")
	ErrRedirectPathNotFound       = errors.New("redirect path not found")
	ErrRedirectTargetMismatch     = errors.New("redirect target mismatch")
	ErrRedirectStatusCodeMismatch = errors.New("redirect status code mismatch")
)

// RedirectSpec represents a specification for a redirect test.
type RedirectSpec struct {
	URL    string `yaml:"url" json:"url"`
	Target string `yaml:"target" json:"target"`
	Code   int    `yaml:"code" json:"code"`
}

// RedirectTest can be used to validate redirects for a set of URLs.
type RedirectTest struct {
	specs []RedirectSpec
}

// NewRedirectTest creates a new RedirectTest, if client.CheckRedirect
// is nil, it will be set to http.ErrUseLastResponse to ensure that redirects
// are not followed.
func NewRedirectTest(redirects ...RedirectSpec) *RedirectTest {
	return &RedirectTest{specs: redirects}
}

func (r RedirectTest) Run(ctx context.Context, client *http.Client) error {
	if client.CheckRedirect == nil {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	var g errgroup.T
	for _, spec := range r.specs {
		g.Go(func() error {
			err := r.verify(ctx, spec, client)
			if err != nil {
				ctxlog.Error(ctx, "redirect", "spec", spec, "success", false, "error", err)
				return fmt.Errorf("%v: %w", spec, err)
			}
			ctxlog.Info(ctx, "redirect", "spec", spec, "success", true)
			return nil
		})
	}
	return g.Wait()
}

func (r RedirectTest) verify(ctx context.Context, spec RedirectSpec, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, "GET", spec.URL, nil)
	if err != nil {
		return fmt.Errorf("error: %v: %w", err, ErrRedirectUnexpectedError)
	}
	resp, err := client.Do(req) //nolint:gosec // G704 is too restrictive here
	if err != nil {
		return fmt.Errorf("error: %v: %w", err, ErrRedirectUnexpectedError)
	}
	defer resp.Body.Close()
	if resp.StatusCode != spec.Code {
		return fmt.Errorf("redirect code: %v, want: %v: %w", resp.StatusCode, spec.Code, ErrRedirectStatusCodeMismatch)
	}
	if resp.Header.Get("Location") != spec.Target {
		return fmt.Errorf("location: %v, want: %v: %w", resp.Header.Get("Location"), spec.Target, ErrRedirectTargetMismatch)
	}
	return nil
}
