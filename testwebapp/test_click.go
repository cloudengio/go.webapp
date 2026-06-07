// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/sync/errgroup"
	"cloudeng.io/webapp/devtest/chromedputil"
	"github.com/cloudengio/chromedp"
)

var (
	ErrClickUnexpectedError = errors.New("click unexpected error")
	ErrClickElementNotFound = errors.New("click element not found")
)

// ClickSpec represents a specification for verifying and clicking elements on a URL.
type ClickSpec struct {
	URL       string   `yaml:"url" json:"url"`
	Selectors []string `yaml:"selectors" json:"selectors"`
}

// ClickTest can be used to validate pages by navigating to a URL,
// waiting for DOM elements to exist/be visible, and clicking them sequentially.
type ClickTest struct {
	specs []ClickSpec
	opts  clickTestOptions
}

type clickTestOptions struct {
	timeout            time.Duration
	extraExecAllocOpts []chromedp.ExecAllocatorOption
	ctxOpts            []chromedp.ContextOption
	userDataDir        string
}

// ClickOption represents options to configure ClickTest.
type ClickOption func(*clickTestOptions)

// WithTimeout sets the timeout for the click test execution.
func WithTimeout(timeout time.Duration) ClickOption {
	return func(o *clickTestOptions) {
		o.timeout = timeout
	}
}

// WithExecAllocatorOptions appends options to the Chrome allocator.
func WithExecAllocatorOptions(opts ...chromedp.ExecAllocatorOption) ClickOption {
	return func(o *clickTestOptions) {
		o.extraExecAllocOpts = append(o.extraExecAllocOpts, opts...)
	}
}

// WithContextOptions appends options to the chromedp context.
func WithContextOptions(opts ...chromedp.ContextOption) ClickOption {
	return func(o *clickTestOptions) {
		o.ctxOpts = append(o.ctxOpts, opts...)
	}
}

// WithUserDataDir sets the user data directory for Chrome.
func WithUserDataDir(dir string) ClickOption {
	return func(o *clickTestOptions) {
		o.userDataDir = dir
	}
}

// NewClickTest creates a new ClickTest with the given specs and options.
func NewClickTest(specs []ClickSpec, opts ...ClickOption) *ClickTest {
	ct := &ClickTest{
		specs: specs,
	}
	for _, opt := range opts {
		opt(&ct.opts)
	}
	if ct.opts.timeout == 0 {
		ct.opts.timeout = 10 * time.Second
	}
	return ct
}

// Run executes the ClickTest specifications. It runs the specs concurrently
// and uses chromedp via chromedputil to control the browser.
func (c *ClickTest) Run(ctx context.Context) error {
	if len(c.specs) == 0 {
		return nil
	}
	var g errgroup.T
	for _, spec := range c.specs {
		g.Go(func() error {
			err := c.verify(ctx, spec)
			if err != nil {
				ctxlog.Error(ctx, "clicktest", "spec", spec, "success", false, "error", err)
				return fmt.Errorf("%v: %w", spec, err)
			}
			ctxlog.Info(ctx, "clicktest", "spec", spec, "success", true)
			return nil
		})
	}
	return g.Wait()
}

func (c *ClickTest) verify(ctx context.Context, spec ClickSpec) (err error) {
	// Create a per-spec timeout context.
	ctx, cancel := context.WithTimeout(ctx, c.opts.timeout)
	defer cancel()

	// If no user data dir is specified, we create a temp directory per-spec
	// to avoid lock conflicts.
	userDataDir := c.opts.userDataDir
	var tempDir string
	if len(userDataDir) == 0 {
		tempDir, err = os.MkdirTemp("", "clicktest-spec-")
		if err != nil {
			return fmt.Errorf("failed to create user data directory: %v: %w", err, ErrClickUnexpectedError)
		}
		defer func() {
			_ = os.RemoveAll(tempDir)
		}()
		userDataDir = tempDir
	}

	chromeCtx, chromeCancel := chromedputil.WithContextForCI(ctx, userDataDir, c.opts.extraExecAllocOpts, c.opts.ctxOpts...)
	defer chromeCancel()

	// Navigate to the URL first.
	ctxlog.Info(chromeCtx, "clicktest: navigating", "url", spec.URL)
	if err := chromedp.Run(chromeCtx, chromedp.Navigate(spec.URL)); err != nil {
		return fmt.Errorf("failed to navigate to %s: %v: %w", spec.URL, err, ErrClickUnexpectedError)
	}

	// Sequentially check and click each selector.
	for _, selector := range spec.Selectors {
		ctxlog.Info(chromeCtx, "clicktest: waiting/clicking selector", "selector", selector)
		err := chromedp.Run(chromeCtx,
			chromedp.WaitVisible(selector),
			chromedp.Click(selector),
		)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("selector %q not found or not visible before timeout: %v: %w", selector, err, ErrClickElementNotFound)
			}
			return fmt.Errorf("error clicking selector %q: %v: %w", selector, err, ErrClickUnexpectedError)
		}
	}

	return nil
}
