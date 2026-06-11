// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/sync/errgroup"
	"cloudeng.io/webapp/devtest/chromedputil"
	"github.com/cloudengio/chromedp"
	"gopkg.in/yaml.v3"
)

var (
	ErrNavigateUnexpectedError = errors.New("click unexpected error")
	ErrNavigateElementNotFound = errors.New("click element not found")
)

// SelectorAction is an enum of the actions that can be performed on a DOM
// element after it becomes visible. Use WithSelectorActions for actions not
// covered by this enum (e.g. right-click via MouseClickNode).
type SelectorAction string

const (
	// SelectorActionNone waits for the element to be visible but performs no
	// further action. This is the default when no action is specified.
	SelectorActionNone SelectorAction = ""
	// SelectorActionClick performs a single left click on the element.
	SelectorActionClick SelectorAction = "click"
	// SelectorActionDoubleClick performs a double left click on the element.
	SelectorActionDoubleClick SelectorAction = "double_click"
)

func (a SelectorAction) MarshalYAML() (any, error) {
	return string(a), nil
}

func (a *SelectorAction) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch SelectorAction(s) {
	case SelectorActionNone, SelectorActionClick, SelectorActionDoubleClick:
		*a = SelectorAction(s)
		return nil
	default:
		return fmt.Errorf("unknown SelectorAction %q; valid values: %q, %q",
			s, SelectorActionClick, SelectorActionDoubleClick)
	}
}

func (a SelectorAction) chromedpActions(selector string) []chromedp.Action {
	switch a {
	case SelectorActionClick:
		return []chromedp.Action{chromedp.Click(selector)}
	case SelectorActionDoubleClick:
		return []chromedp.Action{chromedp.DoubleClick(selector)}
	default:
		return nil
	}
}

// NavigationSpec represents a specification for verifying and interacting with
// elements on a URL. Action is applied to every selector in Selectors; use
// WithSelectorActions to override the action for individual selectors.
// By default all selectors are waited on concurrently; set SequentialActions
// to true when the actions have ordering dependencies (e.g. clicking one
// element causes another to appear).
type NavigationSpec struct {
	URL               string         `yaml:"url"`
	Selectors         []string       `yaml:"selectors"`
	Action            SelectorAction `yaml:"action"`
	SequentialActions bool           `yaml:"sequential_actions"`
}

// NavigationTest can be used to validate pages by navigating to a URL,
// waiting for DOM elements to exist/be visible, and optionally acting on them.
type NavigationTest struct {
	specs []NavigationSpec
	opts  navigateTestOptions
}

type navigateTestOptions struct {
	timeout            time.Duration
	elementTimeout     time.Duration
	extraExecAllocOpts []chromedp.ExecAllocatorOption
	ctxOpts            []chromedp.ContextOption
	userDataDir        string
	selectorActions    map[string][]chromedp.Action
}

// NavigateOption represents options to configure NavigationTest.
type NavigateOption func(*navigateTestOptions)

// WithTimeout sets the overall timeout for the click test execution (including startup and navigation).
func WithTimeout(timeout time.Duration) NavigateOption {
	return func(o *navigateTestOptions) {
		o.timeout = timeout
	}
}

// WithElementTimeout sets the timeout for waiting for each individual DOM element.
func WithElementTimeout(timeout time.Duration) NavigateOption {
	return func(o *navigateTestOptions) {
		o.elementTimeout = timeout
	}
}

// WithExecAllocatorOptions appends options to the Chrome allocator.
func WithExecAllocatorOptions(opts ...chromedp.ExecAllocatorOption) NavigateOption {
	return func(o *navigateTestOptions) {
		o.extraExecAllocOpts = append(o.extraExecAllocOpts, opts...)
	}
}

// WithContextOptions appends options to the chromedp context.
func WithContextOptions(opts ...chromedp.ContextOption) NavigateOption {
	return func(o *navigateTestOptions) {
		o.ctxOpts = append(o.ctxOpts, opts...)
	}
}

// WithUserDataDir sets the user data directory for Chrome.
func WithUserDataDir(dir string) NavigateOption {
	return func(o *navigateTestOptions) {
		o.userDataDir = dir
	}
}

// WithSuppressedCertErrorsFor configures Chrome to suppress certificate errors
// for connections whose chain includes one of the provided CA certificates.
// Intended for testing against servers using locally issued certificates such
// as those from the Pebble ACME test server.
func WithSuppressedCertErrorsFor(certs ...*x509.Certificate) NavigateOption {
	return WithExecAllocatorOptions(chromedputil.CertPoolAllocatorOption(certs...))
}

// WithSelectorActions registers chromedp actions to run after WaitVisible for
// the given selector. If no actions are registered for a selector, only
// WaitVisible is performed. Call this option once per selector that requires
// additional interaction (e.g. chromedp.Click).
func WithSelectorActions(selector string, actions ...chromedp.Action) NavigateOption {
	return func(o *navigateTestOptions) {
		if o.selectorActions == nil {
			o.selectorActions = make(map[string][]chromedp.Action)
		}
		o.selectorActions[selector] = actions
	}
}

// NewNavigationTest creates a new NavigationTest with the given specs and options.
func NewNavigationTest(specs []NavigationSpec, opts ...NavigateOption) *NavigationTest {
	ct := &NavigationTest{
		specs: specs,
	}
	for _, opt := range opts {
		opt(&ct.opts)
	}
	if ct.opts.timeout == 0 {
		ct.opts.timeout = 30 * time.Second
	}
	if ct.opts.elementTimeout == 0 {
		ct.opts.elementTimeout = 5 * time.Second
	}
	return ct
}

// Run executes the NavigationTest specifications. It runs the specs concurrently
// and uses chromedp via chromedputil to control the browser.
func (c *NavigationTest) Run(ctx context.Context) error {
	ctxlog.Info(ctx, "navigation-test: starting", "num_specs", len(c.specs))
	if len(c.specs) == 0 {
		return nil
	}
	var g errgroup.T
	for _, spec := range c.specs {
		g.Go(func() error {
			err := c.verify(ctx, spec)
			if err != nil {
				ctxlog.Error(ctx, "navigation-test", "spec", spec, "success", false, "error", err)
				return fmt.Errorf("%v: %w", spec, err)
			}
			ctxlog.Info(ctx, "navigation-test", "spec", spec, "success", true)
			return nil
		})
	}
	return g.Wait()
}

func (c *NavigationTest) verify(ctx context.Context, spec NavigationSpec) (err error) {
	// Create a per-spec overall timeout context.
	ctx, cancel := context.WithTimeout(ctx, c.opts.timeout)
	defer cancel()

	// If no user data dir is specified, we create a temp directory per-spec
	// to avoid lock conflicts.
	userDataDir := c.opts.userDataDir
	var tempDir string
	if len(userDataDir) == 0 {
		tempDir, err = os.MkdirTemp("", "navigation-test-spec-")
		if err != nil {
			return fmt.Errorf("failed to create user data directory: %w: %w", err, ErrNavigateUnexpectedError)
		}
		defer func() {
			_ = os.RemoveAll(tempDir)
		}()
		userDataDir = tempDir
	}

	chromeCtx, chromeCancel := chromedputil.WithContextForCI(ctx, userDataDir, c.opts.extraExecAllocOpts, c.opts.ctxOpts...)
	defer chromeCancel()

	// Navigate to the URL first.
	ctxlog.Info(chromeCtx, "navigation-test: navigating", "url", spec.URL)
	if err := chromedp.Run(chromeCtx, chromedp.Navigate(spec.URL)); err != nil {
		return fmt.Errorf("failed to navigate to %s: %w: %w", spec.URL, err, ErrNavigateUnexpectedError)
	}

	if spec.SequentialActions {
		for _, selector := range spec.Selectors {
			if err := c.runSelector(chromeCtx, spec, selector); err != nil {
				return err
			}
		}
		return nil
	}
	var g errgroup.T
	for _, selector := range spec.Selectors {
		g.Go(func() error { return c.runSelector(chromeCtx, spec, selector) })
	}
	return g.Wait()
}

func (c *NavigationTest) runSelector(ctx context.Context, spec NavigationSpec, selector string) error {
	actions := []chromedp.Action{chromedp.WaitVisible(selector)}
	if extra, ok := c.opts.selectorActions[selector]; ok {
		actions = append(actions, extra...)
	} else if specActions := spec.Action.chromedpActions(selector); len(specActions) > 0 {
		actions = append(actions, specActions...)
	}
	ctxlog.Info(ctx, "navigatetest: waiting for selector", "selector", selector, "num_actions", len(actions)-1)

	stepCtx, stepCancel := context.WithTimeout(ctx, c.opts.elementTimeout)
	err := chromedp.Run(stepCtx, actions...)
	stepCancel()

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("selector %q not found or not visible before timeout: %w: %w", selector, err, ErrNavigateElementNotFound)
		}
		return fmt.Errorf("error on selector %q: %w: %w", selector, err, ErrNavigateUnexpectedError)
	}
	return nil
}
