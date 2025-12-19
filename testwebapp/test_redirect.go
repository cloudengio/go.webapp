package testwebapp

import (
	"context"
	"fmt"
	"net/http"

	"cloudeng.io/errors"
	"cloudeng.io/logging/ctxlog"
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
	client *http.Client
	specs  []RedirectSpec
}

func NewRedirectTest(client *http.Client, redirects ...RedirectSpec) *RedirectTest {
	return &RedirectTest{client: client, specs: redirects}
}

func (r RedirectTest) Run(ctx context.Context) error {
	var errs errors.M
	for _, spec := range r.specs {
		err := r.verify(ctx, spec)
		if err != nil {
			ctxlog.Error(ctx, "redirect", "spec", spec, "success", false, "error", err)
			errs.Append(fmt.Errorf("%v: %w", spec, err))
			continue
		}
		ctxlog.Info(ctx, "redirect", "spec", spec, "success", true)
	}
	return errs.Err()
}

func (r RedirectTest) verify(ctx context.Context, spec RedirectSpec) error {
	req, err := http.NewRequestWithContext(ctx, "GET", spec.URL, nil)
	if err != nil {
		return fmt.Errorf("error: %v: %w", err, ErrRedirectUnexpectedError)
	}
	resp, err := r.client.Do(req)
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
