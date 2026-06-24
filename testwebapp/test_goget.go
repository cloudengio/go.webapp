// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"cloudeng.io/errors"
	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/webapp/goget"
)

var (
	ErrGoGetUnexpectedError = errors.New("go-get unexpected error")
	ErrGoGetPathNotFound    = errors.New("go-get path not found")
	ErrGoGetNotFound        = errors.New("go-get meta tag not found")
	ErrGoGetContentMismatch = errors.New("go-get meta tag content mismatch")
)

// GoGetTest can be used to validate go-get meta tags for a set of import paths.
type GoGetTest struct {
	specs []goget.Spec
}

func NewGoGetTest(specs ...goget.Spec) *GoGetTest {
	return &GoGetTest{specs: specs}
}

func (g GoGetTest) Run(ctx context.Context, client *http.Client) error {
	ctxlog.Info(ctx, "goget: starting", "num_specs", len(g.specs))
	client = newClient(client)
	var errs errors.M
	for _, spec := range g.specs {
		err := g.verify(ctx, spec, client)
		if err != nil {
			ctxlog.Error(ctx, "goget", "spec", spec, "success", false, "error", err)
			errs.Append(fmt.Errorf("%v: %w", spec, err))
			continue
		}
		ctxlog.Info(ctx, "goget", "spec", spec, "success", true)
	}
	return errs.Err()
}

func (g GoGetTest) verify(ctx context.Context, expected goget.Spec, client *http.Client) error {
	u := "https://" + expected.ImportPath + "?go-get=1"
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return ErrGoGetUnexpectedError
	}
	return verify(req, client, expected)
}

func verify(req *http.Request, client *http.Client, expected goget.Spec) error {
	resp, err := client.Do(req) //nolint:gosec // G704 is too restrictive here
	if err != nil {
		return fmt.Errorf("error: %v: %w", err, ErrGoGetUnexpectedError)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return ErrGoGetPathNotFound
		}
		return ErrGoGetUnexpectedError
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error: %v: %w", err, ErrGoGetUnexpectedError)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, `<meta name="go-import" content="`) {
		return fmt.Errorf("%v: %w", bodyStr, ErrGoGetNotFound)
	}
	// Depending on the webserver, the meta tag may be self-closing or not.
	expectedTag := fmt.Sprintf(`<meta name="go-import" content="%s">`, expected.Content)
	expectedTagSlash := fmt.Sprintf(`<meta name="go-import" content="%s"/>`, expected.Content)
	if !strings.Contains(bodyStr, expectedTagSlash) &&
		!strings.Contains(bodyStr, expectedTag) {
		return fmt.Errorf("%v: %w", firstNLines(bodyStr, 2), ErrGoGetContentMismatch)
	}
	return nil
}

func firstNLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) < n {
		return s
	}
	return strings.Join(lines[:n], "\n")
}
