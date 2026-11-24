// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"slices"
	"strings"
	"testing"
)

func TestOpenLinkCommand(t *testing.T) {
	const link = "http://127.0.0.1:8099/path?a=1&b=2"
	for _, tc := range []struct {
		goos string
		want []string
	}{
		{"darwin", []string{"open", link}},
		// The link is passed as an argument of its own rather than through a
		// shell, so the & in it separates nothing.
		{"windows", []string{"rundll32", "url.dll,FileProtocolHandler", link}},
		{"linux", []string{"xdg-open", link}},
		{"freebsd", []string{"xdg-open", link}},
	} {
		cmd, err := openLinkCommand(tc.goos, link)
		if err != nil {
			t.Errorf("%v: %v", tc.goos, err)
			continue
		}
		if got := cmd.Args; !slices.Equal(got, tc.want) {
			t.Errorf("%v: got %v, want %v", tc.goos, got, tc.want)
		}
	}
}

func TestOpenLinkRejects(t *testing.T) {
	for _, link := range []string{
		"",
		"/etc/passwd",
		"file:///etc/passwd",
		"/Applications/Calculator.app",
		"-a Calculator",
		"javascript:alert(1)",
		"http://",
		"ftp://example.com/",
	} {
		if _, err := openLinkCommand("darwin", link); err == nil {
			t.Errorf("%q: expected it to be refused", link)
		}
		// OpenLink refuses it the same way, before running anything.
		if err := OpenLink(link); err == nil {
			t.Errorf("%q: OpenLink should have refused it", link)
		}
	}
	if _, err := openLinkCommand("plan9", "https://example.com/"); err == nil ||
		!strings.Contains(err.Error(), "not supported on plan9") {
		t.Errorf("got %v, want an error naming the unsupported system", err)
	}
}
