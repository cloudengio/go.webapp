// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

// OpenLink opens link, which must be an http or https URL, in the user's
// default browser. It returns once the browser has been asked to open it,
// without waiting for the browser.
func OpenLink(link string) error {
	cmd, err := openLinkCommand(runtime.GOOS, link)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("opening %v: %w", link, err)
	}
	// Reaped so that a command which exits at once leaves no zombie.
	go func() { _ = cmd.Wait() }()
	return nil
}

// openLinkCommand returns the command that opens link on goos. Only http and
// https URLs are accepted, since each of these commands also opens files and
// applications.
func openLinkCommand(goos, link string) (*exec.Cmd, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid link %q: %w", link, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid link %q: only http and https URLs can be opened", link)
	}
	switch goos {
	case "darwin":
		return exec.Command("open", link), nil
	case "windows":
		// Not 'cmd /c start', whose shell would treat the & of a query
		// string as separating commands.
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", link), nil
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly", "solaris", "illumos":
		return exec.Command("xdg-open", link), nil
	}
	return nil, fmt.Errorf("cannot open %v: opening links is not supported on %v", link, goos)
}
