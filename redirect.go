// Copyright 2020 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"cloudeng.io/logging/ctxlog"
)

// RedirectTarget is a function that given an http.Request returns
// the target URL for the redirect and the HTTP status code to use.
// The request and in particular the Request.URL should not be modified
// by RedirectTarget.
type RedirectTarget func(*http.Request) (string, int)

// Redirect defines a URL path prefix which will be redirected to
// the specified target.
type Redirect struct {
	Description string         // description of the redirect, only used for logging
	Target      RedirectTarget // function that returns the target URL and HTTP status code
	Log         bool           // if true then log the redirect
}

// Handler returns a function that will redirect requests using
// the Target function to determine the target URL and HTTP status code
// and will log the redirect. It is provided for use with other middleware
// packages that expect an http.Handler.
func (r Redirect) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ru := req.URL.String() // just in case r.Target changes it.
		t, c := r.Target(req)
		if r.Log {
			ctxlog.Info(req.Context(), "redirecting request", "from", ru, "to", t, "ecode", c, "requestor", req.RemoteAddr, "description", r.Description)
		}
		http.Redirect(w, req, t, c)
	}
}

func challengeRewrite(host string, r *http.Request) string {
	nrl := url.URL{
		Scheme: "http",
		Host:   host,
		Path:   r.URL.Path,
	}
	return nrl.String()
}

// RedirectAcmeHTTP01 returns a Redirect that will redirect
// ACME HTTP-01 challenges to the specified host.
func RedirectAcmeHTTP01(host string) Redirect {
	return Redirect{
		Log:         true,
		Description: "redirecting ACME HTTP-01 challenge",
		Target: func(r *http.Request) (string, int) {
			return challengeRewrite(host, r), http.StatusTemporaryRedirect
		},
	}
}

const (
	// ACMEHTTP01Prefix is the well-known prefix for ACME HTTP-01 challenges.
	ACMEHTTP01Prefix = "/.well-known/acme-challenge/"
	// ACMEHTTP01HTTPPrefix is the well-known prefix for ACME HTTP-01 challenges
	// when used with http.ServeMux
	ACMEHTTP01HTTPPrefix = ACMEHTTP01Prefix
	// ACMEHTTP01ChiPrefix is the well-known prefix for ACME HTTP-01 challenges
	// when used with chi.Router
	ACMEHTTP01ChiPrefix = ACMEHTTP01Prefix + "*"
)

func splitHostPort(hostport string) (string, string) {
	if host, port, err := net.SplitHostPort(hostport); err == nil {
		return host, port
	}
	if len(hostport) == 0 {
		return "", ""
	}
	if hostport[0] == '[' && hostport[len(hostport)-1] == ']' {
		return hostport[1 : len(hostport)-1], ""
	}
	return hostport, ""
}

// RedirectToHTTPSPort returns a Redirect that will redirect
// to the specified address using https but with the following defaults:
// - if addr does not contain a host then the host from the request is used
// - if addr does not contain a port then port 443 is used.
func RedirectToHTTPSPort(addr string) Redirect {
	host, port := splitHostPort(addr)
	if len(port) == 0 {
		port = "443"
	}
	return Redirect{
		Description: "redirect to https",
		Target: func(r *http.Request) (string, int) {
			h, _ := splitHostPort(r.Host)
			if len(h) == 0 {
				h = host
			}
			u := *r.URL
			u.Host = net.JoinHostPort(h, port)
			u.Scheme = "https"
			return u.String(), http.StatusMovedPermanently
		},
	}
}

// Port80Redirect is a Redirect that that will be registered using
// http.ServeMux with the specified pattern.
type Port80Redirect struct {
	Pattern string
	Redirect
}

// RedirectPort80 starts an http.Server that will redirect port 80 to the
// specified redirect targets.
// The server will run in the background until the supplied context
// is canceled.
func RedirectPort80(ctx context.Context, redirects ...Port80Redirect) error {
	mux := http.NewServeMux()
	for _, r := range redirects {
		mux.Handle(r.Pattern, r.Handler())
	}
	ln, srv, err := NewHTTPServer(ctx, ":80", mux)
	if err != nil {
		return err
	}
	go func() {
		if err := ServeWithShutdown(ctx, ln, srv, time.Minute); err != nil {
			ctxlog.Logger(ctx).Error("error from http redirect server", "addr", srv.Addr, "err", err.Error())
		}
	}()
	return nil
}

// LiteralRedirectTarget returns a RedirectTarget that always
// redirects to the specified URL with the specified status code.
func LiteralRedirectTarget(to string, code int) RedirectTarget {
	return func(_ *http.Request) (string, int) {
		return to, code
	}
}
