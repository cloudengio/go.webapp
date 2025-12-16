// Copyright 2020 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cloudeng.io/logging/ctxlog"
)

// RedirectTarget is a function that given an http.Request returns
// the target URL for the redirect and the HTTP status code to use.
type RedirectTarget func(*http.Request) (string, int)

// Redirect defines a URL path prefix which will be redirected to
// the specified target.
type Redirect struct {
	Prefix string
	Target RedirectTarget
}

// newRedirectHandler creates a RedirectHandler that will redirect
// requests based on the supplied redirects.
func newRedirectHandler(redirects ...Redirect) http.Handler {
	mux := http.NewServeMux()
	for _, r := range redirects {
		p := strings.TrimSuffix(r.Prefix, "/") + "/"
		mux.HandleFunc(p, func(w http.ResponseWriter, req *http.Request) {
			t, c := r.Target(req)
			http.Redirect(w, req, t, c)
			ctxlog.Info(req.Context(), "redirecting request", "from", req.URL.String(), "to", t, "code", c)
		})
	}
	return mux
}

func challengeRewrite(host string, r *http.Request) string {
	nrl := url.URL{
		Scheme: "http",
		Host:   host,
		Path:   r.URL.Path,
	}
	target := nrl.String()
	ctxlog.Info(r.Context(), "redirecting acme challenge", "redirect", target)
	return target
}

// RedirectAcmeHTTP01 returns a Redirect that will redirect
// ACME HTTP-01 challenges to the specified host.
func RedirectAcmeHTTP01(host string) Redirect {
	return Redirect{
		Prefix: "/.well-known/acme-challenge/",
		Target: func(r *http.Request) (string, int) {
			return challengeRewrite(host, r), http.StatusTemporaryRedirect
		},
	}
}

// RedirectToHTTPSPort returns a Redirect that will redirect
// to the specified address using https but with the following defaults:
// - if addr does not contain a host then the host from the request is used
// - if addr does not contain a port then port 443 is used.
func RedirectToHTTPSPort(addr string) Redirect {
	host, port := SplitHostPort(addr)
	if len(port) == 0 {
		port = "443"
	}
	return Redirect{
		Prefix: "/",
		Target: func(r *http.Request) (string, int) {
			h, _ := SplitHostPort(r.Host)
			if len(h) == 0 {
				h = host
			}
			u := r.URL
			u.Host = net.JoinHostPort(h, port)
			u.Scheme = "https"
			return u.String(), http.StatusMovedPermanently
		},
	}
}

func RedirectHandler(redirects ...Redirect) http.Handler {
	return newRedirectHandler(redirects...)
}

// RedirectPort80 starts an http.Server that will redirect port 80 to the
// specified redirect targets.
// The server will run in the background until the supplied context
// is canceled.
func RedirectPort80(ctx context.Context, redirects ...Redirect) error {
	rh := newRedirectHandler(redirects...)
	ln, srv, err := NewHTTPServer(ctx, ":80", rh)
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
