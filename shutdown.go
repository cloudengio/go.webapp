// Copyright 2021 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/net/netutil"
	"cloudeng.io/sync/errgroup"
)

// ServeWithShutdown runs srv.ListenAndServe in background and then
// waits for the context to be canceled. It will then attempt to shutdown
// the web server within the specified grace period.
// If srv.BaseContext is nil it will be set to return ctx.
func ServeWithShutdown(ctx context.Context, ln net.Listener, srv *http.Server, grace time.Duration) error {
	return serveWithShutdown(ctx, srv, ln, grace, func(srv *http.Server, ln net.Listener) error {
		return srv.Serve(ln)
	})
}

// ServeTLSWithShutdown is like ServeWithShutdown except for a TLS server.
// Note that any TLS options must be configured prior to calling this
// function via the TLSConfig field in http.Server.
// If srv.BaseContext is nil it will be set to return ctx.
func ServeTLSWithShutdown(ctx context.Context, ln net.Listener, srv *http.Server, grace time.Duration) error {
	if srv.TLSConfig == nil {
		return fmt.Errorf("ServeTLSWithShutdown requires a non-nil TLSConfig in the http.Server")
	}
	return serveWithShutdown(ctx, srv, ln, grace, func(srv *http.Server, ln net.Listener) error {
		return srv.ServeTLS(ln, "", "")
	})
}

func serveWithShutdown(ctx context.Context, srv *http.Server, ln net.Listener, grace time.Duration, fn func(srv *http.Server, ln net.Listener) error) error {

	if srv.BaseContext == nil {
		srv.BaseContext = func(_ net.Listener) context.Context {
			return ctx
		}
	}

	serveErrCh := make(chan error, 1)
	go func() {
		err := fn(srv, ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrCh <- err
			return
		}
		serveErrCh <- nil
		close(serveErrCh)
	}()

	select {
	case err := <-serveErrCh:
		if err != nil {
			return fmt.Errorf("server %v, unexpected error %w", srv.Addr, err)
		}
		return nil
	case <-ctx.Done():
		ctxlog.Logger(ctx).Info("server being shut down", "addr", srv.Addr, "grace", grace)
	}

	// Use a new context tree for the shutdown, since the original
	// was only intended to signal starting the shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("server running on %v, shutdown failed %s: %w", srv.Addr, grace, err)
	}
	select {
	case err := <-serveErrCh:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// NewHTTPServerOnly returns a new *http.Server whose address defaults
// to ":http" and with it's BaseContext set to the supplied context.
// ErrorLog is set to log errors via the ctxlog package.
func NewHTTPServerOnly(ctx context.Context, addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: time.Minute,
		ErrorLog:          ctxlog.NewLogLogger(ctx, slog.LevelError),
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}
}

// NewTLSServerOnly returns a new *http.Server whose address defaults
// to ":https" and with it's BaseContext set to the supplied context and
// TLSConfig set to the supplied config.
// ErrorLog is set to log errors via the ctxlog package.
func NewTLSServerOnly(ctx context.Context, addr string, handler http.Handler, cfg *tls.Config) *http.Server {
	hs := NewHTTPServerOnly(ctx, addr, handler)
	hs.TLSConfig = cfg
	return hs
}

// NewHTTPServer returns a new *http.Server using netutil.ParseAddrDefaultPort(addr "http")
// to obtain the address to listen on and NewHTTPServerOnly to create the server.
func NewHTTPServer(ctx context.Context, addr string, handler http.Handler) (net.Listener, *http.Server, error) {
	return newServer(ctx, addr, "http", handler, nil)
}

// NewTLSServer returns a new *http.Server using netutil.ParseAddrDefaultPort(addr, "https")
// to obtain the address to listen on and NewTLSServerOnly to create the server.
func NewTLSServer(ctx context.Context, addr string, handler http.Handler, cfg *tls.Config) (net.Listener, *http.Server, error) {
	return newServer(ctx, addr, "https", handler, cfg)
}

func newServer(ctx context.Context, addr, port string, handler http.Handler, cfg *tls.Config) (net.Listener, *http.Server, error) {
	ap, err := netutil.ParseAddrDefaultPort(addr, port)
	if err != nil {
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", netutil.HTTPServerAddr(ap))
	if err != nil {
		return nil, nil, err
	}
	if cfg == nil {
		srv := NewHTTPServerOnly(ctx, addr, handler)
		return ln, srv, nil
	}
	srv := NewTLSServerOnly(ctx, addr, handler, cfg)
	return ln, srv, nil
}

// WaitForServers waits for all supplied addresses to be available
// by attempting to open a TCP connection to each address at the
// specified interval.
func WaitForServers(ctx context.Context, interval time.Duration, addrs ...string) error {
	switch len(addrs) {
	case 0:
		return nil
	case 1:
		return ping(ctx, interval, addrs[0])
	}
	g, ctx := errgroup.WithContext(ctx)
	for _, addr := range addrs {
		g.Go(func() error {
			return ping(ctx, interval, addr)
		})
	}
	return g.Wait()
}

func ping(ctx context.Context, interval time.Duration, addr string) error {
	for {
		ctxlog.Logger(ctx).Info("waitForServers: server", "addr", addr)
		_, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return nil
		}
		ctxlog.Logger(ctx).Debug("waitForServers: server not available yet", "addr", addr, "error", err.Error())
		if errors.Is(err, context.Canceled) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
			ctxlog.Info(ctx, "waitForServers: server timeout", "addr", addr, "duration", interval.String())

		}
	}
}

// WaitForURLs waits for all supplied URLs to be available
// by attempting to perform HTTP GET requests to each URL
// at the specified interval.
func WaitForURLs(ctx context.Context, client *http.Client, interval time.Duration, urls ...string) error {
	if client == nil {
		client = &http.Client{
			Timeout: time.Second,
		}
	}
	switch len(urls) {
	case 0:
		return nil
	case 1:
		return pingURL(ctx, client, interval, urls[0])
	}
	g, ctx := errgroup.WithContext(ctx)
	for _, url := range urls {
		g.Go(func() error {
			return pingURL(ctx, client, interval, url)
		})
	}
	return g.Wait()
}

func pingURL(ctx context.Context, client *http.Client, interval time.Duration, url string) error {
	{
		for {
			ctxlog.Logger(ctx).Info("ping: url", "url", url)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return fmt.Errorf("failed to create request for %s: %w", url, err)
			}
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 400 {
				return nil
			}
			if errors.Is(err, context.Canceled) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
				ctxlog.Info(ctx, "ping: url timeout", "url", url, "duration", interval.String())

			}
		}
	}
}

// SameFileHTTPFilesystem is an http.FileSystem that always returns the same
// file regardless of the name used to open it. It is typically used
// to serve index.html, or any other single file regardless of
// the requested path, eg:
//
// http.Handle("/", http.FileServer(SameFileHTTPFilesystem(assets, "index.html")))
type SameFileHTTPFilesystem struct {
	filename string
	fs       http.FileSystem
}

// NewSameFileHTTPFilesystem returns a new SameFileHTTPFilesystem that always returns
// the specified filename when opened.
func NewSameFileHTTPFilesystem(fs fs.FS, filename string) http.FileSystem {
	return &SameFileHTTPFilesystem{
		filename: filename,
		fs:       http.FS(fs),
	}
}

// Open implements http.FileSystem.
func (sff *SameFileHTTPFilesystem) Open(name string) (http.File, error) {
	return sff.fs.Open(sff.filename)
}
