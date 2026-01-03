// Copyright 2021 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"cloudeng.io/aws/awsconfig"
	"cloudeng.io/webapp"
	"cloudeng.io/webapp/webauth/acme/certcache"
)

type testRedirectFlags struct {
	TLSCertStoreFlags
	webapp.HTTPServerFlags
	AcmeClientHost string `subcmd:"acme-client-host,,the host (with optional port) to which ACME HTTP-01 challenge requests will be redirected."`
	awsconfig.AWSFlags
}

type testRedirectCmd struct{}

func (testRedirectCmd) redirect(ctx context.Context, values any, _ []string) error {
	ctx, done := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer done()
	cl := values.(*testRedirectFlags)

	if len(cl.AcmeClientHost) == 0 {
		return fmt.Errorf("must specific a target for the acme client")
	}

	cfg := cl.HTTPServerConfig()

	if err := webapp.RedirectPort80(ctx,
		webapp.Port80Redirect{
			Pattern:  webapp.ACMEHTTP01Prefix,
			Redirect: webapp.RedirectAcmeHTTP01(cl.AcmeClientHost)},
		webapp.Port80Redirect{
			Pattern:  "/",
			Redirect: webapp.RedirectToHTTPSPort(cfg.Address)}); err != nil {
		return err
	}

	cache, err := newCertStore(ctx, cl.TLSCertStoreFlags, cl.AWSFlags, certcache.WithReadonly(false))
	if err != nil {
		return err
	}

	tlsCfg, err := webapp.TLSConfigUsingCertStore(ctx, cache)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "hello\n")
	})
	ln, srv, err := webapp.NewTLSServer(ctx, cl.Address, mux, tlsCfg)
	if err != nil {
		return err
	}
	fmt.Printf("listening on: %v\n", ln.Addr())
	srv.TLSConfig = tlsCfg
	return webapp.ServeTLSWithShutdown(ctx, ln, srv, time.Minute)
}
