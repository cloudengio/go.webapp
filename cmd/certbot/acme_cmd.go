// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package main

import "context"

type ACMEFlags struct{}

type ACMEHostFlags struct {
	Domain string `subcmd:"domain,,'the domain to obtain certificates for'"`
}

type ACME struct{}

func (a *ACME) Obtain(ctx context.Context, flags any, args []string) error {
	return nil
}

func (a *ACME) Renew(ctx context.Context, flags any, args []string) error {
	return nil
}

func (a *ACME) Serve(ctx context.Context, flags any, args []string) error {
	return nil
}
