// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"

	"cloudeng.io/cmdutil/subcmd"
)

const cmdSpec = `name: certbot
summary: certbot is a command line tool for managing SSL certificates:
  - name: acme
    summary: commands to obtain/renew certificates from letsencrypt.org
    commands:
      - name: obtain
        arguments:
          - hostnames... - the hostnames to obtain certificates for
`

func cli() *subcmd.CommandSetYAML {
	cmd := subcmd.MustFromYAML(cmdSpec)

	acme := &ACME{}
	cmd.Set("acme", "obtain").MustRunner(acme.Obtain, &ACMEFlags{})
	cmd.Set("acme", "renew").MustRunner(acme.Renew, &ACMEFlags{})
	cmd.Set("acme", "serve").MustRunner(acme.Serve, &ACMEFlags{})

	return cmd
}

var errInterrupt = errors.New("interrupt")

func main() {
	ctx := context.Background()
	subcmd.Dispatch(ctx, cli())
}
