// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"fmt"

	"cloudeng.io/cmdutil/cmdyaml"
	"cloudeng.io/webapp/ipacl"
)

// Config represents the configuration for a webhook server.
type Config struct {
	PublicAddr   string            `yaml:"public_addr" doc:"public address to serve webhooks on"`
	PublicIPACL  ipacl.Config      `yaml:"public_ip_acl" doc:"ACL of IPs allowed to access the webhook, if not specified all IPs are allowed"`
	PrivateAddr  string            `yaml:"private_addr" doc:"private address to listen on for webhook requests"`
	PrivateIPACL ipacl.Config      `yaml:"private_ip_acl" doc:"ACL of IPs allowed to access the webhook on the private address, if not specified all IPs are allowed"`
	Path         string            `yaml:"path" doc:"path to serve webhooks on"`
	Service      string            `yaml:"service" doc:"type of webhook to serve, e.g. github, etc."`
	Specific     *cmdyaml.Deferred `yaml:",inline" doc:"additional details about the webhook specific to the type of webhook being served"`
}

// GithubWebhookConfig represents the configuration specific to
// a GitHub webhook. In particular the secrete used to validate the
// webhook requests is accessed via a
// cloudeng.io/cmdutil/keys.InMemoryKeyStore item specified by the KeychainItemUser and KeychainItemTokenID fields.
// The keystore itself will be populated by the server hosting the
// webhook.
type GithubWebhookConfig struct {
	KeychainItemUser    string `yaml:"secret_user" doc:"user name of the key containing the GitHub webhook secret"`
	KeychainItemTokenID string `yaml:"secret_id" doc:"ID of the key containing the GitHub webhook secret as a token"`
}

var (
	ErrWrongServiceSpecificConfig = fmt.Errorf("missing service specific config")
)

func (c Config) Github() (*GithubWebhookConfig, error) {
	if c.Service != "github" {
		return nil, fmt.Errorf("service %q is not github: %w", c.Service, ErrWrongServiceSpecificConfig)
	}
	ghc, err := cmdyaml.ParseDeferred[GithubWebhookConfig](c.Specific)
	if err != nil {
		return nil, fmt.Errorf("failed to parse github webhook config: %w", err)
	}
	return &ghc, nil
}
