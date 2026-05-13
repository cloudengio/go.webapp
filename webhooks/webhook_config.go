// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"context"
	"fmt"

	"cloudeng.io/cmdutil/cmdyaml"
	"cloudeng.io/cmdutil/keys"
	"gopkg.in/yaml.v3"
)

// Config represents the configuration for a webhook server.
type Config struct {
	Path     string            `yaml:"path" doc:"path to serve webhooks on"`
	Service  string            `yaml:"service" doc:"type of webhook to serve, e.g. github, etc."`
	Specific *cmdyaml.Deferred `yaml:",inline" doc:"additional details about the webhook specific to the type of webhook being served"`
}

// SecretsConfig represents a common configuration that uses
// cloudeng.io/cmdutil/keys.KeySpec to specify the secrets to be used for
// validating webhooks. User and Secrets fields can be unmarshaled from YAML,
// but the SecretSpecs field is populated based on those fields by the
// UnmarshalYAML.
type SecretsConfig struct {
	User        string         `yaml:"user" doc:"user to associate with a key id if the KeySpec does not specify a user"`
	Secrets     []string       `yaml:"secrets" doc:"list of KeySpecs specifying the secrets to use for validating webhooks in cloudeng.io.cmdutil/keys.KeySpec format, i.e. id[user] or id. If not user is specified in the KeySpec, the user field will be used."`
	SecretSpecs []keys.KeySpec `yaml:"-" doc:"parsed KeySpecs from the Secrets field"`
}

func (sc *SecretsConfig) UnmarshalYAML(node *yaml.Node) error {
	r := struct {
		User        string   `yaml:"user"`
		SecretSpecs []string `yaml:"secrets"`
	}{}
	if err := node.Decode(&r); err != nil {
		return fmt.Errorf("unmarshal: %v", err)
	}
	sc.User = r.User
	sc.SecretSpecs = make([]keys.KeySpec, len(r.SecretSpecs))
	for i, spec := range r.SecretSpecs {
		ks := keys.ParseKeySpecValue(string(spec))
		if ks.User == "" {
			ks.User = sc.User
		}
		sc.SecretSpecs[i] = ks
	}
	return nil
}

func (sc SecretsConfig) TokensFromContext(ctx context.Context) ([]keys.Token, error) {
	toks := make([]keys.Token, len(sc.SecretSpecs))
	for i, spec := range sc.SecretSpecs {
		tok, ok := keys.TokenFromContext(ctx, spec.User, spec.ID)
		if !ok {
			return nil, fmt.Errorf("error retrieving key for spec %q", spec)
		}
		toks[i] = tok
	}
	return toks, nil
}

var (
	ErrWrongServiceSpecificConfig = fmt.Errorf("missing service specific config")
)

func ParseSpecific[T any](c Config) (T, error) {
	var cfg T
	if c.Specific == nil {
		return cfg, ErrWrongServiceSpecificConfig
	}
	cfg, err := cmdyaml.ParseDeferred[T](c.Specific)
	if err != nil {
		return cfg, fmt.Errorf("failed to parse github webhook config: %w", err)
	}
	return cfg, nil
}
