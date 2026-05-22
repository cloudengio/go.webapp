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
	DeliveryPath   string            `yaml:"delivery_path" doc:"path to receive webhooks on"`
	RelayPath      string            `yaml:"relay_path" doc:"path to read relay payloads from"`
	MaxPayloadSize cmdyaml.ByteSize  `yaml:"max_payload_size" doc:"maximum allowed payload size for incoming webhook requests in bytes, e.g. 1048576 for 1MB"`
	MaxQueueSize   int               `yaml:"max_queue_size" doc:"maximum number of payloads to hold in the queue for processing, leave empty for default"`
	Service        string            `yaml:"service" doc:"type of webhook to serve, e.g. github, etc."`
	Specific       *cmdyaml.Deferred `yaml:",inline" doc:"additional details about the webhook specific to the type of webhook being served, leave empty for default"`
}

func (c *Config) UnmarshalYAML(node *yaml.Node) error {
	type config Config
	var cc config
	if err := node.Decode(&cc); err != nil {
		return err
	}
	if cc.MaxQueueSize == 0 {
		cc.MaxQueueSize = DefaultQueueSize
	}
	if cc.MaxPayloadSize == 0 {
		cc.MaxPayloadSize = cmdyaml.ByteSize(DefaultPayloadLimit)
	}
	*c = Config(cc)
	return nil
}

func (c Config) MarshalYAML() (any, error) {
	type config Config
	cc := config(c)
	if cc.MaxQueueSize == 0 {
		cc.MaxQueueSize = DefaultQueueSize
	}
	if cc.MaxPayloadSize == 0 {
		cc.MaxPayloadSize = cmdyaml.ByteSize(DefaultPayloadLimit)
	}
	return cc, nil
}

func (c Config) Options() []Option {
	opts := []Option{
		WithQueueSize(int64(c.MaxQueueSize)),
		WithMaxPayloadSize(int64(c.MaxPayloadSize)),
	}
	return opts
}

// SecretsConfig represents a common configuration that uses
// cloudeng.io/cmdutil/keys.KeySpec to specify the secrets to be used for
// validating webhooks. User and Secrets fields can be unmarshaled from YAML,
// but the SecretSpecs field is populated based on those fields by the
// UnmarshalYAML.
type SecretsConfig struct {
	User        string         `yaml:"user" doc:"user to associate with a key id if the KeySpec does not specify a user"`
	Secrets     []string       `yaml:"secrets" doc:"list of KeySpecs specifying the secrets to use for validating webhooks in cloudeng.io.cmdutil/keys.KeySpec format, i.e. id[user] or id. If no user is specified, the to-level User field is used. If the User field is not set then the value is used as the id with no user value."`
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
		ks := keys.ParseKeySpecValue(spec)
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
			for j := range i {
				tok := toks[j]
				tok.Clear()
				toks[j] = keys.Token{}
			}
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
