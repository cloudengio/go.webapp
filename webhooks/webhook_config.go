// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"bytes"
	"context"
	"fmt"

	"cloudeng.io/cmdutil/cmdyaml"
	"cloudeng.io/cmdutil/keys"
	"gopkg.in/yaml.v3"
)

// Config represents the configuration for a webhook server.
type Config struct {
	DeliveryPath    string            `yaml:"delivery_path" doc:"path to receive webhooks on"`
	RelayPath       string            `yaml:"relay_path" doc:"path to read relay payloads from"`
	MaxPayloadSize  cmdyaml.ByteSize  `yaml:"max_payload_size" doc:"maximum allowed payload size for incoming webhook requests in bytes, e.g. 1048576 for 1MB"`
	MaxQueueSize    int               `yaml:"max_queue_size" doc:"maximum number of payloads to hold in the queue for processing, leave empty for default"`
	Service         string            `yaml:"service" doc:"type of webhook to serve, e.g. github, etc."`
	ServiceSpecific *cmdyaml.Deferred `yaml:"service_specific" doc:"additional details specific to the type of webhook being served, leave empty for default"`
}

func (c *Config) UnmarshalYAML(node *yaml.Node) error {
	type config Config
	var cc config
	// Re-encode the node so we can run a strict decoder over it, catching
	// unknown field names (e.g. "relay" instead of "relay_path").
	data, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cc); err != nil {
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

// SecretsConfig represents the secrets used to validate incoming webhooks.
// Keys are users (e.g. a GitHub username or email address) and values are
// lists of secret IDs that identify entries in the key store. SecretSpecs is
// populated automatically during unmarshal and must not be set directly.
//
// YAML format (the node itself is the map — no wrapper key):
//
//	alice@example.com:
//	  - secret-id-1
//	  - secret-id-2
//	bob@example.com:
//	  - other-secret
type SecretsConfig struct {
	Secrets     map[string][]string `yaml:"-"`
	SecretSpecs []keys.KeySpec      `yaml:"-"`
}

func (sc *SecretsConfig) UnmarshalYAML(node *yaml.Node) error {
	var secrets map[string][]string
	if err := node.Decode(&secrets); err != nil {
		return fmt.Errorf("unmarshal SecretsConfig: %v", err)
	}
	sc.Secrets = secrets
	for user, ids := range secrets {
		for _, id := range ids {
			sc.SecretSpecs = append(sc.SecretSpecs, keys.KeySpec{User: user, ID: id})
		}
	}
	return nil
}

func (sc SecretsConfig) MarshalYAML() (any, error) {
	if sc.Secrets == nil {
		return map[string][]string{}, nil
	}
	return sc.Secrets, nil
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
	if c.ServiceSpecific == nil {
		return cfg, ErrWrongServiceSpecificConfig
	}
	cfg, err := cmdyaml.ParseDeferred[T](c.ServiceSpecific)
	if err != nil {
		return cfg, fmt.Errorf("failed to parse %v webhook config: %w", c.Service, err)
	}
	return cfg, nil
}
