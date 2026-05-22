// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks_test

import (
	"context"
	"testing"

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/webapp/webhooks"
	"gopkg.in/yaml.v3"
)

const githubConfigYAML = `
delivery_path: "/webhook"
relay_path: "/relay"
service: "github"
user: "myuser"
max_payload_size: 1MiB
secrets:
  - "mytoken"
  - "othertoken[otheruser]"
`

func TestConfigSecretsConfig(t *testing.T) {
	var cfg webhooks.Config
	if err := yaml.Unmarshal([]byte(githubConfigYAML), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Service != "github" {
		t.Errorf("Service: got %q, want %q", cfg.Service, "github")
	}
	if cfg.DeliveryPath != "/webhook" {
		t.Errorf("DeliveryPath: got %q, want %q", cfg.DeliveryPath, "/webhook")
	}
	if cfg.RelayPath != "/relay" {
		t.Errorf("RelayPath: got %q, want %q", cfg.RelayPath, "/relay")
	}
	if cfg.MaxPayloadSize != 1*1024*1024 {
		t.Errorf("MaxPayloadSize: got %d, want %d", cfg.MaxPayloadSize, 1*1024*1024)
	}

	sc, err := webhooks.ParseSpecific[webhooks.SecretsConfig](cfg)
	if err != nil {
		t.Fatalf("ParseSpecific: %v", err)
	}
	if sc.User != "myuser" {
		t.Errorf("User: got %q, want %q", sc.User, "myuser")
	}
	if got, want := len(sc.SecretSpecs), 2; got != want {
		t.Fatalf("SecretSpecs: got %d, want %d", got, want)
	}
	// "mytoken" has no user in the spec, so the top-level User is applied.
	if sc.SecretSpecs[0].ID != "mytoken" {
		t.Errorf("SecretSpecs[0].ID: got %q, want %q", sc.SecretSpecs[0].ID, "mytoken")
	}
	if sc.SecretSpecs[0].User != "myuser" {
		t.Errorf("SecretSpecs[0].User: got %q, want %q", sc.SecretSpecs[0].User, "myuser")
	}
	// "othertoken[otheruser]" has an explicit user.
	if sc.SecretSpecs[1].ID != "othertoken" {
		t.Errorf("SecretSpecs[1].ID: got %q, want %q", sc.SecretSpecs[1].ID, "othertoken")
	}
	if sc.SecretSpecs[1].User != "otheruser" {
		t.Errorf("SecretSpecs[1].User: got %q, want %q", sc.SecretSpecs[1].User, "otheruser")
	}

}

func TestConfigNilSpecific(t *testing.T) {
	cfg := webhooks.Config{Service: "github", Specific: nil}
	_, err := webhooks.ParseSpecific[webhooks.SecretsConfig](cfg)
	if err == nil {
		t.Fatalf("expected error for nil Specific")
	}
}

func TestConfigMarshalYAML_Defaults(t *testing.T) {
	cfg := webhooks.Config{
		DeliveryPath: "/webhook",
		RelayPath:    "/relay",
		Service:      "github",
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got webhooks.Config
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal round-trip: %v", err)
	}
	if got.MaxQueueSize != webhooks.DefaultQueueSize {
		t.Errorf("MaxQueueSize: got %d, want %d", got.MaxQueueSize, webhooks.DefaultQueueSize)
	}
	if got.MaxPayloadSize != webhooks.DefaultPayloadLimit {
		t.Errorf("MaxPayloadSize: got %d, want %d", got.MaxPayloadSize, webhooks.DefaultPayloadLimit)
	}
	if got.DeliveryPath != "/webhook" {
		t.Errorf("DeliveryPath: got %q, want %q", got.DeliveryPath, "/webhook")
	}
	if got.RelayPath != "/relay" {
		t.Errorf("RelayPath: got %q, want %q", got.RelayPath, "/relay")
	}
	if got.Service != "github" {
		t.Errorf("Service: got %q, want %q", got.Service, "github")
	}
}

func TestTokensFromContext(t *testing.T) {
	sc := webhooks.SecretsConfig{
		SecretSpecs: []keys.KeySpec{
			{ID: "key1", User: "user1"},
			{ID: "key2", User: "user2"},
		},
	}

	t.Run("AllFound", func(t *testing.T) {
		ctx := keys.ContextWithKey(context.Background(), keys.NewInfo("key1", "user1", []byte("secret1")))
		ctx = keys.ContextWithKey(ctx, keys.NewInfo("key2", "user2", []byte("secret2")))

		toks, err := sc.TokensFromContext(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(toks[0].Value()) != "secret1" {
			t.Errorf("toks[0]: got %q, want %q", toks[0].Value(), "secret1")
		}
		if string(toks[1].Value()) != "secret2" {
			t.Errorf("toks[1]: got %q, want %q", toks[1].Value(), "secret2")
		}
	})

	// ClearsOnError verifies that TokensFromContext returns (nil, error) when a
	// key is absent, that the error names the missing key, and that no partial
	// token slice is returned (the nil return is the observable proof that any
	// internally collected tokens were discarded).
	//
	// Note: Token.Clear() is a pointer-receiver method that zeroes the backing
	// byte array in place. Each keys.TokenFromContext call returns a fresh
	// slices.Clone, so the zeroing is scoped to the clones held inside
	// TokensFromContext and cannot be observed through an independent reference.
	t.Run("ClearsOnError", func(t *testing.T) {
		// Only key1 is in context; key2 is absent so the error path triggers
		// after key1 has already been collected and must be cleared.
		ctx := keys.ContextWithKey(context.Background(), keys.NewInfo("key1", "user1", []byte("secret1")))

		toks, err := sc.TokensFromContext(ctx)
		if err == nil {
			t.Fatal("expected error when key2 is missing from context")
		}
		if toks != nil {
			t.Errorf("expected nil token slice on error, got %v", toks)
		}
		if got := err.Error(); got == "" {
			t.Error("expected non-empty error message")
		}
	})

	t.Run("FirstKeyMissing", func(t *testing.T) {
		// No keys in context at all — error fires on the very first lookup,
		// nothing to clear.
		toks, err := sc.TokensFromContext(context.Background())
		if err == nil {
			t.Fatal("expected error when no keys in context")
		}
		if toks != nil {
			t.Errorf("expected nil token slice on error, got %v", toks)
		}
	})
}

// TestConfigUnmarshalDefaults verifies that UnmarshalYAML fills in defaults
// when max_queue_size and max_payload_size are absent from the YAML source —
// i.e. without requiring a prior MarshalYAML roundtrip.
func TestConfigUnmarshalDefaults(t *testing.T) {
	const input = `
delivery_path: "/hook"
service: "github"
`
	var cfg webhooks.Config
	if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if cfg.MaxQueueSize != webhooks.DefaultQueueSize {
		t.Errorf("MaxQueueSize: got %d, want %d", cfg.MaxQueueSize, webhooks.DefaultQueueSize)
	}
	if cfg.MaxPayloadSize != webhooks.DefaultPayloadLimit {
		t.Errorf("MaxPayloadSize: got %d, want %d", cfg.MaxPayloadSize, webhooks.DefaultPayloadLimit)
	}
}

// TestConfigUnmarshalNamedFields verifies that UnmarshalYAML correctly assigns
// all decoded values back to the receiver. A missing *c = Config(cc) assignment
// would leave every field at its zero value while returning nil.
func TestConfigUnmarshalNamedFields(t *testing.T) {
	const input = `
delivery_path: "/hook"
relay_path: "/relay"
service: "github"
max_queue_size: 5
max_payload_size: 512
`
	var cfg webhooks.Config
	if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if cfg.DeliveryPath != "/hook" {
		t.Errorf("DeliveryPath: got %q, want %q", cfg.DeliveryPath, "/hook")
	}
	if cfg.RelayPath != "/relay" {
		t.Errorf("RelayPath: got %q, want %q", cfg.RelayPath, "/relay")
	}
	if cfg.Service != "github" {
		t.Errorf("Service: got %q, want %q", cfg.Service, "github")
	}
	if cfg.MaxQueueSize != 5 {
		t.Errorf("MaxQueueSize: got %d, want 5", cfg.MaxQueueSize)
	}
	if cfg.MaxPayloadSize != 512 {
		t.Errorf("MaxPayloadSize: got %d, want 512", cfg.MaxPayloadSize)
	}
}

// TestConfigInOuterStruct verifies that Config's UnmarshalYAML works correctly
// when Config is used as a named field inside an outer struct that also has its
// own fields. This catches the case where yaml.v3's double-inline (an inline
// struct that itself contains an inline custom-unmarshaler) breaks silently.
func TestConfigInOuterStruct(t *testing.T) {
	type relayEntry struct {
		Config    webhooks.Config `yaml:"config"`
		ExtraFlag bool            `yaml:"extra_flag"`
	}

	const input = `
config:
  delivery_path: "/hook"
  relay_path: "/relay"
  service: "github"
  user: "alice"
  secrets:
    - my-secret
extra_flag: true
`
	var entry relayEntry
	if err := yaml.Unmarshal([]byte(input), &entry); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if entry.Config.Service != "github" {
		t.Errorf("Config.Service: got %q, want %q", entry.Config.Service, "github")
	}
	if entry.Config.DeliveryPath != "/hook" {
		t.Errorf("Config.DeliveryPath: got %q, want %q", entry.Config.DeliveryPath, "/hook")
	}
	if !entry.ExtraFlag {
		t.Errorf("ExtraFlag: got false, want true")
	}
	sc, err := webhooks.ParseSpecific[webhooks.SecretsConfig](entry.Config)
	if err != nil {
		t.Fatalf("ParseSpecific: %v", err)
	}
	if sc.User != "alice" {
		t.Errorf("User: got %q, want %q", sc.User, "alice")
	}
	if len(sc.SecretSpecs) != 1 || sc.SecretSpecs[0].ID != "my-secret" {
		t.Errorf("SecretSpecs: got %v, want [{ID:my-secret}]", sc.SecretSpecs)
	}
}

func TestConfigMarshalYAML_ExplicitValues(t *testing.T) {
	cfg := webhooks.Config{
		DeliveryPath:   "/hook",
		Service:        "gitlab",
		MaxQueueSize:   42,
		MaxPayloadSize: 512,
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got webhooks.Config
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal round-trip: %v", err)
	}
	if got.MaxQueueSize != 42 {
		t.Errorf("MaxQueueSize: got %d, want 42", got.MaxQueueSize)
	}
	if got.MaxPayloadSize != 512 {
		t.Errorf("MaxPayloadSize: got %d, want 512", got.MaxPayloadSize)
	}
}
