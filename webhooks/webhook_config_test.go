// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks_test

import (
	"testing"

	"cloudeng.io/webapp/webhooks"
	"gopkg.in/yaml.v3"
)

const githubConfigYAML = `
path: "/webhook"
service: "github"
user: "myuser"
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
	if cfg.Path != "/webhook" {
		t.Errorf("Path: got %q, want %q", cfg.Path, "/webhook")
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
