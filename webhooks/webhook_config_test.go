// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks_test

import (
	"errors"
	"testing"

	"cloudeng.io/webapp/webhooks"
	"gopkg.in/yaml.v3"
)

const githubConfigYAML = `
public_addr: "0.0.0.0:8080"
private_addr: "127.0.0.1:9090"
path: "/webhook"
service: "github"
secret_user: "myuser"
secret_id: "mytoken"
`

func TestConfigGithub(t *testing.T) {
	var cfg webhooks.Config
	if err := yaml.Unmarshal([]byte(githubConfigYAML), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.PublicAddr != "0.0.0.0:8080" {
		t.Errorf("PublicAddr: got %q, want %q", cfg.PublicAddr, "0.0.0.0:8080")
	}
	if cfg.Service != "github" {
		t.Errorf("Service: got %q, want %q", cfg.Service, "github")
	}

	ghc, err := cfg.Github()
	if err != nil {
		t.Fatalf("Github(): %v", err)
	}
	if ghc.KeychainItemUser != "myuser" {
		t.Errorf("KeychainItemUser: got %q, want %q", ghc.KeychainItemUser, "myuser")
	}
	if ghc.KeychainItemTokenID != "mytoken" {
		t.Errorf("KeychainItemTokenID: got %q, want %q", ghc.KeychainItemTokenID, "mytoken")
	}
}

func TestConfigGithubWrongService(t *testing.T) {
	cfg := webhooks.Config{Service: "gitlab"}
	_, err := cfg.Github()
	if err == nil {
		t.Fatal("expected error for wrong service")
	}
	if !errors.Is(err, webhooks.ErrWrongServiceSpecificConfig) {
		t.Errorf("error %v does not wrap ErrWrongServiceSpecificConfig", err)
	}
}

func TestConfigGithubNilSpecific(t *testing.T) {
	cfg := webhooks.Config{Service: "github", Specific: nil}
	_, err := cfg.Github()
	if err == nil {
		t.Fatal("expected error for nil Specific")
	}
}
