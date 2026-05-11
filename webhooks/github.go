// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"cloudeng.io/file"
	"gopkg.in/yaml.v3"
)

// GitHubSecrets represents the structure of the YAML file that contains the
// GitHub webhook secrets. It supports multiple secrets to allow for rotation.
type GitHubSecrets struct {
	Secrets []string `yaml:"secrets"`
}

// UnmarshalYAML unmarshals the YAML data into the GitHubSecrets struct
// by appending the secrets to the Secrets slice. This allows for multiple secrets
// to be specified in a single yaml.Node and across multiple yaml.Node instances
// (e.g. from multiple files).
func (s *GitHubSecrets) UnmarshalYAML(value *yaml.Node) error {
	type tmp GitHubSecrets
	var secrets tmp
	if err := value.Decode(&secrets); err != nil {
		return err
	}
	s.Secrets = append(s.Secrets, secrets.Secrets...)
	return nil
}

func readSecrets(ctx context.Context, fs file.ReadFileFS, secretPaths ...string) (GitHubSecrets, error) {
	if len(secretPaths) == 0 {
		return GitHubSecrets{}, errors.New("no secrets file specified")
	}
	for i, secretPath := range secretPaths {
		if secretPath == "" {
			return GitHubSecrets{}, fmt.Errorf("secret path at index %d is empty", i)
		}
	}
	var ghs GitHubSecrets
	for _, secretPath := range secretPaths {
		data, err := fs.ReadFileCtx(ctx, secretPath)
		if err != nil {
			return GitHubSecrets{}, err
		}
		if err := yaml.Unmarshal(data, &ghs); err != nil {
			return GitHubSecrets{}, err
		}
	}
	return ghs, nil
}

// GitHubValidator returns a Validator that verifies GitHub webhook payloads
// using one of possibly multiple secrets stored in the provided file.ReadFileFS
// instance at the provided path(s). Multiple secrets files and multiple secrets
// per file allow for rotation. GitHub does not currently directly support rotation,
// hence the only way to change the secret used by GitHub is to create a new one,
// wait for it be picked up by the validator then change the secret used by
// GitHub to the new one and remove the old secret from the file.ReadFileFS.
// Ideally, the file.ReadFileFS instance should be an in-memory or
// caching implementation to avoid the overhead of reading the secret from disk on
// every request but that also allows for the secret to be refreshed.
// GitHubValidator returns an error if no secret paths are provided, if any of
// the provided paths are empty or can't be successfully read and parsed.
// Note that this initial validation uses the context passed to GitHubValidator,
// whereas the returned Validator uses the context from the incoming request to
// read the secrets on each request.
func GitHubValidator(ctx context.Context, fs file.ReadFileFS, secretPaths ...string) (Validator, error) {
	_, err := readSecrets(ctx, fs, secretPaths...)
	if err != nil {
		return nil, fmt.Errorf("failed to find/read secrets: %w", err)
	}
	return func(req *http.Request) ([]byte, int) {
		payload, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, http.StatusBadRequest
		}
		defer req.Body.Close()

		signatureHeader := req.Header.Get("X-Hub-Signature-256")
		if signatureHeader == "" {
			return nil, http.StatusUnauthorized
		}

		parts := strings.SplitN(signatureHeader, "=", 2)
		if len(parts) != 2 || parts[0] != "sha256" {
			return nil, http.StatusUnauthorized
		}

		sig, err := hex.DecodeString(parts[1])
		if err != nil {
			return nil, http.StatusUnauthorized
		}

		ghs, err := readSecrets(req.Context(), fs, secretPaths...)
		if err != nil {
			return nil, http.StatusInternalServerError
		}
		for _, secret := range ghs.Secrets {
			mac := hmac.New(sha256.New, []byte(secret))
			_, _ = mac.Write(payload)
			if hmac.Equal(sig, mac.Sum(nil)) {
				return payload, http.StatusOK
			}
		}
		return nil, http.StatusUnauthorized
	}, nil
}
