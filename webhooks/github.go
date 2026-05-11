// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"

	"cloudeng.io/file"
	"gopkg.in/yaml.v3"
)

// GitHubSecrets represents the structure of the YAML file that contains the
// GitHub webhook secrets. `It supports multiple secrets to allow for rotation.
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
func GitHubValidator(fs file.ReadFileFS, secretPaths ...string) Validator {
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

		var ghs GitHubSecrets
		for _, secretPath := range secretPaths {
			data, err := fs.ReadFileCtx(req.Context(), secretPath)
			if err != nil {
				return nil, http.StatusInternalServerError
			}
			if err := yaml.Unmarshal(data, &ghs); err != nil {
				return nil, http.StatusInternalServerError
			}
		}
		for _, secret := range ghs.Secrets {
			mac := hmac.New(sha256.New, []byte(secret))
			_, _ = mac.Write(payload)
			if hmac.Equal(sig, mac.Sum(nil)) {
				return payload, http.StatusOK
			}
		}
		return nil, http.StatusUnauthorized
	}
}
