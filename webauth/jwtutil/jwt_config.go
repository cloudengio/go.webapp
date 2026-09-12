// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"fmt"
	"time"

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/webapp/cookies"
)

// JWTSignerConfig provides configuration for signing JSON Web Tokens (JWTs).
type JWTSignerConfig struct {
	Issuer     string       `yaml:"jwt_issuer" doc:"jwt issuer"`
	Audience   []string     `yaml:"jwt_audience" doc:"jwt audience"`
	SigningKey keys.KeySpec `yaml:"jwt_signing_key" doc:"jwt signing key spec"`
}

func (c JWTSignerConfig) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if len(c.Audience) == 0 {
		return fmt.Errorf("audience is required")
	}
	if c.SigningKey.ID == "" {
		return fmt.Errorf("signing key is required")
	}
	return nil
}

// JWTVerifierConfig provides configuration for verifying JSON Web Tokens (JWTs)
// for a given issuer and audience. Multiple verification keys can be specified
// to allow for key rotation.
type JWTVerifierConfig struct {
	Issuer           string         `yaml:"jwt_issuer" doc:"jwt issuer"`
	Audience         []string       `yaml:"jwt_audience" doc:"jwt audience"`
	VerificationKeys []keys.KeySpec `yaml:"jwt_verification_keys" doc:"jwt verification key specs"`
}

func (c JWTVerifierConfig) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if len(c.Audience) == 0 {
		return fmt.Errorf("audience is required")
	}
	if len(c.VerificationKeys) == 0 {
		return fmt.Errorf("at least one verification key is required")
	}
	return nil
}

// JWTCookieSignerConfig provides configuration for a cookie storing a JWT.
type JWTCookieSignerConfig struct {
	Name                     string        `yaml:"name" doc:"cookie name"`
	ValidationTimeSkew       time.Duration `yaml:"validation_time_skew" doc:"allowed time skew for cookie and token validation"`
	cookies.ScopeAndDuration `yaml:",inline" doc:"cookie and token scope and duration"`
	JWTSignerConfig          `yaml:",inline" doc:"jwt info"`
}

func (c JWTCookieSignerConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("cookie name is required")
	}
	if c.ValidationTimeSkew < 0 {
		return fmt.Errorf("validation time skew cannot be negative")
	}
	return c.JWTSignerConfig.Validate()
}

// JWTCookieVerifierConfig provides configuration for verifying a JWT stored in a
// cookie.
type JWTCookieVerifierConfig struct {
	Name                     string        `yaml:"name" doc:"cookie name"`
	ValidationTimeSkew       time.Duration `yaml:"validation_time_skew" doc:"allowed time skew for cookie and token validation"`
	cookies.ScopeAndDuration `yaml:",inline" doc:"cookie and token scope and duration"`
	JWTVerifierConfig        `yaml:",inline" doc:"jwt info"`
}

func (c JWTCookieVerifierConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("cookie name is required")
	}
	if c.ValidationTimeSkew < 0 {
		return fmt.Errorf("validation time skew cannot be negative")
	}
	return c.JWTVerifierConfig.Validate()
}
