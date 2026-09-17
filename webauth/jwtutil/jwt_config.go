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

type JWTCookieConfig struct {
	Name                     string `yaml:"name" doc:"cookie-name,jwt,name of the authentication cookie to set"`
	cookies.ScopeAndDuration `yaml:",inline" doc:"cookie and token scope and duration"`
	Insecure                 bool `yaml:"insecure" doc:"insecure,false,whether to allow insecure (non-HTTPS) connections"`
}

func (c JWTCookieConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("cookie name is required")
	}
	if c.Domain == "" {
		return fmt.Errorf("cookie domain is required")
	}
	if c.Path == "" {
		return fmt.Errorf("cookie path is required")
	}
	if c.Duration <= 0 {
		return fmt.Errorf("cookie duration must be greater than 0")
	}
	return nil
}

// JWTSignerConfig provides configuration for signing JSON Web Tokens (JWTs).
type JWTSignerConfig struct {
	Issuer     string            `yaml:"jwt_issuer" doc:"jwt issuer"`
	Audience   []string          `yaml:"jwt_audience" doc:"jwt audience"`
	Duration   time.Duration     `yaml:"jwt_duration" doc:"duration,24h,validity duration of the issued JWT"`
	Subject    string            `yaml:"jwt_subject" doc:"jwt subject, always included as 'sub' claim if provided"`
	Claims     map[string]string `yaml:"jwt_claims" doc:"additional claims to include in issued JWTs"`
	SigningKey keys.KeySpec      `yaml:"jwt_signing_key" doc:"jwt signing key spec"`
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
	for k := range c.Claims {
		if isReservedClaim(k) {
			return fmt.Errorf("%w: %q cannot be set via Claims", ErrReservedClaim, k)
		}
	}
	return nil
}

// JWTVerifierConfig provides configuration for verifying JSON Web Tokens (JWTs)
// for a given issuer and audience. Multiple verification keys can be specified
// to allow for key rotation.
type JWTVerifierConfig struct {
	Issuer           string            `yaml:"jwt_issuer" doc:"jwt issuer"`
	Audience         []string          `yaml:"jwt_audience" doc:"jwt audience"`
	Subject          string            `yaml:"jwt_subject" doc:"jwt subject, always expected as 'sub' claim if provided"`
	Claims           map[string]string `yaml:"jwt_claims" doc:"additional claims to expect in the JWT"`
	VerificationKeys []keys.KeySpec    `yaml:"jwt_verification_keys" doc:"jwt verification key specs"`
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
	seen := make(map[string]bool, len(c.VerificationKeys))
	for _, k := range c.VerificationKeys {
		if k.ID == "" {
			return fmt.Errorf("verification key ID is required")
		}
		if seen[k.ID] {
			return fmt.Errorf("duplicate verification key ID: %q", k.ID)
		}
		seen[k.ID] = true
	}
	for k := range c.Claims {
		if isReservedClaim(k) {
			return fmt.Errorf("%w: %q cannot be set via Claims", ErrReservedClaim, k)
		}
	}
	return nil
}

// JWTCookieSignerConfig provides configuration for a cookie storing a JWT.
type JWTCookieSignerConfig struct {
	JWTCookieConfig `yaml:"cookie" doc:"jwt cookie config"`
	JWTSignerConfig `yaml:",inline" doc:"jwt info"`
}

func (c JWTCookieSignerConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("cookie name is required")
	}
	// JWTCookieConfig.Duration (the cookie's own lifetime) must be named
	// explicitly: JWTSignerConfig now has its own Duration (the JWT's
	// validity), and being shallower it would otherwise shadow this one.
	if c.JWTCookieConfig.Duration <= 0 {
		return fmt.Errorf("cookie duration must be greater than 0")
	}
	return c.JWTSignerConfig.Validate()
}

// JWTCookieVerifierConfig provides configuration for verifying a JWT stored in a
// cookie.
type JWTCookieVerifierConfig struct {
	JWTCookieConfig    `yaml:"cookie" doc:"jwt cookie config"`
	ValidationTimeSkew time.Duration `yaml:"validation_time_skew" doc:"allowed time skew for cookie and token validation"`
	JWTVerifierConfig  `yaml:",inline" doc:"jwt info"`
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
