// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"context"
	"fmt"
	"slices"
	"time"

	"cloudeng.io/cmdutil/keys"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// NewSigner returns a Signer for the signing key named by the configuration.
// The key is read from the keys.InMemoryKeyStore stored in ctx (see
// keys.ContextWithKeyStore) and is interpreted as described by KeyExtra.
// ErrNoKeyStore or ErrKeyNotFound are returned if the key is not available.
func (c JWTSignerConfig) NewSigner(ctx context.Context) (Signer, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return SignerForKey(ctx, c.SigningKey)
}

// SignerForKey returns a Signer for the key identified by spec, which is read
// from the keys.InMemoryKeyStore stored in ctx (see keys.ContextWithKeyStore)
// and interpreted as described by KeyExtra. ErrNoKeyStore or ErrKeyNotFound are
// returned if the key is not available.
func SignerForKey(ctx context.Context, spec keys.KeySpec) (Signer, error) {
	info, err := keyInfoFromContext(ctx, spec)
	if err != nil {
		return nil, err
	}
	key, algo, err := signingKey(info)
	if err != nil {
		return nil, err
	}
	return NewSigner(key, spec.ID, algo)
}

// Builder returns a jwt.Builder with the issued at, issuer and audience claims
// set from the configuration. The expiration claim is set to expiresIn from now
// if it is positive.
func (c JWTSignerConfig) Builder(expiresIn time.Duration) *jwt.Builder {
	now := time.Now()
	builder := jwt.NewBuilder().IssuedAt(now).Issuer(c.Issuer).Audience(c.Audience)
	if expiresIn > 0 {
		builder.Expiration(now.Add(expiresIn))
	}
	return builder
}

// VerifierConfig returns the verifier configuration implied by the signer
// configuration, namely the same issuer and audience with the signing key as
// the sole verification key. It is intended for use by a service that both
// issues and verifies its own tokens.
func (c JWTSignerConfig) VerifierConfig() JWTVerifierConfig {
	return JWTVerifierConfig{
		Issuer:           c.Issuer,
		Audience:         slices.Clone(c.Audience),
		VerificationKeys: []keys.KeySpec{c.SigningKey},
	}
}

// NewValidator returns a Validator for the verification keys named by the
// configuration, as per ValidatorForKeys. Unlike the Verifier returned by
// NewVerifier it does not check the issuer or audience claims.
func (c JWTVerifierConfig) NewValidator(ctx context.Context) (Validator, error) {
	set, err := c.keySet(ctx)
	if err != nil {
		return nil, err
	}
	return NewValidator(set), nil
}

// ValidatorForKeys returns a Validator that verifies the signature of any token
// signed by one of the keys identified by specs, which are read from the
// keys.InMemoryKeyStore stored in ctx (see keys.ContextWithKeyStore) and
// interpreted as described by KeyExtra. Unlike the Verifier returned by
// JWTVerifierConfig.NewVerifier it does not check the issuer or audience claims.
func ValidatorForKeys(ctx context.Context, specs ...keys.KeySpec) (Validator, error) {
	set, err := keySetForKeys(ctx, specs)
	if err != nil {
		return nil, err
	}
	return NewValidator(set), nil
}

// keySet returns the jwk.Set containing the verification keys named by the
// configuration.
func (c JWTVerifierConfig) keySet(ctx context.Context) (jwk.Set, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return keySetForKeys(ctx, c.VerificationKeys)
}

// keySetForKeys returns the jwk.Set containing the public halves of the keys
// identified by specs, each with the key id, algorithm and usage required to
// verify a token signed by the corresponding Signer.
func keySetForKeys(ctx context.Context, specs []keys.KeySpec) (jwk.Set, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("at least one verification key is required")
	}
	set := jwk.NewSet()
	for _, spec := range specs {
		info, err := keyInfoFromContext(ctx, spec)
		if err != nil {
			return nil, err
		}
		key, algo, err := verificationKey(info)
		if err != nil {
			return nil, err
		}
		// The key id must match the one set by NewSigner for the key to be
		// selected by jwt.WithKeySet when verifying a token.
		for _, kv := range []struct {
			k string
			v any
		}{
			{jwk.AlgorithmKey, algo},
			{jwk.KeyUsageKey, "sig"},
			{jwk.KeyIDKey, spec.ID},
		} {
			if err := key.Set(kv.k, kv.v); err != nil {
				return nil, fmt.Errorf("key %v: %w", spec, err)
			}
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("key %v: %w", spec, err)
		}
	}
	return set, nil
}

// ValidateOptions returns the validation options implied by the configuration,
// namely that a token must have been issued by the configured issuer and must
// be intended for at least one of the configured audiences.
func (c JWTVerifierConfig) ValidateOptions() []jwt.ValidateOption {
	var opts []jwt.ValidateOption
	if c.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(c.Issuer))
	}
	if len(c.Audience) > 0 {
		opts = append(opts, jwt.WithValidator(audienceValidator(c.Audience)))
	}
	return opts
}

// audienceValidator returns a jwt.Validator that requires the audience claim of
// a token to include at least one of the supplied audiences. jwt.WithAudience
// requires every audience it is given to be present and hence cannot express a
// set of acceptable audiences.
func audienceValidator(audience []string) jwt.Validator {
	acceptable := slices.Clone(audience)
	return jwt.ValidatorFunc(func(_ context.Context, tok jwt.Token) error {
		aud, ok := tok.Audience()
		if !ok {
			return fmt.Errorf("token has no audience claim, expected one of %v", acceptable)
		}
		for _, a := range aud {
			if slices.Contains(acceptable, a) {
				return nil
			}
		}
		return fmt.Errorf("token audience %v does not include any of %v", aud, acceptable)
	})
}

// Verifier is a Validator that applies the issuer and audience checks implied
// by the configuration it was created from, as well as any allowance for clock
// skew, in addition to verifying the signature of a token.
type Verifier struct {
	Validator
	set  jwk.Set
	opts []jwt.ValidateOption
}

// NewVerifier returns a Verifier for the keys, issuer and audience named by the
// configuration. The keys are obtained as per NewValidator.
func (c JWTVerifierConfig) NewVerifier(ctx context.Context) (*Verifier, error) {
	return c.newVerifier(ctx, 0)
}

// newVerifier returns a Verifier that allows for the supplied clock skew when
// validating time based claims.
func (c JWTVerifierConfig) newVerifier(ctx context.Context, skew time.Duration) (*Verifier, error) {
	set, err := c.keySet(ctx)
	if err != nil {
		return nil, err
	}
	opts := c.ValidateOptions()
	if skew > 0 {
		opts = append(opts, jwt.WithAcceptableSkew(skew))
	}
	return &Verifier{Validator: NewValidator(set), set: set, opts: opts}, nil
}

// Parse verifies the signature of token and returns it without validating any
// of its claims, which is left to Validate so that the options implied by the
// configuration are applied.
func (v *Verifier) Parse(_ context.Context, token []byte) (jwt.Token, error) {
	return jwt.Parse(token, jwt.WithKeySet(v.set), jwt.WithValidate(false))
}

// Validate validates token using the configured issuer, audience and clock skew
// followed by any additional validators supplied.
func (v *Verifier) Validate(ctx context.Context, token jwt.Token, validators ...jwt.ValidateOption) error {
	return v.Validator.Validate(ctx, token, v.validateOptions(validators)...)
}

// ParseAndValidate parses and validates token as per Parse and Validate.
func (v *Verifier) ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error) {
	parsed, err := v.Parse(ctx, token)
	if err != nil {
		return nil, err
	}
	if err := v.Validate(ctx, parsed, validators...); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (v *Verifier) validateOptions(validators []jwt.ValidateOption) []jwt.ValidateOption {
	return append(slices.Clone(v.opts), validators...)
}
