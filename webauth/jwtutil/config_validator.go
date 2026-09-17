// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"cloudeng.io/cmdutil/keys"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// KeySetForKeys returns a jwk.KeySet containing the public halves of the keys
// provided.
func KeySetForKeys(ctx context.Context, keys ...keys.Info) (jwk.Set, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one verification key is required")
	}
	set := jwk.NewSet()
	seen := make(map[string]bool, len(keys))
	for _, info := range keys {
		if info.ID == "" {
			return nil, fmt.Errorf("verification key ID is required")
		}
		if seen[info.ID] {
			return nil, fmt.Errorf("duplicate verification key ID: %q", info.ID)
		}
		seen[info.ID] = true
		key, err := PublicKeyFromKeyInfo(ctx, info)
		if err != nil {
			return nil, fmt.Errorf("key %v: %w", info, err)
		}
		// The key id must match the one set by the Signer for the key to be
		// selected by jwt.WithKeySet when verifying a token.
		if err := key.Set(jwk.KeyIDKey, info.ID); err != nil {
			return nil, fmt.Errorf("key %v: %w", info, err)
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("key %v: %w", info, err)
		}
	}
	return set, nil
}

// ValidatorForKeys returns a Validator that verifies the signature of any token
// signed by one of the provided keys.
func ValidatorForKeys(ctx context.Context, keys ...keys.Info) (Validator, error) {
	set, err := KeySetForKeys(ctx, keys...)
	if err != nil {
		return nil, err
	}
	return NewValidator(set), nil
}

// ValidateOptions returns the validation options implied by the configuration,
// namely that a token must have been issued by the configured issuer and must
// be intended for at least one of the configured audiences. Claims entries
// that shadow a reserved claim (see ErrReservedClaim) are skipped: Validate
// already rejects a configuration containing one, but ValidateOptions may be
// called independently of Validate, and standard claims like exp/nbf/iat are
// not strings, so a jwt.WithClaimValue for one would never match and would
// silently reject every otherwise-valid token.
func (c JWTValidatorConfig) ValidateOptions() []jwt.ValidateOption {
	var opts []jwt.ValidateOption
	if c.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(c.Issuer))
	}
	if len(c.Audience) > 0 {
		opts = append(opts, jwt.WithValidator(audienceValidator(c.Audience)))
	}
	if c.Subject != "" {
		opts = append(opts, jwt.WithSubject(c.Subject))
	}
	claimKeys := make([]string, 0, len(c.Claims))
	for k := range c.Claims {
		if isReservedClaim(k) {
			continue
		}
		claimKeys = append(claimKeys, k)
	}
	sort.Strings(claimKeys)
	for _, k := range claimKeys {
		opts = append(opts, jwt.WithClaimValue(k, c.Claims[k]))
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
