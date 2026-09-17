// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"context"
	"slices"
	"time"

	"cloudeng.io/cmdutil/keys"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// SignerForKey returns a Signer for the key identified by spec, which is read
// from the keys.InMemoryKeyStore stored in ctx (see keys.ContextWithKeyStore)
// and interpreted as described by KeyExtra. ErrNoKeyStore or ErrKeyNotFound are
// returned if the key is not available.
func SignerForKey(ctx context.Context, spec keys.KeySpec) (Signer, error) {
	return NewSignerFromContext(ctx, spec.User, spec.ID)
}

// Builder returns a jwt.Builder with the issued at, issuer, audience, subject
// and claims set from the configuration; subject and claims are only set if
// configured, and either can still be overridden by the caller before Build,
// since a later call to Subject or Claim on the same builder simply replaces
// the earlier one. The expiration claim is set to expiresIn from now if it is
// positive, or to c.Duration from now if expiresIn is not positive and
// c.Duration is.
func (c JWTSignerConfig) Builder(expiresIn time.Duration) *jwt.Builder {
	now := time.Now()
	builder := jwt.NewBuilder().IssuedAt(now).Issuer(c.Issuer).Audience(slices.Clone(c.Audience))
	if c.Subject != "" {
		builder.Subject(c.Subject)
	}
	for k, v := range c.Claims {
		builder.Claim(k, v)
	}
	if expiresIn <= 0 {
		expiresIn = c.Duration
	}
	if expiresIn > 0 {
		builder.Expiration(now.Add(expiresIn))
	}
	return builder
}
