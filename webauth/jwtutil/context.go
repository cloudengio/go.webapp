// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"context"
	"maps"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

type tokenContextKey struct{}

// ContextWithToken returns a new context derived from ctx that carries the
// provided jwt.Token keyed by key. If ctx already contains tokens, the
// existing tokens are preserved and the token for key is added or updated.
func ContextWithToken(ctx context.Context, key string, tok jwt.Token) context.Context {
	m, _ := ctx.Value(tokenContextKey{}).(map[string]jwt.Token)
	if m == nil {
		m = make(map[string]jwt.Token, 1)
	} else {
		m = maps.Clone(m)
	}
	m[key] = tok
	return context.WithValue(ctx, tokenContextKey{}, m)
}

// TokenFromContext retrieves the jwt.Token keyed by key from ctx, if present.
func TokenFromContext(ctx context.Context, key string) (jwt.Token, bool) {
	m, ok := ctx.Value(tokenContextKey{}).(map[string]jwt.Token)
	if !ok {
		return nil, false
	}
	tok, ok := m[key]
	return tok, ok
}

// TokensFromContext returns a copy of all jwt.Token instances stored in ctx,
// keyed by their string identifiers.
func TokensFromContext(ctx context.Context) map[string]jwt.Token {
	m, ok := ctx.Value(tokenContextKey{}).(map[string]jwt.Token)
	if !ok {
		return nil
	}
	return maps.Clone(m)
}
