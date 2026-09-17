// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"context"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Validator is an interface for validating JWTs.
type Validator interface {
	Parse(ctx context.Context, token []byte) (jwt.Token, error)
	Validate(ctx context.Context, token jwt.Token, validators ...jwt.ValidateOption) error
	ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error)
}

type validator struct {
	set jwk.Set
}

// NewValidator creates a new Validator instance with the given key set.
func NewValidator(set jwk.Set) Validator {
	return validator{
		set: set,
	}
}

// ParseAndValidate parses and validates a JWT using the signer's key set.
func (v validator) ParseAndValidate(ctx context.Context, tokenBytes []byte, validators ...jwt.ValidateOption) (jwt.Token, error) {
	token, err := v.Parse(ctx, tokenBytes)
	if err != nil {
		return nil, err
	}
	if err := v.Validate(ctx, token, validators...); err != nil {
		return nil, err
	}
	return token, nil
}

func (v validator) Parse(_ context.Context, tokenBytes []byte) (jwt.Token, error) {
	return jwt.Parse(tokenBytes, jwt.WithKeySet(v.set))
}

func (v validator) Validate(_ context.Context, token jwt.Token, validators ...jwt.ValidateOption) error {
	return jwt.Validate(token, validators...)
}
