// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

// Package jwtutil provides support for creating and verifying JSON
// Web Tokens (JWTs) managed by the github.com/lestrrat-go/jwx/v3/jwk
// package. This package provides simplified wrappers around the
// JWT signing and verification process to allow for more convenient
// usage in web applications.
package jwtutil

import (
	"context"
	"crypto/ed25519"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Signer is an interface for signing and verifying JWTs.
type Signer interface {
	Sign(context.Context, jwt.Token) ([]byte, error)
	PublicKey() (jwk.Key, error)
	Validator
}

// ED25519Signer implements the Signer interface using an Ed25519 private key.
type ED25519Signer struct {
	priv jwk.Key
	set  jwk.Set
}

// NewED25519Signer creates a new ED25519Signer instance with the given private key and key ID.
func NewED25519Signer(priv ed25519.PrivateKey, id string) (ED25519Signer, error) {
	key, err := jwk.Import(priv)
	if err != nil {
		return ED25519Signer{}, err
	}
	for _, kv := range []struct {
		k string
		v any
	}{
		{jwk.AlgorithmKey, jwa.EdDSA()},
		{jwk.KeyUsageKey, "sig"},
		{jwk.KeyIDKey, id},
	} {
		if err := key.Set(kv.k, kv.v); err != nil {
			return ED25519Signer{}, err
		}
	}
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return ED25519Signer{}, err
	}

	return ED25519Signer{
		priv: key,
		set:  set,
	}, nil
}

func (s ED25519Signer) Sign(_ context.Context, token jwt.Token) ([]byte, error) {
	return jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), s.priv))
}

func (s ED25519Signer) PublicKey() (jwk.Key, error) {
	return s.priv.PublicKey()
}

// ParseAndValidate parses and validates a JWT using the signer's key set.
func (s ED25519Signer) ParseAndValidate(_ context.Context, tokenBytes []byte, validators ...jwt.ValidateOption) (jwt.Token, error) {
	token, err := jwt.Parse(tokenBytes, jwt.WithKeySet(s.set))
	if err != nil {
		return nil, err
	}
	if err := jwt.Validate(token, validators...); err != nil {
		return nil, err
	}
	return token, nil
}

// Valid
type Validator interface {
	ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error)
}

type validator struct {
	set jwk.Set
}

func NewValidator(set jwk.Set) Validator {
	return validator{
		set: set,
	}
}

func (v validator) ParseAndValidate(_ context.Context, tokenBytes []byte, validators ...jwt.ValidateOption) (jwt.Token, error) {
	token, err := jwt.Parse(tokenBytes, jwt.WithKeySet(v.set))
	if err != nil {
		return nil, err
	}
	if err := jwt.Validate(token, validators...); err != nil {
		return nil, err
	}
	return token, nil
}
