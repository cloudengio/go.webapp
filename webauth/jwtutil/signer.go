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

// NewED25519Signer creates a new ED25519Signer instance with the given private key and key ID.
func NewED25519Signer(priv ed25519.PrivateKey, id string) (Signer, error) {
	jwkKey, err := jwk.Import(priv)
	if err != nil {
		return nil, err
	}
	return NewSigner(jwkKey, id, jwa.EdDSA())
}

type signer struct {
	opt  jwt.SignOption
	pk   jwk.Key
	set  jwk.Set
	algo jwa.SignatureAlgorithm
}

// NewSigner creates a new Signer instance with the given private key and key ID.
func NewSigner(jwkKey jwk.Key, id string, algo jwa.SignatureAlgorithm) (Signer, error) {
	for _, kv := range []struct {
		k string
		v any
	}{
		{jwk.AlgorithmKey, algo},
		{jwk.KeyUsageKey, "sig"},
		{jwk.KeyIDKey, id},
	} {
		if err := jwkKey.Set(kv.k, kv.v); err != nil {
			return nil, err
		}
	}
	pk, err := jwkKey.PublicKey()
	if err != nil {
		return nil, err
	}

	set := jwk.NewSet()
	if err := set.AddKey(jwkKey); err != nil {
		return nil, err
	}
	return signer{
		pk:   pk,
		opt:  jwt.WithKey(algo, jwkKey),
		set:  set,
		algo: algo,
	}, nil

}

func (s signer) Sign(_ context.Context, token jwt.Token) ([]byte, error) {
	return jwt.Sign(token, s.opt)
}

func (s signer) PublicKey() (jwk.Key, error) {
	return s.pk, nil
}

// ParseAndValidate parses and validates a JWT using the signer's key set.
func (s signer) ParseAndValidate(_ context.Context, tokenBytes []byte, validators ...jwt.ValidateOption) (jwt.Token, error) {
	token, err := jwt.Parse(tokenBytes, jwt.WithKeySet(s.set))
	if err != nil {
		return nil, err
	}
	if err := jwt.Validate(token, validators...); err != nil {
		return nil, err
	}
	return token, nil
}

// Validator is an interface for validating JWTs.
type Validator interface {
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
