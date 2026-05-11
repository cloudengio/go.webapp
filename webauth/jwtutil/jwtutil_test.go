// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"cloudeng.io/webapp/webauth/jwtutil"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func newToken(t *testing.T) jwt.Token {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer("test-user").
		Audience([]string{"test"}).
		Subject("test").
		Expiration(time.Now().Add(time.Hour)).
		NotBefore(time.Now()).
		Claim("scope", "a,b").
		Build()
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	return tok
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key pair: %v", err)
	}
	return priv
}

func TestSignAndVerifyED25519(t *testing.T) {
	ctx := t.Context()
	signer, err := jwtutil.NewED25519Signer(newKey(t), "test-key-001")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	tokenBytes, err := signer.Sign(ctx, newToken(t))
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(tokenBytes) == 0 {
		t.Fatal("Sign() returned an empty token string")
	}
	validationOptions := []jwt.ValidateOption{
		jwt.WithIssuer("test-user"),
		jwt.WithAudience("test"),
		jwt.WithAcceptableSkew(1 * time.Second),
		jwt.WithClaimValue("scope", "a,b"),
	}

	t.Run("ValidToken", func(t *testing.T) {
		parsed, err := signer.ParseAndValidate(ctx, tokenBytes, validationOptions...)
		if err != nil {
			t.Fatalf("ParseAndValidate() failed: %v", err)
		}
		subject, _ := parsed.Subject()
		if got, want := subject, "test"; got != want {
			t.Errorf("got subject %q, want %q", got, want)
		}
	})

	t.Run("CorruptedToken", func(t *testing.T) {
		corrupted := slices.Clone(tokenBytes)
		corrupted[4] = 0xff
		_, err := signer.ParseAndValidate(ctx, corrupted, validationOptions...)
		if err == nil {
			t.Fatal("ParseAndValidate() should have failed for corrupted token")
		}
	})

	t.Run("SeparateValidator", func(t *testing.T) {
		publicKey, err := signer.PublicKey()
		if err != nil {
			t.Fatalf("failed to get public key: %v", err)
		}
		jwks, err := marshalKeySet(publicKey)
		if err != nil {
			t.Fatalf("failed to marshal/unmarshal key set: %v", err)
		}
		_, err = jwtutil.NewValidator(jwks).ParseAndValidate(ctx, tokenBytes, validationOptions...)
		if err != nil {
			t.Fatalf("ParseAndValidate() failed: %v", err)
		}
	})

	t.Run("WrongKeyID", func(t *testing.T) {
		publicKey, err := signer.PublicKey()
		if err != nil {
			t.Fatalf("failed to get public key: %v", err)
		}
		diffKey, err := publicKey.Clone()
		if err != nil {
			t.Fatalf("failed to clone public key: %v", err)
		}
		if err := diffKey.Set(jwk.KeyIDKey, "diff-key"); err != nil {
			t.Fatalf("failed to set key ID: %v", err)
		}
		set := jwk.NewSet()
		if err := set.AddKey(diffKey); err != nil {
			t.Fatalf("failed to add key to set: %v", err)
		}
		_, err = jwtutil.NewValidator(set).ParseAndValidate(ctx, tokenBytes, validationOptions...)
		if err == nil {
			t.Fatal("ParseAndValidate() should have failed for wrong key ID")
		}
	})
}

func marshalKeySet(key jwk.Key) (jwk.Set, error) {
	ks := jwk.NewSet()
	if err := ks.AddKey(key); err != nil {
		return nil, err
	}
	buf, err := json.Marshal(ks)
	if err != nil {
		return nil, err
	}
	out := jwk.NewSet()
	if err := json.Unmarshal(buf, &out); err != nil {
		return nil, err
	}
	return out, nil
}
