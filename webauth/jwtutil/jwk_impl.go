// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"

	"cloudeng.io/cmdutil/keys"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// NewED25519KeyInfo generates an ed25519 key pair and returns it as a keys.Info
// that can be added to a key store, or written to a keychain item, and used as
// a JWT signing key, as well as the public key for use as a verification key.
// The private key is stored as the key's token with the algorithm and public
// key in its extra information, as described by KeyExtra.
func NewED25519KeyInfo(id, user string) (keys.Info, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return keys.Info{}, fmt.Errorf("failed to generate an ed25519 key pair: %w", err)
	}
	info := keys.NewInfo(id, user, []byte(base64.StdEncoding.EncodeToString(priv)))
	info.WithExtra(KeyExtra{
		Algorithm: jwa.EdDSAEd25519().String(),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	})
	return info, nil
}

// ED25519 is the JWKKey implementation for keys created by NewED25519KeyInfo,
// registered under the jwa.EdDSAEd25519 algorithm name (see KeyExtra). It
// signs and verifies using the classic, widely supported "EdDSA" JWS
// algorithm rather than the JWA name it is registered under, since the two
// name the same Ed25519 signature scheme and "EdDSA" remains the more
// interoperable choice on the wire.
type ED25519 struct{}

// Signer implements JWKKey by importing the ed25519 private key stored as
// info's token, which must be base64, standard encoding, of the 64 byte
// private key.
func (e ED25519) Signer(info keys.Info) (Signer, error) {
	decoded, cleanup, err := decodeBase64(info.Token().Value())
	defer cleanup()
	if err != nil {
		return nil, fmt.Errorf("key %v: %w", info.KeySpec(), err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key %v: expected a base64 encoded ed25519 private key of %v bytes, got %v",
			info.KeySpec(), ed25519.PrivateKeySize, len(decoded))
	}
	jwkKey, err := jwk.Import(ed25519.PrivateKey(decoded))
	if err != nil {
		return nil, fmt.Errorf("key %v: failed to import JWK: %w", info.KeySpec(), err)
	}
	// The key id must match the one PublicKey sets on the corresponding
	// verification key for it to be selected by jwt.WithKeySet when verifying
	// a token signed by this key.
	return NewSigner(jwkKey, info.KeySpec().ID, jwa.EdDSA())
}

// PublicKey implements JWKKey by importing the ed25519 public key stored in
// info's extra information, which must be base64, standard encoding, of the
// 32 byte public key.
func (e ED25519) PublicKey(info keys.Info) (jwk.Key, error) {
	var extra KeyExtra
	if err := info.UnmarshalExtra(&extra); err != nil {
		return nil, fmt.Errorf("key %v: failed to unmarshal extra information: %w", info.KeySpec(), err)
	}
	if extra.PublicKey == "" {
		return nil, fmt.Errorf("key %v: no public_key in extra information", info.KeySpec())
	}
	decoded, cleanup, err := decodeBase64([]byte(extra.PublicKey))
	defer cleanup()
	if err != nil {
		return nil, fmt.Errorf("key %v: public_key: %w", info.KeySpec(), err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key %v: public_key is not a base64 encoded ed25519 public key of %v bytes, got %v",
			info.KeySpec(), ed25519.PublicKeySize, len(decoded))
	}
	// jwk.Import stores an ed25519.PublicKey's bytes as given, without cloning
	// them, unlike the private key path below; clone here so that cleanup
	// zeroing decoded on return does not corrupt the imported key.
	jwkKey, err := jwk.Import(ed25519.PublicKey(slices.Clone(decoded)))
	if err != nil {
		return nil, fmt.Errorf("key %v: failed to import JWK: %w", info.KeySpec(), err)
	}
	for _, kv := range []struct {
		k string
		v any
	}{
		{jwk.AlgorithmKey, jwa.EdDSA()},
		{jwk.KeyUsageKey, "sig"},
	} {
		if err := jwkKey.Set(kv.k, kv.v); err != nil {
			return nil, fmt.Errorf("key %v: %w", info.KeySpec(), err)
		}
	}
	return jwkKey, nil
}

func init() {
	algoRegistry.Register(jwa.EdDSAEd25519().String(), func(context.Context, ...any) (JWKKey, error) {
		return ED25519{}, nil
	})
}
