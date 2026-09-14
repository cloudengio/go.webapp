// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"cloudeng.io/cmdutil/keys"
	"cloudeng.io/cmdutil/registry"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var (
	// ErrNoKeyStore is returned when the context supplied to one of the
	// functions in this package does not contain a keys.InMemoryKeyStore.
	ErrNoKeyStore = errors.New("no key store in context")

	// ErrKeyNotFound is returned when a named key is not present in the key
	// store obtained from the context.
	ErrKeyNotFound = errors.New("key not found")
)

// KeyExtra describes the optional metadata that may be stored in the 'extra'
// field of a keys.Info alongside the key material itself, ie.:
//
//	key_id: jwt-signing-key
//	token: <base64 encoded key material>
//	extra:
//	  algorithm: Ed25519
//	  public_key: <base64 encoded public key>
//
// All key material is base64 encoded using the standard encoding. Algorithm
// selects the JWKKey implementation, registered under that name, used to turn
// the key material into a Signer or public jwk.Key; see NewED25519KeyInfo for
// the sole implementation currently provided by this package. PublicKey holds
// the public half of the key, required by a verification key since it is not
// derived from the token.
type KeyExtra struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	PublicKey string `json:"public_key" yaml:"public_key"`
}

// JWKKey defines the interface that must be implemented by any algorithm
// that can create signers and public keys from key material and associated
// metadata, see KeyExtra. Implementations register themselves under an
// algorithm name using algoRegistry, see NewED25519KeyInfo/ED25519 for the
// pattern to follow when adding another algorithm.
type JWKKey interface {
	Signer(keys.Info) (Signer, error)
	PublicKey(keys.Info) (jwk.Key, error)
}

var algoRegistry = registry.T[JWKKey]{}

// algoImpl returns the JWKKey implementation registered for the algorithm
// named in info's extra information.
func algoImpl(ctx context.Context, info keys.Info) (JWKKey, error) {
	var extra KeyExtra
	if err := info.UnmarshalExtra(&extra); err != nil {
		return nil, fmt.Errorf("key %v: failed to unmarshal extra information: %w", info.KeySpec(), err)
	}
	fn := algoRegistry.Get(extra.Algorithm)
	if fn == nil {
		return nil, fmt.Errorf("key %v: unsupported algorithm: %q", info.KeySpec(), extra.Algorithm)
	}
	impl, err := fn(ctx)
	if err != nil {
		return nil, fmt.Errorf("key %v: failed to create algorithm implementation for %q: %w",
			info.KeySpec(), extra.Algorithm, err)
	}
	return impl, nil
}

// NewSignerFromKeyInfo returns a Signer for the key material in info, using the
// JWKKey implementation registered for the algorithm named in its extra
// information.
func NewSignerFromKeyInfo(ctx context.Context, info keys.Info) (Signer, error) {
	impl, err := algoImpl(ctx, info)
	if err != nil {
		return nil, err
	}
	return impl.Signer(info)
}

// PublicKeyFromKeyInfo returns the public key corresponding to the key
// material in info, using the JWKKey implementation registered for the
// algorithm named in its extra information. The returned key carries the
// algorithm and usage required to verify a token signed by the corresponding
// Signer, but not a key id: that depends on how the key is being looked up
// and is the caller's responsibility to set, see keySetForKeys.
func PublicKeyFromKeyInfo(ctx context.Context, info keys.Info) (jwk.Key, error) {
	impl, err := algoImpl(ctx, info)
	if err != nil {
		return nil, err
	}
	return impl.PublicKey(info)
}

// keyInfoFromContext returns the key identified by spec from the key store
// stored in ctx, see keys.ContextWithKeyStore. A spec that does not name a
// user matches a key with the same id belonging to any user, provided that
// there is exactly one such key, see keys.InMemoryKeyStore.Get.
func keyInfoFromContext(ctx context.Context, spec keys.KeySpec) (keys.Info, error) {
	store, ok := keys.KeyStoreFromContext(ctx)
	if !ok || store == nil {
		return keys.Info{}, fmt.Errorf("%w: cannot obtain key %v", ErrNoKeyStore, spec)
	}
	info, ok := store.Get(spec.User, spec.ID)
	if !ok {
		return keys.Info{}, fmt.Errorf("%w: %v", ErrKeyNotFound, spec)
	}
	return info, nil
}

// NewSignerFromContext returns a Signer for the key identified by user and id,
// which is read from the keys.InMemoryKeyStore stored in ctx (see
// keys.ContextWithKeyStore). ErrNoKeyStore or ErrKeyNotFound are returned if
// the key is not available.
func NewSignerFromContext(ctx context.Context, user, id string) (Signer, error) {
	info, err := keyInfoFromContext(ctx, keys.KeySpec{User: user, ID: id})
	if err != nil {
		return nil, err
	}
	return NewSignerFromKeyInfo(ctx, info)
}

// decodeBase64 decodes raw using the standard base64 encoding and returns a
// cleanup function that zeroes the decoded bytes; callers should defer it once
// the decoded key material is no longer needed.
func decodeBase64(raw []byte) ([]byte, func(), error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	cleanup := func() {
		for i := range decoded {
			decoded[i] = 0
		}
	}
	n, err := base64.StdEncoding.Decode(decoded, raw)
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to decode base64: %w", err)
	}
	return decoded[:n], cleanup, nil
}
