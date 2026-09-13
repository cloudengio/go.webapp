// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"

	"cloudeng.io/cmdutil/keys"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var (
	// ErrNoKeyStore is returned when the context supplied to one of the
	// configuration driven constructors does not contain a
	// keys.InMemoryKeyStore.
	ErrNoKeyStore = errors.New("no key store in context")

	// ErrKeyNotFound is returned when a key named by a configuration is not
	// present in the key store obtained from the context.
	ErrKeyNotFound = errors.New("key not found")
)

// KeyExtra describes the optional metadata that may be stored in the 'extra'
// field of a keys.Info alongside the key material itself, ie.:
//
//	key_id: jwt-signing-key
//	token: <base64 encoded key material>
//	extra:
//	  algorithm: EdDSA
//	  public_key: <base64 encoded public key>
//
// All key material is base64 encoded using the standard encoding, or is a JWK
// in its JSON representation. Both of the fields below are optional. Algorithm
// names a JWS signature algorithm (EdDSA, RS256, ES256 etc) and defaults to
// EdDSA, which is the only algorithm for which raw (ie. non-JWK) key material
// is supported. PublicKey is used by verification keys whose public key cannot
// be derived from the stored token.
type KeyExtra struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	PublicKey string `json:"public_key" yaml:"public_key"`
}

// keyInfoFromContext returns the key identified by spec from the key store
// stored in ctx, see keys.ContextWithKeyStore. A spec that does not name a user
// matches a key with the same id belonging to any user, provided that there is
// exactly one such key.
func keyInfoFromContext(ctx context.Context, spec keys.KeySpec) (keys.Info, error) {
	store, ok := keys.KeyStoreFromContext(ctx)
	if !ok || store == nil {
		return keys.Info{}, fmt.Errorf("%w: cannot obtain key %v", ErrNoKeyStore, spec)
	}
	if info, ok := store.Get(spec.User, spec.ID); ok {
		return info, nil
	}
	if spec.User != "" {
		return keys.Info{}, fmt.Errorf("%w: %v", ErrKeyNotFound, spec)
	}
	var matches []keys.Info
	for _, info := range store.Keys() {
		if info.ID == spec.ID {
			matches = append(matches, info)
		}
	}
	switch len(matches) {
	case 0:
		return keys.Info{}, fmt.Errorf("%w: %v", ErrKeyNotFound, spec)
	case 1:
		return matches[0], nil
	}
	users := make([]string, 0, len(matches))
	for _, info := range matches {
		users = append(users, info.User)
	}
	return keys.Info{}, fmt.Errorf("key %v does not name a user and is ambiguous: it is held by users %v", spec, users)
}

// NewED25519KeyInfo generates an ed25519 key pair and returns it as a keys.Info
// that can be added to a key store, or written to a keychain item, and used as a
// JWT signing key, as well as the public key for use as a verification key. The
// private key is stored as the key's token with the algorithm and public key in
// its extra information, as described by KeyExtra.
func NewED25519KeyInfo(id, user string) (keys.Info, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return keys.Info{}, nil, fmt.Errorf("failed to generate an ed25519 key pair: %w", err)
	}
	info := keys.NewInfo(id, user, []byte(base64.StdEncoding.EncodeToString(priv)))
	info.WithExtra(KeyExtra{
		Algorithm: jwa.EdDSA().String(),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	})
	return info, pub, nil
}

// keyExtra returns the KeyExtra stored with info, if any. Missing or
// unrecognized extra information yields a zero KeyExtra rather than an error
// since all of its fields are optional.
func keyExtra(info keys.Info) KeyExtra {
	var extra KeyExtra
	if err := info.UnmarshalExtra(&extra); err == nil {
		return extra
	}
	// keys.Info.WithExtra stores values as they are supplied and
	// UnmarshalExtra will only assign them to a value of their original type,
	// so handle the generic map form that is used when the extra information
	// is created programmatically rather than unmarshalled.
	if m, ok := info.GetExtra().(map[string]any); ok {
		extra.Algorithm, _ = m["algorithm"].(string)
		extra.PublicKey, _ = m["public_key"].(string)
	}
	return extra
}

// signatureAlgorithm returns the signature algorithm named by extra, defaulting
// to EdDSA.
func signatureAlgorithm(extra KeyExtra) (jwa.SignatureAlgorithm, error) {
	if extra.Algorithm == "" {
		return jwa.EdDSA(), nil
	}
	algo, ok := jwa.LookupSignatureAlgorithm(extra.Algorithm)
	if !ok {
		return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported signature algorithm: %q", extra.Algorithm)
	}
	return algo, nil
}

// decodeKeyMaterial returns the key material stored in a keys.Info token, which
// must be base64, standard encoding, and decode to one of the supplied sizes.
func decodeKeyMaterial(raw []byte, sizes ...int) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil || !slices.Contains(sizes, len(decoded)) {
		return nil, false
	}
	return decoded, true
}

// jwkFromToken returns the key parsed from token if it contains a JWK, ie. a
// JSON object, rather than raw key material.
func jwkFromToken(token []byte) (jwk.Key, bool, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(token), []byte("{")) {
		return nil, false, nil
	}
	key, err := jwk.ParseKey(token)
	if err != nil {
		return nil, true, fmt.Errorf("failed to parse JWK: %w", err)
	}
	return key, true, nil
}

// jwkAlgorithm returns the signature algorithm to use with a key parsed from a
// JWK, preferring the algorithm named by extra over the key's own 'alg' field.
func jwkAlgorithm(key jwk.Key, extra KeyExtra) (jwa.SignatureAlgorithm, error) {
	if extra.Algorithm != "" {
		return signatureAlgorithm(extra)
	}
	if alg, ok := key.Algorithm(); ok && alg.String() != "" {
		return signatureAlgorithm(KeyExtra{Algorithm: alg.String()})
	}
	return jwa.SignatureAlgorithm{}, fmt.Errorf("no signature algorithm specified by the JWK or its extra information")
}

// signingKey returns the private key to sign with and the algorithm to use for
// the key material in info, see KeyExtra for the storage conventions used.
// Base64 encoded key material is interpreted as an ed25519 private key (or its
// seed).
func signingKey(info keys.Info) (jwk.Key, jwa.SignatureAlgorithm, error) {
	var zero jwa.SignatureAlgorithm
	extra := keyExtra(info)
	tok := info.Token()
	defer tok.Clear()
	key, isJWK, err := jwkFromToken(tok.Value())
	if err != nil {
		return nil, zero, fmt.Errorf("key %v: %w", info.KeySpec(), err)
	}
	if isJWK {
		algo, err := jwkAlgorithm(key, extra)
		if err != nil {
			return nil, zero, fmt.Errorf("key %v: %w", info.KeySpec(), err)
		}
		return key, algo, nil
	}
	algo, err := ed25519Algorithm(extra)
	if err != nil {
		return nil, zero, fmt.Errorf("key %v: %w", info.KeySpec(), err)
	}
	raw, ok := decodeKeyMaterial(tok.Value(), ed25519.PrivateKeySize, ed25519.SeedSize)
	if !ok {
		return nil, zero, fmt.Errorf("key %v: expected a base64 encoded ed25519 private key of %v bytes, or its %v byte seed",
			info.KeySpec(), ed25519.PrivateKeySize, ed25519.SeedSize)
	}
	priv := ed25519.PrivateKey(raw)
	if len(raw) == ed25519.SeedSize {
		priv = ed25519.NewKeyFromSeed(raw)
	}
	key, err = jwk.Import(priv)
	if err != nil {
		return nil, zero, fmt.Errorf("key %v: %w", info.KeySpec(), err)
	}
	return key, algo, nil
}

// ed25519Algorithm returns the signature algorithm to use with raw ed25519 key
// material, which must be an EdDSA algorithm.
func ed25519Algorithm(extra KeyExtra) (jwa.SignatureAlgorithm, error) {
	algo, err := signatureAlgorithm(extra)
	if err != nil {
		return algo, err
	}
	switch algo.String() {
	case jwa.EdDSA().String(), jwa.Ed25519().String():
		return algo, nil
	}
	return jwa.SignatureAlgorithm{}, fmt.Errorf("raw key material is interpreted as an ed25519 key and cannot be used with the %v algorithm, store the key as a JWK instead", algo)
}

// verificationKey returns the public key to verify with and the algorithm to
// use for the key material in info, see KeyExtra for the storage conventions
// used. The public key is taken from the 'public_key' extra field if present,
// otherwise it is derived from, or is, the stored token. Note that a 32 byte
// token is treated as a public key rather than as an ed25519 seed; store the
// full 64 byte private key, or the public key in the 'public_key' extra field,
// for a key that is used for both signing and verification.
func verificationKey(info keys.Info) (jwk.Key, jwa.SignatureAlgorithm, error) {
	var zero jwa.SignatureAlgorithm
	extra := keyExtra(info)
	tok := info.Token()
	defer tok.Clear()
	key, isJWK, err := jwkFromToken(tok.Value())
	if err != nil {
		return nil, zero, fmt.Errorf("key %v: %w", info.KeySpec(), err)
	}
	if isJWK {
		algo, err := jwkAlgorithm(key, extra)
		if err != nil {
			return nil, zero, fmt.Errorf("key %v: %w", info.KeySpec(), err)
		}
		pub, err := key.PublicKey()
		if err != nil {
			return nil, zero, fmt.Errorf("key %v: %w", info.KeySpec(), err)
		}
		return pub, algo, nil
	}
	algo, err := ed25519Algorithm(extra)
	if err != nil {
		return nil, zero, fmt.Errorf("key %v: %w", info.KeySpec(), err)
	}
	pub, err := ed25519PublicKey(info, extra)
	if err != nil {
		return nil, zero, err
	}
	key, err = jwk.Import(pub)
	if err != nil {
		return nil, zero, fmt.Errorf("key %v: %w", info.KeySpec(), err)
	}
	return key, algo, nil
}

// ed25519PublicKey returns the ed25519 public key for info as described by
// verificationKey.
func ed25519PublicKey(info keys.Info, extra KeyExtra) (ed25519.PublicKey, error) {
	if extra.PublicKey != "" {
		raw, ok := decodeKeyMaterial([]byte(extra.PublicKey), ed25519.PublicKeySize)
		if !ok {
			return nil, fmt.Errorf("key %v: public_key is not a base64 encoded ed25519 public key of %v bytes",
				info.KeySpec(), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(raw), nil
	}
	tok := info.Token()
	defer tok.Clear()
	raw, ok := decodeKeyMaterial(tok.Value(), ed25519.PrivateKeySize, ed25519.PublicKeySize)
	if !ok {
		return nil, fmt.Errorf("key %v: expected a base64 encoded ed25519 public key of %v bytes, or a private key of %v bytes",
			info.KeySpec(), ed25519.PublicKeySize, ed25519.PrivateKeySize)
	}
	if len(raw) == ed25519.PrivateKeySize {
		pub, ok := ed25519.PrivateKey(raw).Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key %v: failed to derive an ed25519 public key", info.KeySpec())
		}
		return pub, nil
	}
	return ed25519.PublicKey(raw), nil
}
