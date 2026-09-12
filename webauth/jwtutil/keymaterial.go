// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package jwtutil

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
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
// Both fields are optional. Algorithm names a JWS signature algorithm
// (EdDSA, RS256, ES256 etc) and defaults to EdDSA, which is the only algorithm
// for which raw (ie. non-JWK) key material is supported. PublicKey is used by
// verification keys whose public key cannot be derived from the stored token.
type KeyExtra struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	PublicKey string `json:"public_key" yaml:"public_key"`
}

// keyInfoFromContext returns the key identified by spec from the key store
// stored in ctx, see keys.ContextWithKeyStore.
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
// may be base64 (standard, raw or URL) encoded, hex encoded, or the raw bytes
// themselves. These encodings are not mutually exclusive, a hex string is also
// valid base64 for example, so the first decoding whose length is one of the
// supplied sizes is returned. The token is only considered to be raw key
// material if it is not encoded text, since a hex encoded 32 byte key would
// otherwise be indistinguishable from 64 raw bytes.
func decodeKeyMaterial(raw []byte, sizes ...int) ([]byte, bool) {
	var candidates [][]byte
	trimmed := string(bytes.TrimSpace(raw))
	for _, decode := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if decoded, err := decode(trimmed); err == nil {
			candidates = append(candidates, decoded)
		}
	}
	if !isEncodedText(raw) {
		candidates = append(candidates, slices.Clone(raw))
	}
	for _, candidate := range candidates {
		if slices.Contains(sizes, len(candidate)) {
			return candidate, true
		}
	}
	return nil, false
}

// isEncodedText returns true if raw consists solely of the characters used by
// the encodings accepted by decodeKeyMaterial, ie. it cannot be raw key
// material.
func isEncodedText(raw []byte) bool {
	if len(raw) == 0 {
		return true
	}
	for _, c := range raw {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '-', c == '_', c == '=':
		case c == ' ', c == '\t', c == '\r', c == '\n':
		default:
			return false
		}
	}
	return true
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
// Raw key material is interpreted as an ed25519 private key (or its seed).
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
		return nil, zero, fmt.Errorf("key %v: expected an ed25519 private key of %v bytes, or its %v byte seed",
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
			return nil, fmt.Errorf("key %v: public_key is not an ed25519 public key of %v bytes",
				info.KeySpec(), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(raw), nil
	}
	tok := info.Token()
	defer tok.Clear()
	raw, ok := decodeKeyMaterial(tok.Value(), ed25519.PrivateKeySize, ed25519.PublicKeySize)
	if !ok {
		return nil, fmt.Errorf("key %v: expected an ed25519 public key of %v bytes, or a private key of %v bytes",
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
