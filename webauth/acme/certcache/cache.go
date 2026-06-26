// Copyright 2021 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

// Package certcache  provides support for working with autocert
// caches with persistent backing stores for storing and distributing
// certificates.
package certcache

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"cloudeng.io/errors"
	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/os/lockedfile"
	"cloudeng.io/webapp"
	"golang.org/x/crypto/acme/autocert"
)

// CachingStore implements a 'caching store' that intergrates with
// autocert. It provides an instance of autocert.Cache that will store
// certificates in 'backing' store, but use the local file system for
// temporary/private data such as the ACME client's private key. This
// allows for certificates to be shared across multiple hosts by using
// a distributed 'backing' store such as AWS' secretsmanager.
// In addition, certificates may be extracted safely on the host that
// manages them programmatically.
type CachingStore struct {
	lock         *lockedfile.Mutex
	localCache   autocert.Cache
	backingStore StoreFS
	opts         options
}

// ErrCacheMiss is the same as autocert.ErrCacheMiss
var ErrCacheMiss = autocert.ErrCacheMiss

// StoreFS defines an interface that combines reading, writing
// and deleting files and is used to create an acme/autocert cache.
type StoreFS interface {
	ReadFile(name string) ([]byte, error)
	ReadFileCtx(ctx context.Context, name string) ([]byte, error)
	WriteFileCtx(ctx context.Context, name string, data []byte, perm fs.FileMode) error
	Delete(ctx context.Context, name string) error
}

type Option func(o *options)

type options struct {
	readonly           bool
	saveAccountKeyName string
	logger             *slog.Logger
	allowRSAKeys       bool
	metrics            webapp.CounterVecInc
}

// WithReadonly sets whether the caching store is readonly.
func WithReadonly(readonly bool) Option {
	return func(o *options) {
		o.readonly = readonly
	}
}

// WithSaveAccountKey sets whether ACME account keys are to be saved to
// the backing store using the specified name.
func WithSaveAccountKey(name string) Option {
	return func(o *options) {
		o.saveAccountKeyName = name
	}
}

// HasReadonlyOption returns true if the supplied options include
// the WithReadonly option set to true.
func HasReadonlyOption(opts []Option) bool {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o.readonly
}

// WithLogger sets the logger to use for logging cache operations.
// This is the only way to set a logger since the context passed used
// when invoking autocert.Cache methods is derived from context.Background()
// and cannot be otherwise specified.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) {
		o.logger = logger
	}
}

// WithAllowRSAKeys sets whether RSA keys are allowed to be used for ACME
// account keys. By default, RSA keys are not allowed since they are not
// intended for legacy clients only.
func WithAllowRSAKeys(allow bool) Option {
	return func(o *options) {
		o.allowRSAKeys = allow
	}
}

// WithMetrics sets the metrics to use for logging cache operations.
func WithMetrics(metrics webapp.CounterVecInc) Option {
	return func(o *options) {
		o.metrics = metrics
	}
}

// MetricsColumns returns the list of columns that will be used
// for metric. Name represents the cache key name and operation represents the
// operation performed
func MetricsColumns() []string {
	return []string{"name", "operation"}
}

// MetricsOperationValues returns the list of values that will be used
// for the "operation" label of the metric.
func MetricsOperationValues() []string {
	return []string{"get", "put", "delete", "get-backing", "put-backing", "delete-backing"}
}

// NewCachingStore returns an instance of autocert.Cache that will store
// certificates in 'backing' store, but use the local file system for
// temporary/private data such as the ACME client's private key. This
// allows for certificates to be shared across multiple hosts by using
// a distributed 'backing' store such as AWS' secretsmanager.
// Certificates may be extracted safely for use by other servers.
// CachingStore implements autocert.Cache.
func NewCachingStore(localDir string, backingStore StoreFS, opts ...Option) (*CachingStore, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.logger == nil {
		o.logger = slog.New(slog.DiscardHandler)
	}
	if o.metrics == nil {
		o.metrics = func(context.Context, ...string) {}
	}
	if err := os.MkdirAll(localDir, 0700); err != nil {
		return nil, err
	}
	cache := &CachingStore{
		lock:         lockedfile.MutexAt(filepath.Join(localDir, "dir.lock")),
		localCache:   autocert.DirCache(localDir),
		backingStore: backingStore,
		opts:         o,
	}
	if o.readonly {
		// Use the lock in order to create the lock file if it does not already
		// exist, since RLock will fail if the lock file does not already exist.
		unlock, err := cache.lock.Lock()
		if err != nil {
			return nil, fmt.Errorf("lock acquisition failed: %w", err)
		}
		unlock()
	}
	return cache, nil
}

// IsAcmeAccountKey returns true if the specified name is for an
// ACME account private key.
func IsAcmeAccountKey(name string) bool {
	return name == "acme_account+key" || name == "acme_account.key"
}

// IsLocalName returns true if the specified name is for local-only
// data such as ACME client private keys or http-01 challenge tokens.
// If allowRSAKeys is false, RSA keys are considered local-only and are never
// written to backing stores since they are intended for legacy clients only.
func IsLocalName(name string, allowRSAKeys bool) bool {
	return strings.HasSuffix(name, "+token") ||
		(strings.HasSuffix(name, "+rsa") && !allowRSAKeys) ||
		strings.Contains(name, "http-01") ||
		IsAcmeAccountKey(name)
}

var (
	ErrReadonlyCache    = errors.New("readonly cache")
	ErrLocalOperation   = errors.New("local operation")
	ErrBackingOperation = errors.New("backing store operation")
	ErrLockFailed       = errors.New("lock acquisition failed")
)

func (dc *CachingStore) isRSAKeyAllowed(name string) bool {
	if !strings.HasSuffix(name, "+rsa") {
		return true
	}
	return dc.opts.allowRSAKeys
}

// Delete implements autocert.Cache.
func (dc *CachingStore) Delete(ctx context.Context, name string) error {
	if dc.opts.readonly {
		return fmt.Errorf("webauth/acme/certcache: delete %q: %w", name, ErrReadonlyCache)
	}
	dc.opts.metrics(ctx, name, "delete")
	ctxlog.Warn(ctx, "webauth/acme/certcache: delete", "key", name)
	if !IsLocalName(name, dc.opts.allowRSAKeys) {
		dc.opts.metrics(ctx, name, "delete-backing")
		if err := dc.backingStore.Delete(ctx, name); err != nil {
			return fmt.Errorf("webauth/acme/certcache: delete %q: %w", name, errors.NewM(err, ErrBackingOperation))
		}
		return nil
	}
	unlock, err := dc.lock.Lock()
	if err != nil {
		return errors.NewM(fmt.Errorf("webauth/acme/certcache: delete %q: lock acquisition failed: %w", name, err), ErrLockFailed)
	}
	defer unlock()
	if err := dc.localCache.Delete(ctx, name); err != nil {
		return fmt.Errorf("webauth/acme/certcache: delete %q: %w", name, errors.NewM(err, ErrLocalOperation))
	}
	return nil

}

func (dc *CachingStore) translateCacheMiss(err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, autocert.ErrCacheMiss) || errors.Is(err, os.ErrNotExist) {
		return ErrCacheMiss
	}
	return err
}

// Get implements autocert.Cache.
func (dc *CachingStore) Get(ctx context.Context, name string) ([]byte, error) {
	dc.opts.metrics(ctx, name, "get")
	if bname, backingStore := dc.useBackingStore(name); backingStore {
		dc.opts.metrics(ctx, bname, "get-backing")
		dc.opts.logger.Info("webauth/acme/certcache: get using backing store", "key", name, "backing store name", bname)
		data, err := dc.backingStore.ReadFileCtx(ctx, bname)
		if err != nil {
			if err = dc.translateCacheMiss(err); err == ErrCacheMiss {
				return nil, ErrCacheMiss
			}
			return nil, fmt.Errorf("webauth/acme/certcache: get %q: backing store name %q: %w", name, bname, errors.NewM(err, ErrBackingOperation))
		}
		return data, nil
	}
	var err error
	var unlock func()
	if dc.opts.readonly {
		unlock, err = dc.lock.RLock()
	} else {
		unlock, err = dc.lock.Lock()
	}
	if err != nil {
		return nil, errors.NewM(fmt.Errorf("webauth/acme/certcache: get lock acquisition failed: %w", err), ErrLockFailed)
	}
	defer unlock()
	data, err := dc.localCache.Get(ctx, name)
	if err != nil {
		if err = dc.translateCacheMiss(err); err == ErrCacheMiss {
			return nil, ErrCacheMiss
		}
		return nil, fmt.Errorf("webauth/acme/certcache: get %q: %w", name, errors.NewM(err, ErrLocalOperation))
	}
	return data, nil
}

func (dc *CachingStore) useBackingStore(name string) (string, bool) {
	if !IsLocalName(name, dc.opts.allowRSAKeys) {
		return name, true
	}
	if len(dc.opts.saveAccountKeyName) > 0 && IsAcmeAccountKey(name) {
		return dc.opts.saveAccountKeyName, true
	}
	return name, false
}

// Put implements autocert.Cache.
func (dc *CachingStore) Put(ctx context.Context, name string, data []byte) error {
	dc.opts.metrics(ctx, name, "put")
	if !dc.isRSAKeyAllowed(name) {
		return fmt.Errorf("put %q: %w", name, errors.NewM(fmt.Errorf("RSA keys are not enabled"), ErrBackingOperation))
	}
	if dc.opts.readonly {
		dc.opts.logger.Error("webauth/acme/certcache: put readonly cache", "key", name)
		return fmt.Errorf("put %q: %w", name, ErrReadonlyCache)
	}
	if bname, backingStore := dc.useBackingStore(name); backingStore {
		dc.opts.metrics(ctx, bname, "put-backing")
		if err := dc.backingStore.WriteFileCtx(ctx, bname, data, 0600); err != nil {
			dc.opts.logger.Error("webauth/acme/certcache: put backing store failed", "key", name, "backing store name", bname, "error", err)
			return fmt.Errorf("put %q, backing store name: %q: %w", name, bname, errors.NewM(err, ErrBackingOperation))
		}
		dc.opts.logger.Info("webauth/acme/certcache: put backing store succeeded", "key", name, "backing store name", bname)
		return nil
	}
	unlock, err := dc.lock.Lock()
	if err != nil {
		return errors.NewM(fmt.Errorf("webauth/acme/certcache: put lock acquisition failed: %w", err), ErrLockFailed)
	}
	defer unlock()
	if err := dc.localCache.Put(ctx, name, data); err != nil {
		dc.opts.logger.Error("webauth/acme/certcache: put local cache failed", "key", name, "error", err)
		return fmt.Errorf("put %q: %w", name, errors.NewM(err, ErrLocalOperation))
	}
	dc.opts.logger.Info("webauth/acme/certcache: put local cache succeeded", "key", name)
	return nil
}

// Implement file.ReadfileFS“
func (dc *CachingStore) ReadFile(name string) ([]byte, error) {
	return dc.ReadFileCtx(context.Background(), name)
}

// Implement file.ReadfileFS
func (dc *CachingStore) ReadFileCtx(ctx context.Context, name string) ([]byte, error) {
	return dc.Get(ctx, name)
}

// Implement file.WritefileFS
func (dc *CachingStore) WriteFile(name string, data []byte, perm fs.FileMode) error {
	return dc.WriteFileCtx(context.Background(), name, data, perm)
}

// Implement file.WritefileFS
func (dc *CachingStore) WriteFileCtx(ctx context.Context, name string, data []byte, _ fs.FileMode) error {
	return dc.Put(ctx, name, data)
}

type localCache struct {
	root string
}

func NewLocalStore(dir string) (StoreFS, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &localCache{root: dir}, nil
}

func (lc *localCache) path(name string) string {
	return filepath.Join(lc.root, name)
}

func (lc *localCache) ReadFile(name string) ([]byte, error) {
	return lc.ReadFileCtx(context.Background(), name)
}

// Implement autocert.StoreFS.
func (lc *localCache) ReadFileCtx(_ context.Context, name string) ([]byte, error) {
	return os.ReadFile(lc.path(name))
}

func (lc *localCache) WriteFileCtx(_ context.Context, name string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(lc.path(name), data, perm)
}

func (lc *localCache) Delete(_ context.Context, name string) error {
	return os.Remove(lc.path(name))
}
