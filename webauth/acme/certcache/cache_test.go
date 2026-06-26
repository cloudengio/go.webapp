// Copyright 2021 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package certcache_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"cloudeng.io/os/lockedfile"
	"cloudeng.io/webapp/webauth/acme/certcache"
	"github.com/stretchr/testify/require"
)

// metricsCall records a single invocation of a webapp.CounterVecInc, in
// terms of the (name, operation) labels passed to it by CachingStore.
type metricsCall struct {
	name, op string
}

// fakeMetrics is a webapp.CounterVecInc that records every call it
// receives for later inspection.
type fakeMetrics struct {
	mu    sync.Mutex
	calls []metricsCall
}

func (f *fakeMetrics) Inc(_ context.Context, labels ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, metricsCall{name: labels[0], op: labels[1]})
}

func (f *fakeMetrics) Calls() []metricsCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

type mockCacheFS struct {
	mu    sync.Mutex
	store map[string][]byte
	err   error // to inject errors
}

func newMockCacheFS() *mockCacheFS {
	return &mockCacheFS{
		store: make(map[string][]byte),
	}
}

func (m *mockCacheFS) ReadFile(name string) ([]byte, error) {
	return m.ReadFileCtx(context.Background(), name)
}

func (m *mockCacheFS) ReadFileCtx(_ context.Context, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	data, ok := m.store[name]
	if !ok {
		return nil, certcache.ErrCacheMiss
	}
	return data, nil
}

func (m *mockCacheFS) WriteFileCtx(_ context.Context, name string, data []byte, _ fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.store[name] = data
	return nil
}

func (m *mockCacheFS) Delete(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	delete(m.store, name)
	return nil
}

func TestIsLocalName(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name         string
		allowRSAKeys bool
		local        bool
	}{
		{"example.com", false, false},
		{"example.com", true, false},
		{"foo.bar.org", false, false},
		{"example.com+token", false, true},
		{"example.com+token", true, true},
		// +rsa names are local-only unless allowRSAKeys is true.
		{"example.com+rsa", false, true},
		{"example.com+rsa", true, false},
		{"acme_account.key+token", false, true},
		{"acme_account+key", false, true},
		{"acme_account.key", false, true},
		{"something/http-01/foo", false, true},
	}
	for _, tc := range testCases {
		if got, want := certcache.IsLocalName(tc.name, tc.allowRSAKeys), tc.local; got != want {
			t.Errorf("IsLocalName(%q, allowRSAKeys=%v): got %v, want %v", tc.name, tc.allowRSAKeys, got, want)
		}
	}
}

func TestIsAcmeAccountKey(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name  string
		isKey bool
	}{
		{"example.com", false},
		{"foo.bar.org", false},
		{"example.com+token", false},
		{"example.com+rsa", false},
		{"acme_account+key", true},
		{"acme_account.key", true},
		{"acme_account.key+token", false},
		{"something/http-01/foo", false},
	}
	for _, tc := range testCases {
		if got, want := certcache.IsAcmeAccountKey(tc.name), tc.isKey; got != want {
			t.Errorf("IsAcmeAccountKey(%q): got %v, want %v", tc.name, got, want)
		}
	}
}

func setupCache(t *testing.T, readonly bool) (*certcache.CachingStore, *mockCacheFS, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	mockFS := newMockCacheFS()
	cache, err := certcache.NewCachingStore(tmpDir, mockFS, certcache.WithReadonly(readonly))
	if err != nil {
		t.Fatal(err)
	}
	return cache, mockFS, func() {}
}

func TestCacheReadonly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cache, _, cleanup := setupCache(t, true)
	defer cleanup()

	// Put should fail.
	err := cache.Put(ctx, "remote.com", []byte("cert"))
	if !errors.Is(err, certcache.ErrReadonlyCache) {
		t.Errorf("got %v, want %v", err, certcache.ErrReadonlyCache)
	}
	err = cache.Put(ctx, "local.key+token", []byte("key"))
	if !errors.Is(err, certcache.ErrReadonlyCache) {
		t.Errorf("got %v, want %v", err, certcache.ErrReadonlyCache)
	}

	// Delete should fail.
	err = cache.Delete(ctx, "remote.com")
	if !errors.Is(err, certcache.ErrReadonlyCache) {
		t.Errorf("got %v, want %v", err, certcache.ErrReadonlyCache)
	}
	err = cache.Delete(ctx, "local.key+token")
	if !errors.Is(err, certcache.ErrReadonlyCache) {
		t.Errorf("got %v, want %v", err, certcache.ErrReadonlyCache)
	}
}

func TestCacheMiss(t *testing.T) {
	ctx := context.Background()
	for _, readonly := range []bool{true, false} {
		cache, mockFS, cleanup := setupCache(t, readonly)
		defer cleanup()
		// Get should return miss.
		for _, mockErr := range []error{nil, os.ErrNotExist, fs.ErrNotExist, certcache.ErrCacheMiss} {
			mockFS.err = mockErr
			_, err := cache.Get(ctx, "remote.com")
			if !errors.Is(err, certcache.ErrCacheMiss) {
				t.Errorf("got %v, want %v", err, certcache.ErrCacheMiss)
			}
			_, err = cache.Get(ctx, "local.key+token")
			if !errors.Is(err, certcache.ErrCacheMiss) {
				t.Errorf("got %v, want %v", err, certcache.ErrCacheMiss)
			}
		}
	}

}

func TestCacheReadWrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cache, mockFS, cleanup := setupCache(t, false)
	defer cleanup()

	remoteName, remoteData := "remote.com", []byte("cert-data")
	localName, localData := "acme_account.key+token", []byte("key-data")

	// Test Put
	if err := cache.Put(ctx, remoteName, remoteData); err != nil {
		t.Fatal(err)
	}
	if err := cache.Put(ctx, localName, localData); err != nil {
		t.Fatal(err)
	}

	// Test Get
	// Remote
	gotData, err := cache.Get(ctx, remoteName)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotData, remoteData) {
		t.Errorf("got %q, want %q", gotData, remoteData)
	}
	if got, want := mockFS.store[remoteName], remoteData; !reflect.DeepEqual(got, want) {
		t.Errorf("backing store: got %q, want %q", got, want)
	}

	// Local
	gotData, err = cache.Get(ctx, localName)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotData, localData) {
		t.Errorf("got %q, want %q", gotData, localData)
	}

	// Test Delete
	// Remote
	if err := cache.Delete(ctx, remoteName); err != nil {
		t.Fatal(err)
	}
	_, err = cache.Get(ctx, remoteName)
	if !errors.Is(err, certcache.ErrCacheMiss) {
		t.Errorf("got %v, want %v", err, certcache.ErrCacheMiss)
	}
	if _, ok := mockFS.store[remoteName]; ok {
		t.Errorf("remote entry not deleted from backing store")
	}

	// Local
	if err := cache.Delete(ctx, localName); err != nil {
		t.Fatal(err)
	}
	_, err = cache.Get(ctx, localName)
	if !errors.Is(err, certcache.ErrCacheMiss) {
		t.Errorf("got %v, want %v", err, certcache.ErrCacheMiss)
	}
}

func TestCacheLocking(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tmpDir := t.TempDir()
	mockFS := newMockCacheFS()
	cache, err := certcache.NewCachingStore(tmpDir, mockFS, certcache.WithReadonly(false))
	if err != nil {
		t.Fatal(err)
	}

	localName, localData := "local.key+token", []byte("key")
	if err := cache.Put(ctx, localName, localData); err != nil {
		t.Fatal(err)
	}

	// Manually lock the file to simulate contention.
	m := lockedfile.MutexAt(filepath.Join(tmpDir, "dir.lock"))
	unlock, err := m.Lock()
	if err != nil {
		t.Fatal(err)
	}

	timeCh := make(chan time.Time, 3)
	errCh := make(chan error, 3)

	start := time.Now()

	go func() {
		err := cache.Put(ctx, localName, []byte("new-data"))
		errCh <- err
		timeCh <- time.Now()
		_, err = cache.Get(ctx, localName)
		errCh <- err
		timeCh <- time.Now()
		err = cache.Delete(ctx, localName)
		errCh <- err
		timeCh <- time.Now()
	}()

	time.Sleep(time.Second)
	unlock()
	stopped := time.Now().Add(time.Millisecond * 100)
	for range 3 {
		err := <-errCh
		if err != nil {
			t.Errorf("got %v, want %v", err, context.DeadlineExceeded)
		}
		done := <-timeCh
		if done.Before(start) || done.After(stopped) {
			t.Errorf("operation did not wait for lock release (start .. done .. stopped) %v .. %v .. %v", start, done, stopped)
		}
	}

	if err := cache.Put(ctx, localName, localData); err != nil {
		t.Fatal(err)
	}

	// Change the permissions on the lock file to simulate lock acquisition failure.
	err = os.Chmod(filepath.Join(tmpDir, "dir.lock"), 0000)
	require.NoError(t, err)

	err = cache.Put(ctx, localName, []byte("new-data"))
	require.ErrorIs(t, err, certcache.ErrLockFailed)

	_, err = cache.Get(ctx, localName)
	require.ErrorIs(t, err, certcache.ErrLockFailed)

	err = cache.Delete(ctx, localName)
	require.ErrorIs(t, err, certcache.ErrLockFailed)

	err = os.Chmod(tmpDir, 0700)
	require.NoError(t, err)
}

func TestCacheACMEKeyInBackingStore(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	mockFS := newMockCacheFS()
	cache, err := certcache.NewCachingStore(tmpDir, mockFS, certcache.WithSaveAccountKey("another-name-in-backing-store"))
	if err != nil {
		t.Fatal(err)
	}

	keyName := "acme_account+key"

	err = cache.Put(ctx, keyName, []byte("acme-key-data"))
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the data is in the backing store under the specified name.
	data, err := mockFS.ReadFileCtx(ctx, "another-name-in-backing-store")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "acme-key-data"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	data, err = cache.Get(ctx, keyName)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "acme-key-data"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

}

func TestMetricsColumnsAndOperationValues(t *testing.T) {
	t.Parallel()
	if got, want := certcache.MetricsColumns(), []string{"name", "operation"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got, want := certcache.MetricsOperationValues(), []string{"get", "put", "delete", "get-backing", "put-backing", "delete-backing"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCacheMetricsBackingStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tmpDir := t.TempDir()
	mockFS := newMockCacheFS()
	metrics := &fakeMetrics{}
	cache, err := certcache.NewCachingStore(tmpDir, mockFS, certcache.WithMetrics(metrics.Inc))
	if err != nil {
		t.Fatal(err)
	}

	name := "remote.com"
	if err := cache.Put(ctx, name, []byte("cert-data")); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := cache.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}

	want := []metricsCall{
		{name, "put"},
		{name, "put-backing"},
		{name, "get"},
		{name, "get-backing"},
		{name, "delete"},
		{name, "delete-backing"},
	}
	if got := metrics.Calls(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCacheMetricsLocal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tmpDir := t.TempDir()
	mockFS := newMockCacheFS()
	metrics := &fakeMetrics{}
	cache, err := certcache.NewCachingStore(tmpDir, mockFS, certcache.WithMetrics(metrics.Inc))
	if err != nil {
		t.Fatal(err)
	}

	name := "local.key+token"
	if err := cache.Put(ctx, name, []byte("key-data")); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := cache.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}

	// Local-only names never hit the backing store, so only the
	// non-"-backing" operations are recorded.
	want := []metricsCall{
		{name, "put"},
		{name, "get"},
		{name, "delete"},
	}
	if got := metrics.Calls(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCacheMetricsACMEKeyRenamedInBackingStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tmpDir := t.TempDir()
	mockFS := newMockCacheFS()
	metrics := &fakeMetrics{}
	const backingName = "another-name-in-backing-store"
	cache, err := certcache.NewCachingStore(tmpDir, mockFS,
		certcache.WithSaveAccountKey(backingName),
		certcache.WithMetrics(metrics.Inc),
	)
	if err != nil {
		t.Fatal(err)
	}

	keyName := "acme_account+key"
	if err := cache.Put(ctx, keyName, []byte("acme-key-data")); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(ctx, keyName); err != nil {
		t.Fatal(err)
	}

	// The "-backing" labelled calls use the renamed backing store key, not
	// the original cache name.
	want := []metricsCall{
		{keyName, "put"},
		{backingName, "put-backing"},
		{keyName, "get"},
		{backingName, "get-backing"},
	}
	if got := metrics.Calls(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCacheMetricsReadonly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tmpDir := t.TempDir()
	mockFS := newMockCacheFS()
	metrics := &fakeMetrics{}
	cache, err := certcache.NewCachingStore(tmpDir, mockFS,
		certcache.WithReadonly(true),
		certcache.WithMetrics(metrics.Inc),
	)
	if err != nil {
		t.Fatal(err)
	}

	name := "remote.com"
	// Put records its "put" metric before checking readonly, so it is
	// recorded even though the operation itself fails.
	if err := cache.Put(ctx, name, []byte("cert-data")); !errors.Is(err, certcache.ErrReadonlyCache) {
		t.Fatalf("got %v, want %v", err, certcache.ErrReadonlyCache)
	}
	// Delete checks readonly before recording any metric, so nothing is
	// recorded for it.
	if err := cache.Delete(ctx, name); !errors.Is(err, certcache.ErrReadonlyCache) {
		t.Fatalf("got %v, want %v", err, certcache.ErrReadonlyCache)
	}

	want := []metricsCall{{name, "put"}}
	if got := metrics.Calls(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLocalStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tmpDir := t.TempDir()

	store, err := certcache.NewLocalStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// Test Write
	name, data := "test-file", []byte("test-data")
	if err := store.WriteFileCtx(ctx, name, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Verify file exists and has correct content
	filePath := filepath.Join(tmpDir, name)
	readData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(readData, data) {
		t.Errorf("got %q, want %q", readData, data)
	}

	// Test Read
	readData, err = store.ReadFileCtx(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(readData, data) {
		t.Errorf("got %q, want %q", readData, data)
	}

	// Test Delete
	if err := store.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}

	// Verify file is gone
	_, err = os.Stat(filePath)
	if !os.IsNotExist(err) {
		t.Errorf("expected file to not exist, but got err: %v", err)
	}

	// Test Read on non-existent file
	_, err = store.ReadFileCtx(ctx, "non-existent")
	if !os.IsNotExist(err) {
		t.Errorf("expected not-exist error, but got: %v", err)
	}
}
