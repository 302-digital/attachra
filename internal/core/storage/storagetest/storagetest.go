// Package storagetest provides a contract test suite shared by every
// storage.Driver implementation (ATR-177, ATR-174, SR-122-2). Each
// driver package (fs, s3) calls storagetest.Run(t, driverUnderTest)
// from its own _test.go file so the same behavioral contract —
// Put/Get/Stat/Delete round-trip, not-found semantics, streaming of
// large objects, concurrent Put, and rejection of malformed/traversal
// keys — is enforced identically across backends.
package storagetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/302-digital/attachra/internal/core/storage"
)

// Run executes the full contract test suite against drv, using
// newKey to obtain a fresh, valid object key for each subtest (so
// tests never collide with each other's objects and, for a real
// backend, never depend on any particular key format beyond what
// storage.NewObjectKey produces).
func Run(t *testing.T, drv storage.Driver, newKey func() string) {
	t.Helper()

	t.Run("PutGetStatDeleteRoundTrip", func(t *testing.T) { testRoundTrip(t, drv, newKey) })
	t.Run("GetMissingReturnsErrNotFound", func(t *testing.T) { testGetMissing(t, drv, newKey) })
	t.Run("StatMissingReturnsErrNotFound", func(t *testing.T) { testStatMissing(t, drv, newKey) })
	t.Run("DeleteMissingReturnsErrNotFound", func(t *testing.T) { testDeleteMissing(t, drv, newKey) })
	t.Run("LargeObjectStreams", func(t *testing.T) { testLargeObject(t, drv, newKey) })
	t.Run("ConcurrentPutDifferentKeys", func(t *testing.T) { testConcurrentPut(t, drv, newKey) })
	t.Run("RejectsTraversalAndSpecialKeys", func(t *testing.T) { testRejectsBadKeys(t, drv) })
}

func testRoundTrip(t *testing.T, drv storage.Driver, newKey func() string) {
	ctx := context.Background()
	key := newKey()
	want := []byte("hello attachra storage contract test")

	if err := drv.Put(ctx, key, bytes.NewReader(want), int64(len(want))); err != nil {
		t.Fatalf("Put() error = %v, want nil", err)
	}

	info, err := drv.Stat(ctx, key)
	if err != nil {
		t.Fatalf("Stat() error = %v, want nil", err)
	}
	if info.Size != int64(len(want)) {
		t.Errorf("Stat().Size = %d, want %d", info.Size, len(want))
	}

	rc, err := drv.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v, want nil", err)
	}
	got, err := io.ReadAll(rc)
	if closeErr := rc.Close(); closeErr != nil {
		t.Errorf("Close() error = %v", closeErr)
	}
	if err != nil {
		t.Fatalf("ReadAll(Get()) error = %v, want nil", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Get() content = %q, want %q", got, want)
	}

	if err := drv.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v, want nil", err)
	}

	if _, err := drv.Get(ctx, key); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get() after Delete() error = %v, want wrapping storage.ErrNotFound", err)
	}
}

func testGetMissing(t *testing.T, drv storage.Driver, newKey func() string) {
	_, err := drv.Get(context.Background(), newKey())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get() error = %v, want wrapping storage.ErrNotFound", err)
	}
}

func testStatMissing(t *testing.T, drv storage.Driver, newKey func() string) {
	_, err := drv.Stat(context.Background(), newKey())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Stat() error = %v, want wrapping storage.ErrNotFound", err)
	}
}

func testDeleteMissing(t *testing.T, drv storage.Driver, newKey func() string) {
	err := drv.Delete(context.Background(), newKey())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Delete() error = %v, want wrapping storage.ErrNotFound", err)
	}
}

func testLargeObject(t *testing.T, drv storage.Driver, newKey func() string) {
	if testing.Short() {
		t.Skip("skipping large object test in -short mode")
	}

	ctx := context.Background()
	key := newKey()

	const size = 8 * 1024 * 1024 // 8 MiB: large enough to catch whole-buffer reads
	h := sha256.New()
	pr, pw := io.Pipe()

	go func() {
		mw := io.MultiWriter(pw, h)
		_, err := io.CopyN(mw, rand.Reader, size)
		pw.CloseWithError(err) //nolint:errcheck // CloseWithError always succeeds for io.PipeWriter
	}()

	if err := drv.Put(ctx, key, pr, size); err != nil {
		t.Fatalf("Put() error = %v, want nil", err)
	}
	wantSum := h.Sum(nil)

	info, err := drv.Stat(ctx, key)
	if err != nil {
		t.Fatalf("Stat() error = %v, want nil", err)
	}
	if info.Size != size {
		t.Errorf("Stat().Size = %d, want %d", info.Size, size)
	}

	rc, err := drv.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v, want nil", err)
	}
	gotH := sha256.New()
	n, err := io.Copy(gotH, rc)
	closeErr := rc.Close()
	if err != nil {
		t.Fatalf("Copy(Get()) error = %v, want nil", err)
	}
	if closeErr != nil {
		t.Errorf("Close() error = %v", closeErr)
	}
	if n != size {
		t.Errorf("read %d bytes, want %d", n, size)
	}
	if !bytes.Equal(gotH.Sum(nil), wantSum) {
		t.Error("large object content hash mismatch")
	}

	if err := drv.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v, want nil", err)
	}
}

func testConcurrentPut(t *testing.T, drv storage.Driver, newKey func() string) {
	ctx := context.Background()
	const n = 16

	keys := make([]string, n)
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		keys[i] = newKey()
		payload := []byte(fmt.Sprintf("concurrent-object-%d", i))

		wg.Add(1)
		go func(i int, key string, payload []byte) {
			defer wg.Done()
			errs[i] = drv.Put(ctx, key, bytes.NewReader(payload), int64(len(payload)))
		}(i, keys[i], payload)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("Put() for key %d error = %v, want nil", i, err)
		}
	}

	for i, key := range keys {
		rc, err := drv.Get(ctx, key)
		if err != nil {
			t.Errorf("Get() for key %d error = %v, want nil", i, err)
			continue
		}
		got, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Errorf("ReadAll() for key %d error = %v", i, err)
			continue
		}
		want := fmt.Sprintf("concurrent-object-%d", i)
		if string(got) != want {
			t.Errorf("Get() for key %d = %q, want %q", i, got, want)
		}
		_ = drv.Delete(ctx, key)
	}
}

func testRejectsBadKeys(t *testing.T, drv storage.Driver) {
	ctx := context.Background()

	badKeys := []string{
		"",
		"../../etc/passwd",
		"../escape",
		"/absolute/path",
		"a/../../b",
		"a/./b/../../../c",
		"nul-byte\x00here",
	}

	for _, key := range badKeys {
		t.Run(fmt.Sprintf("key=%q", key), func(t *testing.T) {
			if err := drv.Put(ctx, key, bytes.NewReader(nil), 0); err == nil {
				t.Errorf("Put(%q) error = nil, want rejection", key)
			}
			if _, err := drv.Get(ctx, key); err == nil {
				t.Errorf("Get(%q) error = nil, want rejection", key)
			}
			if err := drv.Delete(ctx, key); err == nil {
				t.Errorf("Delete(%q) error = nil, want rejection", key)
			}
			if _, err := drv.Stat(ctx, key); err == nil {
				t.Errorf("Stat(%q) error = nil, want rejection", key)
			}
		})
	}
}
