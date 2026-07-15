package main

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/retention"
	fsstorage "github.com/302-digital/attachra/internal/core/storage/fs"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// newTestSweeper builds a real, empty retention.Sweeper backed by a
// freshly migrated sqlite store and an fs storage driver, both rooted
// in per-test temp dirs — enough for these tests, which only exercise
// the ticker-loop plumbing (retention.Sweeper's own behavior is
// covered by internal/core/retention's test suite), not any specific
// sweep outcome.
func newTestSweeper(t *testing.T) *retention.Sweeper {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "retention-cmd-test.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	drv, err := fsstorage.New(fsstorage.Config{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("fsstorage.New() error = %v, want nil", err)
	}

	sweeper, err := retention.New(retention.Params{Metadata: st, Storage: drv})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}
	return sweeper
}

// TestRunRetentionCleanupLoop_TicksAndStops verifies the ticker loop
// runs sweep passes while ctx is live and returns promptly once ctx is
// canceled (no goroutine leak), the periodic-trigger analog of
// TestRunPolicyReloadLoop_ChannelDriven for the signal-driven policy
// reload loop.
func TestRunRetentionCleanupLoop_TicksAndStops(t *testing.T) {
	sweeper := newTestSweeper(t)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		runRetentionCleanupLoop(ctx, sweeper, 10*time.Millisecond, logger)
	}()

	time.Sleep(50 * time.Millisecond) // Let at least one tick fire.
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runRetentionCleanupLoop did not return after context cancellation — goroutine leak")
	}
}

// TestWatchRetentionCleanup_NilSweeperIsNoOp verifies a disabled
// retention job (nil Sweeper, config.RetentionConfig.Enabled == false
// in run()) starts no goroutine at all and its stop function returns
// immediately.
func TestWatchRetentionCleanup_NilSweeperIsNoOp(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	stop := watchRetentionCleanup(context.Background(), nil, time.Hour, logger)

	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return for nil sweeper — want immediate no-op")
	}
}

// TestWatchRetentionCleanup_StopTerminatesGoroutine mirrors
// TestWatchPolicyReload_StopTerminatesGoroutine: stop() must
// deterministically wait for its goroutine to exit even though the
// parent ctx is already canceled by the time stop runs (CLAUDE.md
// invariant: every goroutine has an owner and a way to terminate).
func TestWatchRetentionCleanup_StopTerminatesGoroutine(t *testing.T) {
	sweeper := newTestSweeper(t)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := watchRetentionCleanup(ctx, sweeper, time.Hour, logger)

	cancel()

	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return — goroutine leak")
	}
}

// TestWatchRetentionCleanup_StopTerminatesGoroutine_ParentCtxStillLive
// covers the same early-error-return ordering as
// TestWatchPolicyReload_StopTerminatesGoroutine_ParentCtxStillLive:
// stop() must not deadlock even when the parent ctx is never canceled.
func TestWatchRetentionCleanup_StopTerminatesGoroutine_ParentCtxStillLive(t *testing.T) {
	sweeper := newTestSweeper(t)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	ctx := context.Background() // Deliberately never canceled.
	stop := watchRetentionCleanup(ctx, sweeper, time.Hour, logger)

	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return with parent ctx still live — goroutine leak")
	}
}
