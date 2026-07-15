package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/policy"
)

func writeMainTestPolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

const mainTestValidPolicy = `
version: 1
name: "Policy v1"
rules: []
default:
  action: pass
`

const mainTestValidPolicyV2 = `
version: 1
name: "Policy v2"
rules:
  - name: "block executables"
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
      reason: "no executables"
default:
  action: pass
`

const mainTestInvalidPolicy = `
version: 1
name: "Invalid"
rules:
  - name: "no default"
    then:
      action: pass
`

// TestHandleSIGHUP_Success exercises a single successful reload
// through handleSIGHUP directly (the unit tested via a channel, per
// T-4.2.1's acceptance criteria, is runPolicyReloadLoop below; this
// covers the log-message contract of a bare success).
func TestHandleSIGHUP_Success(t *testing.T) {
	path := writeMainTestPolicy(t, mainTestValidPolicy)
	store, err := policy.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	if err := os.WriteFile(path, []byte(mainTestValidPolicyV2), 0o600); err != nil {
		t.Fatalf("rewrite policy file: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	handleSIGHUP(store, logger)

	if store.Current().Name != "Policy v2" {
		t.Errorf("Current().Name = %q, want %q after successful reload", store.Current().Name, "Policy v2")
	}

	out := buf.String()
	for _, want := range []string{"policy reloaded", "name=\"Policy v2\"", "rules=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output = %q, want substring %q", out, want)
		}
	}
}

// TestHandleSIGHUP_Failure_KeepsPreviousPolicy asserts the log
// message on a failed reload explicitly says the previous policy is
// kept, and that the store's Current() indeed didn't change.
func TestHandleSIGHUP_Failure_KeepsPreviousPolicy(t *testing.T) {
	path := writeMainTestPolicy(t, mainTestValidPolicy)
	store, err := policy.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	if err := os.WriteFile(path, []byte(mainTestInvalidPolicy), 0o600); err != nil {
		t.Fatalf("rewrite policy file: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	handleSIGHUP(store, logger)

	if store.Current().Name != "Policy v1" {
		t.Errorf("Current().Name = %q, want unchanged %q after failed reload", store.Current().Name, "Policy v1")
	}

	out := buf.String()
	for _, want := range []string{"policy reload failed", "keeping previous policy"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output = %q, want substring %q", out, want)
		}
	}
}

// TestHandleSIGHUP_NilStore_LogsWithoutPanic covers the passthrough
// (no policy.path configured) case.
func TestHandleSIGHUP_NilStore_LogsWithoutPanic(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	handleSIGHUP(nil, logger)

	if !strings.Contains(buf.String(), "no policy configured") {
		t.Errorf("log output = %q, want a note that no policy is configured", buf.String())
	}
}

// TestRunPolicyReloadLoop_ChannelDriven is the T-4.2.1 acceptance
// criterion: the SIGHUP handler must be unit-testable by driving it
// through a channel instead of a real OS signal. It sends a synthetic
// os.Signal down a test-owned channel and asserts a reload happened,
// then cancels the context and confirms the loop returns (no
// goroutine leak).
func TestRunPolicyReloadLoop_ChannelDriven(t *testing.T) {
	path := writeMainTestPolicy(t, mainTestValidPolicy)
	store, err := policy.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	if err := os.WriteFile(path, []byte(mainTestValidPolicyV2), 0o600); err != nil {
		t.Fatalf("rewrite policy file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	hupCh := make(chan os.Signal, 1)

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	done := make(chan struct{})
	go func() {
		defer close(done)
		runPolicyReloadLoop(ctx, hupCh, store, logger)
	}()

	hupCh <- syntheticSignal{}

	waitForCondition(t, func() bool {
		return store.Current().Name == "Policy v2"
	})

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runPolicyReloadLoop did not return after context cancellation — goroutine leak")
	}
}

// TestWatchPolicyReload_StopTerminatesGoroutine verifies the
// production wiring: watchPolicyReload's returned stop function
// deterministically waits for its goroutine to exit, so callers (e.g.
// run() via defer) never leave a dangling goroutine (CLAUDE.md
// invariant: "every goroutine has an owner and a way to terminate").
// The parent ctx is canceled first here (the SIGINT/SIGTERM shutdown
// path); TestWatchPolicyReload_StopTerminatesGoroutine_ParentCtxStillLive
// below covers the other order, where ctx is NOT yet canceled.
func TestWatchPolicyReload_StopTerminatesGoroutine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	stop := watchPolicyReload(ctx, nil, logger)

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

// TestWatchPolicyReload_StopTerminatesGoroutine_ParentCtxStillLive
// covers the early error-exit path in run(): SIGINT/SIGTERM's
// signal.NotifyContext cancel is deferred BEFORE
// watchPolicyReload's stop (see run() in main.go), so on an early
// error return (e.g. milterServer.ListenAndServe fails to bind before
// the outer defer stop() runs) stopPolicyReload's stop function
// unwinds first, with the parent ctx still live (not yet canceled).
//
// This test never cancels the parent ctx at all, simulating exactly
// that ordering, and asserts stop() still returns promptly — i.e.
// stop() must be self-sufficient teardown, not merely wait on the
// parent ctx's own cancellation. Before the fix (stop() relying on
// the parent ctx instead of canceling its own derived context), this
// scenario deadlocked forever.
func TestWatchPolicyReload_StopTerminatesGoroutine_ParentCtxStillLive(t *testing.T) {
	ctx := context.Background() // deliberately never canceled

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	stop := watchPolicyReload(ctx, nil, logger)

	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return while the parent ctx was still live — this is the reported deadlock on the early error-exit path")
	}
}

// syntheticSignal is a minimal os.Signal implementation for feeding a
// synthetic value through a real os.Signal channel in tests, without
// depending on actually being able to send ourselves a SIGHUP in the
// test process.
type syntheticSignal struct{}

func (syntheticSignal) String() string { return "synthetic" }
func (syntheticSignal) Signal()        {}

// waitForCondition polls cond until it returns true or a timeout
// elapses, failing the test on timeout. Used instead of a fixed sleep
// to avoid flakiness while keeping the test fast in the common case.
func waitForCondition(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
