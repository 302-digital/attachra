package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/302-digital/attachra/internal/core/policy"
)

// watchPolicyReload registers a SIGHUP handler that reloads store's
// policy file for as long as ctx is not done, logging the outcome of
// every reload attempt. It returns immediately; the handler runs in
// its own goroutine, owned by this function and terminated either
// when ctx is canceled or when the returned stop function is called.
//
// store may be nil, meaning no policy is configured (community
// passthrough mode, see config.PolicyConfig.Path); in that case
// watchPolicyReload still consumes and acknowledges SIGHUP (so the
// operator gets a clear log line instead of the signal being silently
// ignored) but never attempts a reload.
//
// The returned stop function is self-sufficient teardown: it cancels
// watchPolicyReload's own internal context (independently of ctx, the
// parent passed in) before waiting for the goroutine to exit, so it
// never blocks regardless of whether ctx itself has already been
// canceled by the time stop runs. This matters because callers using
// defer register stop functions in LIFO order: if watchPolicyReload's
// stop is deferred after the parent ctx's own cancel — as it is in
// run(), where SIGINT/SIGTERM's signal.NotifyContext cancel is
// deferred first — an early error return unwinds stop() BEFORE the
// parent cancel(), and a stop() that merely waited on the parent ctx
// would deadlock forever on that path. Self-canceling makes stop()
// correct regardless of defer order or whether the parent ctx is
// still live. It must be called exactly once, typically via defer.
func watchPolicyReload(ctx context.Context, store *policy.Store, logger *slog.Logger) (stop func()) {
	loopCtx, cancel := context.WithCancel(ctx)

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runPolicyReloadLoop(loopCtx, hupCh, store, logger)
	}()

	return func() {
		signal.Stop(hupCh)
		cancel()
		wg.Wait()
	}
}

// runPolicyReloadLoop is the body of the SIGHUP watcher goroutine,
// split out from watchPolicyReload so it can be driven directly from
// a test-owned channel instead of a real OS signal (T-4.2.1
// acceptance criterion: "SIGHUP handler unit-testable via a
// channel").
func runPolicyReloadLoop(ctx context.Context, hupCh <-chan os.Signal, store *policy.Store, logger *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-hupCh:
			handleSIGHUP(store, logger)
		}
	}
}

// handleSIGHUP performs a single reload attempt in response to a
// received SIGHUP, logging a structured summary either way:
//   - success: policy name, rule count and any warnings;
//   - failure: the error, plus an explicit note that the previous
//     policy is still in effect (Store.Reload already guarantees this
//     — the log line just makes it visible to the operator).
//
// If store is nil (no policy configured), SIGHUP is acknowledged with
// an info log but no reload is attempted.
func handleSIGHUP(store *policy.Store, logger *slog.Logger) {
	if store == nil {
		logger.Info("received SIGHUP, no policy configured — nothing to reload")
		return
	}

	logger.Info("received SIGHUP, reloading policy", "path", store.Path())

	p, warnings, err := store.Reload()
	if err != nil {
		logger.Error("policy reload failed, keeping previous policy",
			"path", store.Path(),
			"error", err,
		)
		return
	}

	logger.Info("policy reloaded",
		"path", store.Path(),
		"name", p.Name,
		"rules", len(p.Rules),
		"warnings", len(warnings),
	)
	for _, w := range warnings {
		logger.Warn("policy reload warning", "path", store.Path(), "warning", w)
	}
}
