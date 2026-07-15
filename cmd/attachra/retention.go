package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/302-digital/attachra/internal/core/retention"
)

// watchRetentionCleanup starts a ticker-driven loop that runs
// sweeper.Sweep once every interval, for as long as ctx is not done,
// logging the outcome of every pass. It returns immediately; the loop
// runs in its own goroutine, owned by this function and terminated
// either when ctx is canceled or when the returned stop function is
// called.
//
// sweeper may be nil, meaning the retention cleanup job is disabled
// (config.RetentionConfig.Enabled == false, see run() in main.go); in
// that case watchRetentionCleanup starts no goroutine at all and
// returns a no-op stop function, mirroring watchPolicyReload's own
// handling of "nothing configured, nothing to run".
//
// The returned stop function is self-sufficient teardown, exactly like
// watchPolicyReload's: it cancels its own derived context before
// waiting for the goroutine to exit, so it never blocks regardless of
// whether ctx itself has already been canceled by the time stop runs
// (see watchPolicyReload's doc comment for the full defer-ordering
// rationale this mirrors). It must be called exactly once, typically
// via defer.
func watchRetentionCleanup(ctx context.Context, sweeper *retention.Sweeper, interval time.Duration, logger *slog.Logger) (stop func()) {
	if sweeper == nil {
		return func() {}
	}

	loopCtx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runRetentionCleanupLoop(loopCtx, sweeper, interval, logger)
	}()

	return func() {
		cancel()
		wg.Wait()
	}
}

// runRetentionCleanupLoop is the body of the retention sweep ticker
// goroutine, split out from watchRetentionCleanup so it is directly
// unit-testable against a short interval instead of a real, much
// longer production interval (matching runPolicyReloadLoop's own
// precedent of separating the loop body from its production-wiring
// wrapper).
func runRetentionCleanupLoop(ctx context.Context, sweeper *retention.Sweeper, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runRetentionSweepOnce(ctx, sweeper, logger)
		}
	}
}

// runRetentionSweepOnce performs a single retention sweep pass,
// logging a structured summary either way. A failed pass (a store
// outage, per retention.Sweeper.Sweep's doc comment) is logged and
// simply awaits the next tick — there is no separate retry/backoff
// path, since the next scheduled tick already serves that purpose.
func runRetentionSweepOnce(ctx context.Context, sweeper *retention.Sweeper, logger *slog.Logger) {
	res, err := sweeper.Sweep(ctx)
	if err != nil {
		logger.Error("retention sweep failed", "error", err.Error())
		return
	}
	logger.Info("retention sweep completed",
		"deleted", res.Deleted,
		"held_skipped", res.HeldSkipped,
		"failed", res.Failed,
		"expired_links", res.ExpiredLinks,
	)
}
