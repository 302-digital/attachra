package http

import (
	"sync"
	"testing"
	"time"
)

func TestTokenBucketAllowsUpToBurstThenBlocks(t *testing.T) {
	b := newTokenBucket(60, 3) // 1 token/sec refill, burst 3.
	fixedNow := time.Now()
	b.now = func() time.Time { return fixedNow }

	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Fatalf("allow() call %d = false, want true (within burst)", i+1)
		}
	}
	if b.allow() {
		t.Fatal("allow() after burst exhausted = true, want false")
	}
}

func TestTokenBucketRefillsOverTime(t *testing.T) {
	b := newTokenBucket(60, 1) // 1 token/sec, burst 1.
	fixedNow := time.Now()
	b.now = func() time.Time { return fixedNow }

	if !b.allow() {
		t.Fatal("first allow() = false, want true")
	}
	if b.allow() {
		t.Fatal("second immediate allow() = true, want false (bucket empty)")
	}

	fixedNow = fixedNow.Add(1100 * time.Millisecond)
	if !b.allow() {
		t.Fatal("allow() after refill window = false, want true")
	}
}

func TestTokenBucketDisabledAlwaysAllows(t *testing.T) {
	b := newTokenBucket(0, 0)
	for i := 0; i < 100; i++ {
		if !b.allow() {
			t.Fatalf("allow() call %d on disabled bucket = false, want true", i)
		}
	}
}

// TestTokenBucketConcurrentNeverExceedsBurst races many goroutines
// against a small bucket and asserts the number of successful allows
// never exceeds the configured burst — the mutex-guarded refill/debit
// must not let concurrent callers double-spend the same token
// (CLAUDE.md rule on racing critical counters; run with -race).
func TestTokenBucketConcurrentNeverExceedsBurst(t *testing.T) {
	const burst = 5
	b := newTokenBucket(0, burst) // rate 0 disables refill: exactly `burst` allows total, ever.
	b.ratePerSecond = 0.0000001   // effectively no refill within the test's duration, but nonzero so the disabled-shortcut path isn't taken.

	const attempts = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.allow() {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes > burst {
		t.Errorf("successes = %d, want <= %d (burst must never be exceeded under concurrency)", successes, burst)
	}
}

func TestPerIPLimiterIsolatesByIP(t *testing.T) {
	l := newPerIPLimiter(60, 1, 0)

	if !l.allowRequest("1.1.1.1") {
		t.Fatal("first request from 1.1.1.1 = false, want true")
	}
	if l.allowRequest("1.1.1.1") {
		t.Fatal("second immediate request from 1.1.1.1 = true, want false")
	}
	// A different IP must have its own independent budget.
	if !l.allowRequest("2.2.2.2") {
		t.Fatal("first request from 2.2.2.2 = false, want true (independent per-IP budget)")
	}
}

func TestPerIPLimiterNotFoundBudgetSeparateFromRequestBudget(t *testing.T) {
	l := newPerIPLimiter(1000, 1000, 1) // generous request budget, tight not-found budget.

	if !l.allowNotFound("3.3.3.3") {
		t.Fatal("first not-found from 3.3.3.3 = false, want true")
	}
	if l.allowNotFound("3.3.3.3") {
		t.Fatal("second immediate not-found from 3.3.3.3 = true, want false (tarpit budget exhausted)")
	}
	// The general request budget is untouched by allowNotFound calls.
	if !l.allowRequest("3.3.3.3") {
		t.Fatal("allowRequest after exhausting not-found budget = false, want true")
	}
}
