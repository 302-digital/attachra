package http

import (
	"fmt"
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
// (critical counters must be race-safe; run with -race).
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

// TestPerIPLimiterMemoryBoundedUnderSprayAttack asserts ATR-297's core
// property end to end through perIPLimiter's public API: a distributed
// attacker spraying requests from a very large number of distinct
// source IPs cannot grow either of its internal per-IP maps beyond the
// configured eviction cap, regardless of how many unique IPs it uses.
func TestPerIPLimiterMemoryBoundedUnderSprayAttack(t *testing.T) {
	const evictionCap = 200
	l := newPerIPLimiterWithBounds(60, 10, 30, evictionCap, time.Hour)

	for i := 0; i < 20000; i++ {
		ip := fmt.Sprintf("198.51.100.%d.%d", i/256, i%256)
		l.allowRequest(ip)
		l.allowNotFound(ip)
	}

	if got := l.requests.len(); got > evictionCap {
		t.Errorf("requests map len() = %d, exceeds eviction cap %d", got, evictionCap)
	}
	if got := l.notFounds.len(); got > evictionCap {
		t.Errorf("notFounds map len() = %d, exceeds eviction cap %d", got, evictionCap)
	}
}

// TestPerIPLimiterZeroBoundsFallBackToPackageDefaults asserts
// newPerIPLimiterWithBounds never produces an unbounded map by
// accident: a zero-value RateLimitConfig (EvictionMaxEntries/
// EvictionTTL both unset, e.g. a caller that forgot to normalize, or
// direct construction in a test) must still get the package defaults,
// not "no eviction at all".
func TestPerIPLimiterZeroBoundsFallBackToPackageDefaults(t *testing.T) {
	l := newPerIPLimiterWithBounds(60, 10, 30, 0, 0)

	if l.requests.maxEntries != defaultBucketMapMaxEntries {
		t.Errorf("requests.maxEntries = %d, want default %d", l.requests.maxEntries, defaultBucketMapMaxEntries)
	}
	if l.requests.ttl != defaultBucketMapTTL {
		t.Errorf("requests.ttl = %v, want default %v", l.requests.ttl, defaultBucketMapTTL)
	}
	if l.notFounds.maxEntries != defaultBucketMapMaxEntries {
		t.Errorf("notFounds.maxEntries = %d, want default %d", l.notFounds.maxEntries, defaultBucketMapMaxEntries)
	}
}

// TestPerIPLimiterEvictionDoesNotDegradeReturningLegitimateClient
// asserts the acceptance criterion that a bucket restored after
// eviction behaves correctly rather than letting an attacker bypass the
// throttle by forcing a reset: once evicted (simulated here via a tiny
// cap and a burst of other IPs), a returning client gets a fresh bucket
// that itself immediately enforces the configured burst — it is not
// left permanently unthrottled or in some inconsistent state.
func TestPerIPLimiterEvictionDoesNotDegradeReturningLegitimateClient(t *testing.T) {
	const evictionCap = 1
	l := newPerIPLimiterWithBounds(60, 2, 0, evictionCap, time.Hour)

	if !l.allowRequest("legit") {
		t.Fatal("first request from legit = false, want true")
	}

	// Force eviction of "legit"'s entry by pushing a different key
	// through the size-1 map.
	l.allowRequest("attacker")

	// "legit" now gets a fresh bucket (starting full at burst=2), which
	// must still enforce its own burst correctly: 2 allowed, then
	// throttled.
	if !l.allowRequest("legit") {
		t.Fatal("first request after eviction = false, want true (fresh bucket starts full)")
	}
	if !l.allowRequest("legit") {
		t.Fatal("second request after eviction = false, want true (within fresh burst)")
	}
	if l.allowRequest("legit") {
		t.Fatal("third immediate request after eviction = true, want false (fresh bucket still enforces its burst)")
	}
}
