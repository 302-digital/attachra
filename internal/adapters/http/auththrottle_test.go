package http

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAuthThrottleAllowsUpToBurstThenBlocks(t *testing.T) {
	a := newAuthThrottle(60, 2)

	if !a.failAllowed("9.9.9.9") {
		t.Fatal("first failure = false, want true")
	}
	if !a.failAllowed("9.9.9.9") {
		t.Fatal("second failure = false, want true (within burst)")
	}
	if a.failAllowed("9.9.9.9") {
		t.Fatal("third immediate failure = true, want false (burst exhausted)")
	}
}

func TestAuthThrottleIsolatesByIP(t *testing.T) {
	a := newAuthThrottle(60, 1)

	if !a.failAllowed("1.2.3.4") {
		t.Fatal("first failure from 1.2.3.4 = false, want true")
	}
	if a.failAllowed("1.2.3.4") {
		t.Fatal("second immediate failure from 1.2.3.4 = true, want false")
	}
	if !a.failAllowed("5.6.7.8") {
		t.Fatal("first failure from 5.6.7.8 = false, want true (independent budget)")
	}
}

func TestAuthThrottleDisabledAlwaysAllows(t *testing.T) {
	a := newAuthThrottle(0, 0)
	for i := 0; i < 100; i++ {
		if !a.failAllowed("1.1.1.1") {
			t.Fatalf("failAllowed call %d on disabled throttle = false, want true", i)
		}
	}
}

// TestAuthThrottleMemoryBoundedUnderDistributedSweep asserts ATR-297's
// property for the auth-failure throttle specifically: a brute-force
// sweep distributed across a very large number of source IPs cannot
// grow the throttle's internal map beyond the configured eviction cap.
func TestAuthThrottleMemoryBoundedUnderDistributedSweep(t *testing.T) {
	const evictionCap = 300
	a := newAuthThrottleWithBounds(10, 10, evictionCap, time.Hour)

	for i := 0; i < 30000; i++ {
		ip := fmt.Sprintf("192.0.2.%d.%d", i/256, i%256)
		a.failAllowed(ip)
	}

	if got := a.buckets.len(); got > evictionCap {
		t.Errorf("buckets map len() = %d, exceeds eviction cap %d", got, evictionCap)
	}
}

func TestAuthThrottleZeroBoundsFallBackToPackageDefaults(t *testing.T) {
	a := newAuthThrottleWithBounds(10, 10, 0, 0)

	if a.buckets.maxEntries != defaultBucketMapMaxEntries {
		t.Errorf("buckets.maxEntries = %d, want default %d", a.buckets.maxEntries, defaultBucketMapMaxEntries)
	}
	if a.buckets.ttl != defaultBucketMapTTL {
		t.Errorf("buckets.ttl = %v, want default %v", a.buckets.ttl, defaultBucketMapTTL)
	}
}

// TestAuthThrottleConcurrentNeverExceedsCapOrBurst races many
// goroutines, each its own simulated source IP, against a
// small-capacity throttle and asserts both that the map never exceeds
// its cap and that no single IP's successes ever exceed its burst
// (critical counters must be race-safe; run with -race).
func TestAuthThrottleConcurrentNeverExceedsCapOrBurst(t *testing.T) {
	const evictionCap = 50
	const burst = 3
	// ratePerMinute=1 refills far too slowly to add a token within this
	// test's sub-millisecond duration, so it behaves like the disabled
	// (ratePerMinute<=0) case would if that didn't also skip the
	// eviction-map bookkeeping entirely — this exercises the real path.
	a := newAuthThrottleWithBounds(1, burst, evictionCap, time.Hour)

	const sameIP = "203.0.113.7"
	const goroutines = 30
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a.failAllowed(sameIP) {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes > burst {
		t.Errorf("successes for a single IP = %d, want <= burst %d", successes, burst)
	}
	if got := a.buckets.len(); got > evictionCap {
		t.Errorf("buckets map len() = %d, exceeds eviction cap %d", got, evictionCap)
	}
}
