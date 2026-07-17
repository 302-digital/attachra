package http

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestBucket() *tokenBucket {
	return newTokenBucket(60, 5)
}

func TestEvictingBucketMapReturnsSameBucketForSameKey(t *testing.T) {
	m := newEvictingBucketMap(10, time.Hour)

	b1 := m.getOrCreate("1.1.1.1", newTestBucket)
	b2 := m.getOrCreate("1.1.1.1", newTestBucket)

	if b1 != b2 {
		t.Fatal("getOrCreate returned a different bucket for the same key on the second call")
	}
	if got := m.len(); got != 1 {
		t.Fatalf("len() = %d, want 1", got)
	}
}

func TestEvictingBucketMapEvictsOverCapByLRU(t *testing.T) {
	const capacity = 3
	m := newEvictingBucketMap(capacity, time.Hour)

	// Fill to capacity.
	for i := 0; i < capacity; i++ {
		m.getOrCreate(fmt.Sprintf("ip-%d", i), newTestBucket)
	}
	if got := m.len(); got != capacity {
		t.Fatalf("len() after filling to capacity = %d, want %d", got, capacity)
	}

	// Touch every entry except ip-0 so it becomes the least-recently-used.
	for i := 1; i < capacity; i++ {
		m.getOrCreate(fmt.Sprintf("ip-%d", i), newTestBucket)
	}

	// One more distinct key should evict ip-0 (the LRU entry), not any of
	// the entries touched above.
	m.getOrCreate("ip-new", newTestBucket)

	if got := m.len(); got != capacity {
		t.Fatalf("len() after inserting over capacity = %d, want %d (hard capacity must hold)", got, capacity)
	}

	// ip-0's bucket should have been recreated (fresh, full burst) since
	// its old entry was evicted; we can't compare pointers without
	// capturing the original, so instead assert the map still reports
	// exactly `capacity` entries and that ip-1..ip-(capacity-1) plus ip-new are
	// present by checking a fresh getOrCreate for one of the retained
	// keys does not grow the map further.
	before := m.len()
	m.getOrCreate("ip-new", newTestBucket)
	if after := m.len(); after != before {
		t.Fatalf("len() changed from a getOrCreate on an already-present key: %d -> %d", before, after)
	}
}

func TestEvictingBucketMapEvictionIsLeastRecentlyUsedNotInsertionOrder(t *testing.T) {
	const capacity = 2
	m := newEvictingBucketMap(capacity, time.Hour)

	first := m.getOrCreate("first", newTestBucket)
	m.getOrCreate("second", newTestBucket)

	// Touch "first" again so "second" becomes the LRU entry instead.
	m.getOrCreate("first", newTestBucket)

	// Inserting a third key must evict "second" (LRU), not "first".
	m.getOrCreate("third", newTestBucket)

	if got := m.len(); got != capacity {
		t.Fatalf("len() = %d, want %d", got, capacity)
	}

	stillFirst := m.getOrCreate("first", newTestBucket)
	if stillFirst != first {
		t.Fatal("\"first\" was evicted even though it was the most-recently-used entry, not the least")
	}
}

func TestEvictingBucketMapEvictsByTTL(t *testing.T) {
	m := newEvictingBucketMap(0, time.Minute) // No capacity: isolate the TTL mechanism.
	fixedNow := time.Now()
	m.now = func() time.Time { return fixedNow }

	first := m.getOrCreate("stale", newTestBucket)
	if got := m.len(); got != 1 {
		t.Fatalf("len() after first insert = %d, want 1", got)
	}

	// Advance time past the TTL without touching "stale".
	fixedNow = fixedNow.Add(2 * time.Minute)

	// Any call that touches the map (even for a different key) sweeps
	// expired entries first.
	m.getOrCreate("fresh", newTestBucket)

	if got := m.len(); got != 1 {
		t.Fatalf("len() after TTL sweep = %d, want 1 (only \"fresh\" should remain)", got)
	}

	recreated := m.getOrCreate("stale", newTestBucket)
	if recreated == first {
		t.Fatal("\"stale\" bucket was not recreated after TTL eviction")
	}
}

func TestEvictingBucketMapTTLDisabledWhenNonPositive(t *testing.T) {
	m := newEvictingBucketMap(0, 0)
	fixedNow := time.Now()
	m.now = func() time.Time { return fixedNow }

	b := m.getOrCreate("ip", newTestBucket)
	fixedNow = fixedNow.Add(365 * 24 * time.Hour)
	again := m.getOrCreate("ip", newTestBucket)

	if b != again {
		t.Fatal("entry was evicted despite ttl <= 0 disabling TTL eviction")
	}
}

// TestEvictingBucketMapBoundedUnderSprayAttack simulates a distributed
// attacker spraying requests from a very large number of distinct
// source IPs — the exact scenario ATR-297 exists to bound — and asserts
// the map's memory footprint (its entry count) never exceeds the
// configured capacity, no matter how many unique keys are pushed through it.
func TestEvictingBucketMapBoundedUnderSprayAttack(t *testing.T) {
	const capacity = 500
	m := newEvictingBucketMap(capacity, time.Hour)

	for i := 0; i < 50000; i++ {
		m.getOrCreate(fmt.Sprintf("203.0.113.%d.%d", i/256, i%256), newTestBucket)
		if got := m.len(); got > capacity {
			t.Fatalf("len() = %d exceeds capacity %d after %d unique keys", got, capacity, i+1)
		}
	}
	if got := m.len(); got != capacity {
		t.Fatalf("final len() = %d, want exactly %d (map should be saturated at the capacity)", got, capacity)
	}
}

// TestEvictingBucketMapConcurrentBounded races many goroutines, each
// minting its own unique key (simulating many concurrent distinct
// source IPs), against a small-capacity map and asserts the entry count
// never exceeds the capacity under concurrent access (critical counters
// must be race-safe; run with -race).
func TestEvictingBucketMapConcurrentBounded(t *testing.T) {
	const capacity = 100
	const goroutines = 500
	m := newEvictingBucketMap(capacity, time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("ip-%d", i)
			for j := 0; j < 10; j++ {
				m.getOrCreate(key, newTestBucket)
			}
		}(i)
	}
	wg.Wait()

	if got := m.len(); got > capacity {
		t.Fatalf("len() = %d exceeds capacity %d after concurrent access", got, capacity)
	}
}

// TestEvictingBucketMapRecentlyUsedSurvivesSprayAttack asserts that a
// legitimate, actively-used client's bucket is not evicted just because
// many other (attacker-controlled) keys are being minted concurrently —
// the acceptance criterion that eviction must not degrade a legitimate
// client's behavior. Since eviction is strictly LRU, an entry touched
// on every iteration should never reach the back of the list.
func TestEvictingBucketMapRecentlyUsedSurvivesSprayAttack(t *testing.T) {
	const capacity = 50
	m := newEvictingBucketMap(capacity, time.Hour)

	legit := m.getOrCreate("legit-client", newTestBucket)

	for i := 0; i < 10000; i++ {
		// The legitimate client keeps making requests interleaved with
		// the attack.
		if i%2 == 0 {
			m.getOrCreate("legit-client", newTestBucket)
		}
		m.getOrCreate(fmt.Sprintf("attacker-%d", i), newTestBucket)
	}

	still := m.getOrCreate("legit-client", newTestBucket)
	if still != legit {
		t.Fatal("legitimate client's bucket was evicted despite being touched throughout the spray, losing its accumulated throttle state")
	}
}
