package http

import (
	"container/list"
	"sync"
	"time"
)

// Default bounds for the per-IP bucket maps behind perIPLimiter and
// authThrottle (ATR-297, security review ATR-196 non-blocking #1). A
// distributed attacker spraying requests across many source IPs
// (trivial over IPv6, where a single attacker can claim a huge range of
// addresses from one /64 subnet) previously grew these maps by one
// *tokenBucket per unique IP, for the lifetime of the process, without
// any eviction. defaultBucketMapMaxEntries gives a hard ceiling on the
// number of entries a map may hold, independent of how fast the attack
// mints new IPs; defaultBucketMapTTL evicts an entry once it has been
// idle long enough that a real client's bucket would have refilled to
// full through ordinary token-bucket replenishment anyway (see
// evictingBucketMap's doc comment for why that makes TTL eviction safe
// against throttle-reset abuse).
//
// 20000 entries per map costs on the order of a few MiB (a
// container/list element plus a small struct and a string map key per
// entry) — negligible next to the process's other memory use, while
// comfortably covering realistic legitimate concurrent-client counts
// for a self-hosted deployment.
const (
	defaultBucketMapMaxEntries = 20000
	defaultBucketMapTTL        = 30 * time.Minute
)

// evictingBucketMap is a bounded, thread-safe map of *tokenBucket keyed
// by client IP (ATR-297). It backs perIPLimiter's two per-IP maps and
// authThrottle's map, replacing the plain, never-evicted
// map[string]*tokenBucket those used before.
//
// Entries are ordered by recency of access — an in-process LRU, built
// on the standard library's container/list rather than a third-party
// dependency (mirroring this package's existing dependency-free
// tokenBucket). Two independent eviction checks both walk from the back
// of that list, which by construction is always where the
// least-recently-touched entries are:
//
//   - a hard cap: once the map holds more than maxEntries, the
//     least-recently-used entries are evicted until it does not, giving
//     a strict upper bound on memory regardless of how many distinct
//     IPs an attacker sprays requests from;
//   - a TTL: an entry idle longer than ttl is evicted lazily, on the
//     next call that touches the map, keeping steady-state memory well
//     under the cap in the common case rather than only bounding the
//     worst case.
//
// Both checks run inline on the request path, inside getOrCreate, under
// the same lock that already serializes access to the map. There is no
// background sweep goroutine to own or cancel — the
// every-goroutine-has-an-owner rule is satisfied trivially, since this
// type spawns none.
//
// A client whose entry is evicted and later returns gets a fresh bucket
// starting full, the same state a brand-new client gets. This is not a
// throttle-reset bypass: defaultBucketMapTTL is chosen so that by the
// time an entry becomes TTL-eligible for eviction, an un-evicted bucket
// for any of this package's configured rates would already have
// refilled to full through ordinary replenishment — eviction never
// hands a returning client anything it would not already have gotten by
// simply waiting. Eviction under capacity pressure (the LRU cap, rather
// than TTL) only ever removes the least-recently-active entries, i.e.
// exactly the ones an attacker spraying many short-lived IPs is least
// likely to still be using; it never evicts a busy legitimate client's
// entry to make room, since that entry keeps moving back to the front
// on every request.
//
// Safe for concurrent use by multiple goroutines.
type evictingBucketMap struct {
	mu sync.Mutex

	maxEntries int
	ttl        time.Duration

	order   *list.List               // Front = most recently used, back = least.
	entries map[string]*list.Element // key -> element wrapping *bucketMapEntry

	now func() time.Time // overridable for tests; nil uses time.Now.
}

// bucketMapEntry is the value held by each element of evictingBucketMap.order.
type bucketMapEntry struct {
	key        string
	bucket     *tokenBucket
	lastAccess time.Time
}

// newEvictingBucketMap returns an empty evictingBucketMap bounded by
// maxEntries and ttl. maxEntries <= 0 disables the hard cap; ttl <= 0
// disables TTL eviction. Callers in this package always pass positive
// values (the package-level defaults or an operator override); passing
// both as <= 0 is allowed for tests that want to isolate one eviction
// mechanism from the other, but defeats ATR-297's memory bound and must
// not be reachable from production configuration.
func newEvictingBucketMap(maxEntries int, ttl time.Duration) *evictingBucketMap {
	return &evictingBucketMap{
		maxEntries: maxEntries,
		ttl:        ttl,
		order:      list.New(),
		entries:    make(map[string]*list.Element),
	}
}

func (m *evictingBucketMap) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// getOrCreate returns the bucket for key, creating it via newBucket if
// this is the first request from key or its previous entry has since
// been evicted. It touches key's recency (moving it to the front of the
// LRU order) and opportunistically evicts stale/excess entries — from
// any key, not just this one — before returning.
func (m *evictingBucketMap) getOrCreate(key string, newBucket func() *tokenBucket) *tokenBucket {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()
	m.evictExpiredLocked(now)

	if el, ok := m.entries[key]; ok {
		m.order.MoveToFront(el)
		be := el.Value.(*bucketMapEntry)
		be.lastAccess = now
		return be.bucket
	}

	b := newBucket()
	el := m.order.PushFront(&bucketMapEntry{key: key, bucket: b, lastAccess: now})
	m.entries[key] = el

	m.evictOverCapLocked()

	return b
}

// evictExpiredLocked removes every entry idle longer than m.ttl,
// walking from the back of the LRU order (oldest lastAccess first) and
// stopping at the first entry that is still fresh — by the LRU
// invariant, everything in front of it is fresher still, so no entry
// past that point can also be expired. Callers must hold m.mu.
func (m *evictingBucketMap) evictExpiredLocked(now time.Time) {
	if m.ttl <= 0 {
		return
	}
	for {
		back := m.order.Back()
		if back == nil {
			return
		}
		be := back.Value.(*bucketMapEntry)
		if now.Sub(be.lastAccess) < m.ttl {
			return
		}
		m.order.Remove(back)
		delete(m.entries, be.key)
	}
}

// evictOverCapLocked removes least-recently-used entries until the map
// holds at most m.maxEntries, giving a hard ceiling on memory regardless
// of how fast new keys arrive. Callers must hold m.mu.
func (m *evictingBucketMap) evictOverCapLocked() {
	if m.maxEntries <= 0 {
		return
	}
	for m.order.Len() > m.maxEntries {
		back := m.order.Back()
		if back == nil {
			return
		}
		be := back.Value.(*bucketMapEntry)
		m.order.Remove(back)
		delete(m.entries, be.key)
	}
}

// len reports the current number of entries. Used by tests and
// diagnostics; not on any request path.
func (m *evictingBucketMap) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.order.Len()
}
