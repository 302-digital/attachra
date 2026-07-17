package http

import (
	"sync"
	"time"
)

// tokenBucket is a minimal, dependency-free token-bucket rate limiter
// (SR-125-7). It is reimplemented here rather than pulling in
// golang.org/x/time/rate, mirroring the same trade-off
// internal/adapters/netutil.LimitListener already made ("reimplemented
// here to avoid adding a dependency for a handful of lines").
//
// Safe for concurrent use by multiple goroutines.
type tokenBucket struct {
	mu sync.Mutex

	ratePerSecond float64
	burst         float64
	tokens        float64
	updatedAt     time.Time

	now func() time.Time
}

// newTokenBucket returns a bucket refilling at ratePerMinute/60 tokens
// per second, holding at most burst tokens, starting full. A
// ratePerMinute <= 0 makes Allow always return true (no limiting).
func newTokenBucket(ratePerMinute, burst int) *tokenBucket {
	if burst <= 0 {
		burst = ratePerMinute
	}
	return &tokenBucket{
		ratePerSecond: float64(ratePerMinute) / 60,
		burst:         float64(burst),
		tokens:        float64(burst),
		updatedAt:     time.Now(),
	}
}

func (b *tokenBucket) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

// allow reports whether a request may proceed, consuming one token if
// so. Disabled buckets (ratePerSecond <= 0, i.e. the configured
// per-minute rate was <= 0) always allow.
func (b *tokenBucket) allow() bool {
	if b.ratePerSecond <= 0 {
		return true
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.clock()
	elapsed := now.Sub(b.updatedAt).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.ratePerSecond
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.updatedAt = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// perIPLimiter tracks one tokenBucket per client IP for the general
// request rate (SR-125-7) and, separately, one tokenBucket per IP for
// the tighter not-found budget that drives the enumeration tarpit
// (T1.1). Entries are created lazily; each map is an evictingBucketMap
// (ATR-297), so a distributed attacker spraying requests across many
// source IPs cannot grow either map without bound — see
// evictingBucketMap's doc comment for the eviction policy and why it is
// safe against throttle-reset abuse.
type perIPLimiter struct {
	requestRatePerMinute  int
	requestBurst          int
	notFoundRatePerMinute int

	requests  *evictingBucketMap
	notFounds *evictingBucketMap
}

// newPerIPLimiter returns a perIPLimiter whose eviction bounds are the
// package defaults (defaultBucketMapMaxEntries/defaultBucketMapTTL).
// Most callers, including every existing test, want this; NewHandler
// uses newPerIPLimiterWithBounds directly so RateLimitConfig can override
// the bounds per deployment.
func newPerIPLimiter(requestRatePerMinute, requestBurst, notFoundRatePerMinute int) *perIPLimiter {
	return newPerIPLimiterWithBounds(requestRatePerMinute, requestBurst, notFoundRatePerMinute, 0, 0)
}

// newPerIPLimiterWithBounds is newPerIPLimiter with explicit eviction
// bounds (ATR-297): maxEntries <= 0 and/or ttl <= 0 fall back to the
// package defaults, so a caller (or an unnormalized RateLimitConfig
// zero value) always gets a bounded map, never an accidentally
// unbounded one.
func newPerIPLimiterWithBounds(requestRatePerMinute, requestBurst, notFoundRatePerMinute, maxEntries int, ttl time.Duration) *perIPLimiter {
	if maxEntries <= 0 {
		maxEntries = defaultBucketMapMaxEntries
	}
	if ttl <= 0 {
		ttl = defaultBucketMapTTL
	}
	return &perIPLimiter{
		requestRatePerMinute:  requestRatePerMinute,
		requestBurst:          requestBurst,
		notFoundRatePerMinute: notFoundRatePerMinute,
		requests:              newEvictingBucketMap(maxEntries, ttl),
		notFounds:             newEvictingBucketMap(maxEntries, ttl),
	}
}

// allowRequest reports whether ip may make another request under the
// general per-IP budget.
func (l *perIPLimiter) allowRequest(ip string) bool {
	if l.requestRatePerMinute <= 0 {
		return true
	}
	rate, burst := l.requestRatePerMinute, l.requestBurst
	b := l.requests.getOrCreate(ip, func() *tokenBucket { return newTokenBucket(rate, burst) })
	return b.allow()
}

// allowNotFound reports whether ip may receive another generic
// not-found-shaped response without being tarpitted (SR-125-7, T1.1).
// A disabled (<=0) notFoundRatePerMinute always allows, meaning no
// extra tarpit delay is applied beyond the general per-IP limit.
func (l *perIPLimiter) allowNotFound(ip string) bool {
	if l.notFoundRatePerMinute <= 0 {
		return true
	}
	rate := l.notFoundRatePerMinute
	b := l.notFounds.getOrCreate(ip, func() *tokenBucket { return newTokenBucket(rate, rate) })
	return b.allow()
}
