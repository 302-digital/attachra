package http

import "time"

// authThrottle rate-limits repeated authentication failures per source
// IP (SR-130-5's "rate limit on auth failures"; anti-brute-force against
// invalid Bearer guessing, called out in api/openapi.yaml's
// Authentication section). It is deliberately separate from the
// download adapter's request-rate perIPLimiter: this budget is charged
// only by auth *failures*, so a client presenting a valid token is never
// throttled by it no matter how many requests it makes, while a client
// spraying invalid tokens is cut off after a small number of tries.
//
// It reuses the same dependency-free tokenBucket the rest of this
// adapter uses, stored in an evictingBucketMap (ATR-297) rather than a
// plain map, so a pathological number of distinct source IPs cannot
// grow buckets without bound — see evictingBucketMap's doc comment for
// the eviction policy.
//
// Safe for concurrent use by multiple goroutines.
type authThrottle struct {
	ratePerMinute int
	burst         int
	buckets       *evictingBucketMap
}

// newAuthThrottle returns an authThrottle allowing ratePerMinute
// sustained auth failures per IP with the given burst, evicted per the
// package-default bounds (defaultBucketMapMaxEntries/
// defaultBucketMapTTL). A ratePerMinute <= 0 disables throttling
// (failAllowed always returns true), so an operator can turn it off,
// and unit tests that do not exercise it are unaffected.
func newAuthThrottle(ratePerMinute, burst int) *authThrottle {
	return newAuthThrottleWithBounds(ratePerMinute, burst, 0, 0)
}

// newAuthThrottleWithBounds is newAuthThrottle with explicit eviction
// bounds (ATR-297): maxEntries <= 0 and/or ttl <= 0 fall back to the
// package defaults, mirroring newPerIPLimiterWithBounds.
func newAuthThrottleWithBounds(ratePerMinute, burst, maxEntries int, ttl time.Duration) *authThrottle {
	if burst <= 0 {
		burst = ratePerMinute
	}
	if maxEntries <= 0 {
		maxEntries = defaultBucketMapMaxEntries
	}
	if ttl <= 0 {
		ttl = defaultBucketMapTTL
	}
	return &authThrottle{
		ratePerMinute: ratePerMinute,
		burst:         burst,
		buckets:       newEvictingBucketMap(maxEntries, ttl),
	}
}

// failAllowed reports whether another authentication failure from ip may
// still be answered with an ordinary 401, consuming one unit of that IP's
// failure budget. Once it returns false the caller answers 429 instead,
// slowing a brute-force sweep. A disabled throttle (ratePerMinute <= 0)
// always allows.
func (a *authThrottle) failAllowed(ip string) bool {
	if a.ratePerMinute <= 0 {
		return true
	}

	rate, burst := a.ratePerMinute, a.burst
	b := a.buckets.getOrCreate(ip, func() *tokenBucket { return newTokenBucket(rate, burst) })
	return b.allow()
}
