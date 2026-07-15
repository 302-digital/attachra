package http

import "sync"

// authThrottle rate-limits repeated authentication failures per source
// IP (SR-130-5's "rate limit on auth failures"; anti-brute-force against
// invalid Bearer guessing, called out in api/openapi.yaml's
// Authentication section). It is deliberately separate from the
// download adapter's request-rate perIPLimiter: this budget is charged
// only by auth *failures*, so a client presenting a valid token is never
// throttled by it no matter how many requests it makes, while a client
// spraying invalid tokens is cut off after a small number of tries.
//
// It reuses the same dependency-free tokenBucket the rest of this adapter
// uses. Buckets are created lazily per IP and never evicted within the
// process lifetime — the same accepted MVP bound documented on
// perIPLimiter (a pathological number of distinct source IPs grows this
// map); it is not a correctness issue.
//
// Safe for concurrent use by multiple goroutines.
type authThrottle struct {
	mu sync.Mutex

	ratePerMinute int
	burst         int
	buckets       map[string]*tokenBucket
}

// newAuthThrottle returns an authThrottle allowing ratePerMinute
// sustained auth failures per IP with the given burst. A ratePerMinute
// <= 0 disables throttling (failAllowed always returns true), so an
// operator can turn it off, and unit tests that do not exercise it are
// unaffected.
func newAuthThrottle(ratePerMinute, burst int) *authThrottle {
	if burst <= 0 {
		burst = ratePerMinute
	}
	return &authThrottle{
		ratePerMinute: ratePerMinute,
		burst:         burst,
		buckets:       make(map[string]*tokenBucket),
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

	a.mu.Lock()
	b, ok := a.buckets[ip]
	if !ok {
		b = newTokenBucket(a.ratePerMinute, a.burst)
		a.buckets[ip] = b
	}
	a.mu.Unlock()

	return b.allow()
}
