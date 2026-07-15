package http

import (
	"sync"
	"time"
)

// tokenBucket is a minimal, dependency-free token-bucket rate limiter
// (SR-125-7). It is reimplemented here rather than pulling in
// golang.org/x/time/rate, mirroring the same trade-off the milter
// adapter already made for limitListener (internal/adapters/milter/
// limitlistener.go: "reimplemented here to avoid adding a dependency
// for a handful of lines").
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
// (T1.1). Entries are created lazily and never actively evicted within
// the process lifetime; this is an accepted MVP bound (a long-running
// process facing a very large number of distinct source IPs grows this
// map unbounded) rather than a correctness issue — see the package doc
// comment on limiter for the sizing note.
type perIPLimiter struct {
	mu sync.Mutex

	requestRatePerMinute  int
	requestBurst          int
	notFoundRatePerMinute int

	requests  map[string]*tokenBucket
	notFounds map[string]*tokenBucket
}

func newPerIPLimiter(requestRatePerMinute, requestBurst, notFoundRatePerMinute int) *perIPLimiter {
	return &perIPLimiter{
		requestRatePerMinute:  requestRatePerMinute,
		requestBurst:          requestBurst,
		notFoundRatePerMinute: notFoundRatePerMinute,
		requests:              make(map[string]*tokenBucket),
		notFounds:             make(map[string]*tokenBucket),
	}
}

// allowRequest reports whether ip may make another request under the
// general per-IP budget.
func (l *perIPLimiter) allowRequest(ip string) bool {
	if l.requestRatePerMinute <= 0 {
		return true
	}
	return l.bucketFor(l.requests, ip, l.requestRatePerMinute, l.requestBurst).allow()
}

// allowNotFound reports whether ip may receive another generic
// not-found-shaped response without being tarpitted (SR-125-7, T1.1).
// A disabled (<=0) notFoundRatePerMinute always allows, meaning no
// extra tarpit delay is applied beyond the general per-IP limit.
func (l *perIPLimiter) allowNotFound(ip string) bool {
	if l.notFoundRatePerMinute <= 0 {
		return true
	}
	return l.bucketFor(l.notFounds, ip, l.notFoundRatePerMinute, l.notFoundRatePerMinute).allow()
}

func (l *perIPLimiter) bucketFor(set map[string]*tokenBucket, ip string, ratePerMinute, burst int) *tokenBucket {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := set[ip]
	if !ok {
		b = newTokenBucket(ratePerMinute, burst)
		set[ip] = b
	}
	return b
}
