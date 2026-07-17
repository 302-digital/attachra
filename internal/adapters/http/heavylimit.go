package http

import (
	"net/http"
	"strconv"
)

// heavyRequestRetryAfterSeconds is the Retry-After hint sent with a 429
// from heavyLimitMiddleware (ATR-298). It is a short, fixed value —
// callers running into this limit are expected to be automation, not a
// human waiting on a spinner, and the limiter's slots typically free up
// within seconds once one of the concurrently running scans finishes.
const heavyRequestRetryAfterSeconds = 5

// heavyRequestLimiter bounds the number of concurrently in-flight
// "heavy" read requests across every caller combined (ATR-298, security
// review ATR-200 N1). GET /audit/export streams a full, unpaginated scan
// of the audit log, and GET /stats/summary and GET /stats/deliverability
// each recompute a full-window aggregate on every call; none of them are
// bounded by anything else in front of the store (its reader pool is
// deliberately left unbounded — see internal/core/store/sqlite/conn.go),
// so a single low-privilege token (viewer, or auditor for export)
// authorized only for read access could otherwise open an unbounded
// number of these scans in parallel and pressure reader connections,
// CPU and IO. Keeping a low-privilege token's blast radius small is the
// whole point of the viewer/auditor role split (ADR-015); this closes
// the concurrency-shaped gap in that story.
//
// It is a simple counting semaphore over a buffered channel: acquire
// never blocks, so a request that cannot get a slot is rejected
// immediately (429 + Retry-After) rather than queued behind whichever
// requests are already running — queuing would let one caller's slow
// scan head-of-line block another caller's unrelated one, trading one
// blast-radius problem for another.
//
// Safe for concurrent use by multiple goroutines.
type heavyRequestLimiter struct {
	slots chan struct{}
}

// newHeavyRequestLimiter returns a heavyRequestLimiter allowing at most
// maxConcurrent requests through at once. maxConcurrent <= 0 defaults to
// defaultMaxConcurrentHeavyRequests, so a caller can never end up with
// an accidentally unbounded (or zero-capacity, permanently-rejecting)
// limiter.
func newHeavyRequestLimiter(maxConcurrent int) *heavyRequestLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentHeavyRequests
	}
	return &heavyRequestLimiter{slots: make(chan struct{}, maxConcurrent)}
}

// acquire attempts to reserve one concurrency slot, returning
// immediately: ok is false if the limiter is already at capacity. A
// successful acquire (ok == true) must be paired with exactly one call
// to release once the request finishes, by whatever path it finishes
// (normal completion, an error return, or the client disconnecting/the
// request context being canceled mid-stream) — callers do this with a
// deferred release immediately after a successful acquire, which covers
// all three uniformly.
func (l *heavyRequestLimiter) acquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// release frees the slot reserved by a prior successful acquire. Calling
// it without a matching successful acquire is a programming error (it
// would block forever on an empty channel receive in the general case,
// or panic if the channel were also closed — neither of which this type
// ever does), so every call site pairs it with acquire via defer.
func (l *heavyRequestLimiter) release() {
	<-l.slots
}

// heavyLimitMiddleware wraps a heavy-read handler with h.heavyLimiter,
// answering 429 rate_limited (with a Retry-After hint, SR-130-5's
// pattern for a client that should back off) instead of calling next
// once every concurrency slot is taken (ATR-298). No audit event is
// recorded for a rejection here — unlike an auth failure, this is not a
// security-relevant event on its own, just ordinary backpressure.
//
// It is applied per-route in routes() rather than globally: an ordinary
// single-record GET is cheap regardless of how many run at once, so
// only the actual full-scan/full-aggregation endpoints carry this
// limiter.
func (h *APIHandler) heavyLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.heavyLimiter.acquire() {
			w.Header().Set("Retry-After", strconv.Itoa(heavyRequestRetryAfterSeconds))
			writeAPIError(w, h.logger, http.StatusTooManyRequests, errCodeRateLimited, "too many concurrent heavy requests, try again shortly")
			return
		}
		defer h.heavyLimiter.release()
		next(w, r)
	}
}
