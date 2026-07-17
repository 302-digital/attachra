package http

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestHeavyRequestLimiterAcquireUpToCapacityThenRejects(t *testing.T) {
	l := newHeavyRequestLimiter(2)

	if !l.acquire() {
		t.Fatal("first acquire = false, want true")
	}
	if !l.acquire() {
		t.Fatal("second acquire = false, want true (within capacity)")
	}
	if l.acquire() {
		t.Fatal("third acquire = true, want false (capacity exhausted)")
	}
}

func TestHeavyRequestLimiterReleaseFreesASlot(t *testing.T) {
	l := newHeavyRequestLimiter(1)

	if !l.acquire() {
		t.Fatal("first acquire = false, want true")
	}
	if l.acquire() {
		t.Fatal("second acquire before release = true, want false")
	}

	l.release()

	if !l.acquire() {
		t.Fatal("acquire after release = false, want true (slot freed)")
	}
}

func TestHeavyRequestLimiterZeroCapacityFallsBackToDefault(t *testing.T) {
	l := newHeavyRequestLimiter(0)
	if cap(l.slots) != defaultMaxConcurrentHeavyRequests {
		t.Errorf("slots capacity = %d, want default %d", cap(l.slots), defaultMaxConcurrentHeavyRequests)
	}
}

// TestHeavyRequestLimiterConcurrentNeverExceedsCapacity races many
// goroutines acquiring against a small-capacity limiter and asserts the
// number of goroutines simultaneously holding a slot never exceeds the
// configured capacity (critical counters must be race-safe; run with
// -race).
func TestHeavyRequestLimiterConcurrentNeverExceedsCapacity(t *testing.T) {
	const capacity = 4
	const goroutines = 50
	l := newHeavyRequestLimiter(capacity)

	var mu sync.Mutex
	current, maxObserved := 0, 0
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !l.acquire() {
				return
			}
			defer l.release()

			mu.Lock()
			current++
			if current > maxObserved {
				maxObserved = current
			}
			mu.Unlock()

			// Hold the slot briefly so other goroutines have a chance to
			// race in and (incorrectly, if there were a bug) also acquire
			// while this one is still held.
			time.Sleep(time.Millisecond)

			mu.Lock()
			current--
			mu.Unlock()
		}()
	}
	wg.Wait()

	if maxObserved > capacity {
		t.Errorf("max concurrently held slots = %d, exceeds capacity %d", maxObserved, capacity)
	}
}

// TestHeavyLimitMiddlewareRejectsOverCapacityWith429 exercises
// heavyLimitMiddleware directly (bypassing the full APIHandler auth
// chain) to assert its response contract: once the wrapped limiter is
// at capacity, further requests get 429 rate_limited with a Retry-After
// header, and the wrapped handler is never called for the rejected
// request.
func TestHeavyLimitMiddlewareRejectsOverCapacityWith429(t *testing.T) {
	h := &APIHandler{logger: testLogger(), heavyLimiter: newHeavyRequestLimiter(1)}

	release := make(chan struct{})
	entered := make(chan struct{})
	slow := h.heavyLimitMiddleware(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})

	// Occupy the single slot with an in-flight request.
	done := make(chan struct{})
	go func() {
		defer close(done)
		slow(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil))
	}()
	<-entered

	// A second, concurrent request must be rejected immediately rather
	// than queued.
	called := false
	rejecting := h.heavyLimitMiddleware(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	rejecting(rec, httptest.NewRequest(http.MethodGet, "/api/v1/stats/summary", nil))

	if called {
		t.Fatal("wrapped handler was called despite the limiter being at capacity")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After header not set on 429 response")
	}

	// Release the in-flight request and confirm the slot is freed
	// (ctx-cancellation/completion must always release, per acceptance
	// criteria).
	close(release)
	<-done

	if !h.heavyLimiter.acquire() {
		t.Fatal("slot was not freed after the in-flight request completed")
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
