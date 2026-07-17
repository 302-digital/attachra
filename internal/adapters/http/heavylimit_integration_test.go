package http

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// newHeavyLimitTestHandler builds a real APIHandler (real sqlite store,
// real link.Engine, real middleware chain) with MaxConcurrentHeavyRequests
// set to 1, plus a seeded admin bearer secret. It is a white-box
// (package http, not http_test) counterpart to api_test.go's
// newAPITestServer, kept minimal and local to this file so ATR-298's
// integration test can also reach the unexported heavyLimiter field
// directly to deterministically force the at-capacity state, rather
// than relying on real request concurrency and timing.
func newHeavyLimitTestHandler(t *testing.T) (h *APIHandler, adminSecret string) {
	t.Helper()

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "heavylimit-test.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine, err := link.NewEngine(st, link.Defaults{
		TTL:          72 * time.Hour,
		MaxDownloads: 0,
		TokenBytes:   link.MinTokenBytes,
	}, st, logger)
	if err != nil {
		t.Fatalf("link.NewEngine() error = %v, want nil", err)
	}

	h = NewAPIHandler(st, st, engine, nil, logger, st, st, metrics.New(), APIConfig{
		MaxBodyBytes:               512,
		AuthFailuresPerMinute:      1000,
		AuthFailuresBurst:          1000,
		MaxConcurrentHeavyRequests: 1,
	})

	id, err := store.NewTokenID()
	if err != nil {
		t.Fatalf("NewTokenID() error = %v", err)
	}
	secret, hash, err := store.GenerateAPISecret(store.MinAPISecretBytes)
	if err != nil {
		t.Fatalf("GenerateAPISecret() error = %v", err)
	}
	if err := st.CreateAPIToken(context.Background(), store.NewAPITokenParams{
		ID: id, Name: "admin", Role: store.RoleAdmin, TokenHash: hash,
	}); err != nil {
		t.Fatalf("CreateAPIToken() error = %v", err)
	}

	return h, secret
}

// TestHeavyEndpointsRejectAtCapacityAndOrdinaryRoutesAreUnaffected
// exercises ATR-298 end to end through the real APIHandler: with
// MaxConcurrentHeavyRequests=1, once the single slot is held, all three
// heavy routes (GET /audit/export, GET /stats/summary, GET
// /stats/deliverability) answer 429 rate_limited with a Retry-After
// header, while an ordinary route (GET /audit, which is not
// concurrency-limited) still succeeds — the limiter must not
// degrade single/unrelated requests, only bound the heavy ones.
func TestHeavyEndpointsRejectAtCapacityAndOrdinaryRoutesAreUnaffected(t *testing.T) {
	h, adminSecret := newHeavyLimitTestHandler(t)
	ts := httptest.NewServer(h.Handler())
	t.Cleanup(ts.Close)

	get := func(path string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest(%q) error = %v", path, err)
		}
		req.Header.Set("Authorization", "Bearer "+adminSecret)
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("client.Do(%q) error = %v", path, err)
		}
		return resp
	}

	// Occupy the single concurrency slot directly (white-box), rather
	// than racing a real slow request against these assertions.
	if !h.heavyLimiter.acquire() {
		t.Fatal("acquire() on a fresh limiter = false, want true")
	}

	for _, path := range []string{
		"/api/v1/audit/export",
		"/api/v1/stats/summary?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z",
		"/api/v1/stats/deliverability?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z",
	} {
		resp := get(path)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("GET %s while at capacity: status = %d, want 429", path, resp.StatusCode)
		}
		if got := resp.Header.Get("Retry-After"); got == "" {
			t.Errorf("GET %s while at capacity: Retry-After header not set", path)
		}
		_ = resp.Body.Close()
	}

	// An ordinary, non-heavy route must be entirely unaffected by the
	// heavy limiter being saturated.
	resp := get("/api/v1/audit")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/v1/audit while heavy limiter is at capacity: status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Freeing the slot lets a heavy request through again.
	h.heavyLimiter.release()

	resp = get("/api/v1/audit/export")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/v1/audit/export after releasing the slot: status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()
}
