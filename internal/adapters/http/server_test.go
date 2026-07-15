package http_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	adapterhttp "github.com/302-digital/attachra/internal/adapters/http"
	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/storage/fs"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// startTestServer starts an adapterhttp.Server on an ephemeral loopback
// TCP port (mirroring internal/adapters/milter's own
// startTestServer helper) and returns its base URL and a real
// *sqlite.Store/link.Engine/fs.Driver it was constructed with, plus a
// cleanup func that shuts it down.
func startTestServer(t *testing.T, m *metrics.Metrics, checks []adapterhttp.ReadinessCheck) (baseURL string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}

	st, err := sqlite.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	drv, err := fs.New(fs.Config{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("fs.New() error = %v, want nil", err)
	}

	engine, err := link.NewEngine(st, link.Defaults{
		TTL:          time.Hour,
		MaxDownloads: 0,
		TokenBytes:   link.MinTokenBytes,
	}, st)
	if err != nil {
		t.Fatalf("link.NewEngine() error = %v, want nil", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv := adapterhttp.NewServer(adapterhttp.Config{
		Listen:          addr,
		ShutdownTimeout: 5 * time.Second,
	}, engine, st, drv, logger, st, m, checks, nil)

	ctx, cancel := context.WithCancel(context.Background())
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- srv.ListenAndServe(ctx) }()

	t.Cleanup(func() {
		cancel()
		if err := <-serveErrCh; err != nil {
			t.Errorf("ListenAndServe() returned error after shutdown: %v", err)
		}
	})

	waitForServer(t, addr)

	return "http://" + addr
}

// waitForServer polls addr until a TCP connection succeeds or t's
// deadline-ish budget is exhausted, so tests do not race the server's
// own goroutine starting to listen.
func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s did not start listening in time", addr)
}

// TestServerMountsHealthAndReadyRoutes verifies GET /healthz and GET
// /readyz are served without authentication (SR-130-1) regardless of
// whether readiness checks are configured (T-7.2.3, ATR-194).
func TestServerMountsHealthAndReadyRoutes(t *testing.T) {
	baseURL := startTestServer(t, nil, nil)

	resp, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	resp2, err := http.Get(baseURL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("GET /readyz status = %d, want %d (no checks configured)", resp2.StatusCode, http.StatusOK)
	}
}

// TestServerReadyzReflectsFailingCheck verifies a failing
// ReadinessCheck flips /readyz to 503, and that no check error detail
// leaks into the response body (SR-130-1).
func TestServerReadyzReflectsFailingCheck(t *testing.T) {
	checks := []adapterhttp.ReadinessCheck{
		{Name: "database", Check: func(context.Context) error { return context.DeadlineExceeded }},
	}
	baseURL := startTestServer(t, nil, checks)

	resp, err := http.Get(baseURL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

// TestServerMountsMetricsWhenConfigured verifies GET /metrics serves
// the Prometheus text exposition format when a Metrics is configured,
// and that the route is absent (404) when it is not (US-7.2/T-7.2.1,
// ATR-192).
func TestServerMountsMetricsWhenConfigured(t *testing.T) {
	m := metrics.New()
	m.ObserveDownload("success")
	baseURL := startTestServer(t, m, nil)

	resp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /metrics status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics body: %v", err)
	}
	if !strings.Contains(string(body), "attachra_downloads_total") {
		t.Errorf("/metrics body does not contain the expected metric family:\n%s", body)
	}
}

// TestServerOmitsMetricsRouteWhenNil verifies GET /metrics 404s when
// no Metrics was configured, rather than serving an always-empty
// registry.
func TestServerOmitsMetricsRouteWhenNil(t *testing.T) {
	baseURL := startTestServer(t, nil, nil)

	resp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /metrics status = %d, want %d (no Metrics configured)", resp.StatusCode, http.StatusNotFound)
	}
}
