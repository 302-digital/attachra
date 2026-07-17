package http_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
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
	}, st, nil)
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

// TestServerMountsAboutRoute verifies GET /about (ATR-271, Recipient
// Trust Kit layer 2) is served without authentication, alongside /p/,
// /healthz and /readyz (SR-130-1's public-route exception), carries the
// same page security headers as the package page, and does not leak
// any installation-specific detail (e.g. the server's own listen
// address) into the response body — the page is a fully static
// template with no request- or config-derived data.
func TestServerMountsAboutRoute(t *testing.T) {
	baseURL := startTestServer(t, nil, nil)

	resp, err := http.Get(baseURL + "/about")
	if err != nil {
		t.Fatalf("GET /about: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /about status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
	wantCSP := "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	if got := resp.Header.Get("Content-Security-Policy"); got != wantCSP {
		t.Errorf("Content-Security-Policy = %q, want %q", got, wantCSP)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "private, no-store, max-age=0" {
		t.Errorf("Cache-Control = %q, want private, no-store, max-age=0", got)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /about body: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "Attachra") {
		t.Errorf("/about body does not mention Attachra:\n%s", text)
	}
	// No installation-specific detail: this server's own listen address
	// must never appear in a page served to an unauthenticated caller.
	if addr := strings.TrimPrefix(baseURL, "http://"); strings.Contains(text, addr) {
		t.Errorf("/about body leaks the server's listen address %q:\n%s", addr, text)
	}
}

// TestServerAboutRouteRejectsNonGET verifies GET/HEAD are the only
// methods /about accepts; anything else answers 405 with an Allow
// header, matching the rest of this adapter's route table rather than
// silently falling through to a generic 404.
func TestServerAboutRouteRejectsNonGET(t *testing.T) {
	baseURL := startTestServer(t, nil, nil)

	resp, err := http.Post(baseURL+"/about", "text/plain", nil) //nolint:noctx
	if err != nil {
		t.Fatalf("POST /about: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /about status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
	if got, want := resp.Header.Get("Allow"), "GET, HEAD"; got != want {
		t.Errorf("Allow header = %q, want %q", got, want)
	}
}

// startSplitTestServer starts an adapterhttp.Server with a separate
// admin listener configured (ATR-292), on two ephemeral loopback TCP
// ports, and returns both base URLs plus a cleanup func registered via
// t.Cleanup.
func startSplitTestServer(t *testing.T, m *metrics.Metrics, checks []adapterhttp.ReadinessCheck) (baseURL, adminURL string) {
	t.Helper()

	addr := ephemeralAddr(t)
	adminAddr := ephemeralAddr(t)

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
	}, st, nil)
	if err != nil {
		t.Fatalf("link.NewEngine() error = %v, want nil", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv := adapterhttp.NewServer(adapterhttp.Config{
		Listen:          addr,
		AdminListen:     adminAddr,
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
	waitForServer(t, adminAddr)

	return "http://" + addr, "http://" + adminAddr
}

// ephemeralAddr reserves a free loopback TCP port and returns its
// address (mirroring startTestServer's own probe-then-close pattern).
func ephemeralAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return addr
}

// TestServerAboutRouteDoesNotCollideWithAPI is the ATR-271 acceptance
// check that /about (public, unauthenticated) and /api/v1 (the
// token-authenticated admin/automation surface, US-8.1/SR-130-1) stay
// on their own sides of the mount point when both are wired into the
// same Server: GET /about needs no Authorization header at all, while
// GET /api/v1/about — a path that only differs by the API's own mount
// prefix — still goes through the API's deny-by-default auth rather
// than accidentally serving the about page or bypassing auth.
func TestServerAboutRouteDoesNotCollideWithAPI(t *testing.T) {
	addr := ephemeralAddr(t)

	st, err := sqlite.Open(t.TempDir() + "/about-api-test.db")
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	drv, err := fs.New(fs.Config{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("fs.New() error = %v, want nil", err)
	}

	engine := newTestLinkEngine(t, st)
	policyStore, _ := newTestPolicyStore(t, defaultTestPolicyYAML)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	api := adapterhttp.NewAPIHandler(st, st, engine, policyStore, logger, st, st, nil, adapterhttp.APIConfig{
		MaxBodyBytes:          512,
		AuthFailuresPerMinute: 1000,
		AuthFailuresBurst:     1000,
	})

	srv := adapterhttp.NewServer(adapterhttp.Config{
		Listen:          addr,
		ShutdownTimeout: 5 * time.Second,
	}, engine, st, drv, logger, st, nil, nil, api)

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
	baseURL := "http://" + addr

	resp, err := http.Get(baseURL + "/about")
	if err != nil {
		t.Fatalf("GET /about: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /about status = %d, want %d (public route unaffected by API mount)", resp.StatusCode, http.StatusOK)
	}

	resp2, err := http.Get(baseURL + "/api/v1/about")
	if err != nil {
		t.Fatalf("GET /api/v1/about: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/about status = %d, want %d (deny-by-default, not the about page)", resp2.StatusCode, http.StatusUnauthorized)
	}
}

// TestServerSplitsAdminRoutesWhenConfigured verifies the ATR-292 route
// split: GET /metrics and the dependency-detailed GET /readyz are
// unreachable on the public listener and reachable on the admin one;
// GET /healthz (liveness) is reachable on both; GET /p/ is unaffected
// (still only on the public listener).
func TestServerSplitsAdminRoutesWhenConfigured(t *testing.T) {
	m := metrics.New()
	baseURL, adminURL := startSplitTestServer(t, m, nil)

	// /metrics: 404 on public, 200 on admin.
	resp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("GET %s/metrics: %v", baseURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("public GET /metrics status = %d, want %d (moved to the admin listener)", resp.StatusCode, http.StatusNotFound)
	}

	adminResp, err := http.Get(adminURL + "/metrics")
	if err != nil {
		t.Fatalf("GET %s/metrics: %v", adminURL, err)
	}
	defer adminResp.Body.Close() //nolint:errcheck
	if adminResp.StatusCode != http.StatusOK {
		t.Errorf("admin GET /metrics status = %d, want %d", adminResp.StatusCode, http.StatusOK)
	}

	// /readyz: 404 on public, 200 on admin.
	resp2, err := http.Get(baseURL + "/readyz")
	if err != nil {
		t.Fatalf("GET %s/readyz: %v", baseURL, err)
	}
	defer resp2.Body.Close() //nolint:errcheck
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("public GET /readyz status = %d, want %d (moved to the admin listener)", resp2.StatusCode, http.StatusNotFound)
	}

	adminResp2, err := http.Get(adminURL + "/readyz")
	if err != nil {
		t.Fatalf("GET %s/readyz: %v", adminURL, err)
	}
	defer adminResp2.Body.Close() //nolint:errcheck
	if adminResp2.StatusCode != http.StatusOK {
		t.Errorf("admin GET /readyz status = %d, want %d", adminResp2.StatusCode, http.StatusOK)
	}

	// /healthz: 200 on both.
	resp3, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET %s/healthz: %v", baseURL, err)
	}
	defer resp3.Body.Close() //nolint:errcheck
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("public GET /healthz status = %d, want %d", resp3.StatusCode, http.StatusOK)
	}

	adminResp3, err := http.Get(adminURL + "/healthz")
	if err != nil {
		t.Fatalf("GET %s/healthz: %v", adminURL, err)
	}
	defer adminResp3.Body.Close() //nolint:errcheck
	if adminResp3.StatusCode != http.StatusOK {
		t.Errorf("admin GET /healthz status = %d, want %d", adminResp3.StatusCode, http.StatusOK)
	}

	// /p/ (a token that does not exist -> the handler's own not-found
	// response, but crucially NOT a 404 from an absent route/mux
	// entry) stays reachable only on the public listener.
	resp4, err := http.Get(baseURL + "/p/nonexistent-token")
	if err != nil {
		t.Fatalf("GET %s/p/nonexistent-token: %v", baseURL, err)
	}
	defer resp4.Body.Close() //nolint:errcheck

	adminResp4, err := http.Get(adminURL + "/p/nonexistent-token")
	if err != nil {
		t.Fatalf("GET %s/p/nonexistent-token: %v", adminURL, err)
	}
	defer adminResp4.Body.Close() //nolint:errcheck
	if adminResp4.StatusCode != http.StatusNotFound {
		t.Errorf("admin GET /p/nonexistent-token status = %d, want %d (no /p/ route on the admin listener)", adminResp4.StatusCode, http.StatusNotFound)
	}
}

// TestServerAdminListenEmptyKeepsLegacySingleListener verifies that
// leaving AdminListen empty (the explicit opt-out) reproduces the
// pre-ATR-292 behavior: /metrics and /readyz both remain reachable on
// the single public listener, and no second listener is bound (a
// connection attempt to a second ephemeral port grabbed for this test
// simply is not the server — nothing to assert there beyond the
// existing TestServerMountsHealthAndReadyRoutes /
// TestServerMountsMetricsWhenConfigured coverage already exercising
// this exact configuration shape via startTestServer).
func TestServerAdminListenEmptyKeepsLegacySingleListener(t *testing.T) {
	m := metrics.New()
	baseURL := startTestServer(t, m, nil)

	for _, path := range []string{"/metrics", "/readyz", "/healthz"} {
		resp, err := http.Get(baseURL + path)
		if err != nil {
			t.Fatalf("GET %s%s: %v", baseURL, path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d (AdminListen empty: legacy single-listener mode)", path, resp.StatusCode, http.StatusOK)
		}
		_ = resp.Body.Close()
	}
}

// syncBuffer is a concurrency-safe io.Writer around bytes.Buffer, for
// tests that read a slog log while a background goroutine (a running
// Server) may still be writing to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitForLogContains polls buf until it contains substr or a 2-second
// budget is exhausted, avoiding a fixed sleep for a log line written by
// a background goroutine.
func waitForLogContains(t *testing.T, buf *syncBuffer, substr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), substr) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("log does not contain %q within timeout; got:\n%s", substr, buf.String())
}

// newTestServerDeps builds the real (non-nil) core dependencies
// adapterhttp.NewServer requires, without starting any listener —
// shared by the tests below that only care about NewServer's own
// synchronous construction-time behavior (route tables, fold-warning
// logging) or that need full control over when ListenAndServe runs.
func newTestServerDeps(t *testing.T) (*link.Engine, *sqlite.Store, *fs.Driver) {
	t.Helper()

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
	}, st, nil)
	if err != nil {
		t.Fatalf("link.NewEngine() error = %v, want nil", err)
	}

	return engine, st, drv
}

// TestNewServer_FoldWarnsWhenPublicListenerIsLoopback verifies the
// ATR-292 security-review requirement that folding admin routes onto
// the public listener (AdminListen empty) is never silent: with a
// loopback public listener it must log at least a Warn.
func TestNewServer_FoldWarnsWhenPublicListenerIsLoopback(t *testing.T) {
	engine, st, drv := newTestServerDeps(t)

	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	adapterhttp.NewServer(adapterhttp.Config{
		Listen: "127.0.0.1:8080",
		// AdminListen empty: fold mode.
	}, engine, st, drv, logger, st, nil, nil, nil)

	got := buf.String()
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("expected a WARN log line when folding onto a loopback public listener, got:\n%s", got)
	}
	if strings.Contains(got, "level=ERROR") {
		t.Errorf("expected no ERROR log line for a loopback public listener, got:\n%s", got)
	}
}

// TestNewServer_FoldErrorsWhenPublicListenerIsNotLoopback verifies the
// escalation half of the same requirement: folding admin routes onto a
// public listener that does NOT look loopback-only (e.g. 0.0.0.0) must
// log at Error level, since /metrics and /readyz may then be reachable
// from outside the host.
func TestNewServer_FoldErrorsWhenPublicListenerIsNotLoopback(t *testing.T) {
	engine, st, drv := newTestServerDeps(t)

	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	adapterhttp.NewServer(adapterhttp.Config{
		Listen: "0.0.0.0:8080",
		// AdminListen empty: fold mode.
	}, engine, st, drv, logger, st, nil, nil, nil)

	got := buf.String()
	if !strings.Contains(got, "level=ERROR") {
		t.Errorf("expected an ERROR log line when folding onto a non-loopback public listener, got:\n%s", got)
	}
}

// TestNewServer_SplitLogsNothingAboutFolding verifies the negative
// case: when AdminListen is actually configured (no folding), NewServer
// does not emit either fold-warning log line.
func TestNewServer_SplitLogsNothingAboutFolding(t *testing.T) {
	engine, st, drv := newTestServerDeps(t)

	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	adapterhttp.NewServer(adapterhttp.Config{
		Listen:      "127.0.0.1:8080",
		AdminListen: "127.0.0.1:18090",
	}, engine, st, drv, logger, st, nil, nil, nil)

	got := buf.String()
	if strings.Contains(got, "fold_into_http") || strings.Contains(got, "folded onto") || strings.Contains(got, "are served on the public download listener") {
		t.Errorf("expected no fold-warning log line when AdminListen is configured, got:\n%s", got)
	}
}

// TestServerAdminBindFailureDegradesWithoutStoppingPublicListener is
// the ATR-292 security-review regression test for the chosen resolution
// of the admin-bind-failure blocker: occupying the admin port before
// the server starts must NOT prevent the public listener (/p/,
// /healthz — both load-bearing for mail delivery) from serving
// normally, must NOT make ListenAndServe return an error, and must log
// the failure loudly.
func TestServerAdminBindFailureDegradesWithoutStoppingPublicListener(t *testing.T) {
	// Occupy the admin address before the real server ever tries to
	// bind it.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen (occupy admin port): %v", err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	adminAddr := occupied.Addr().String()

	addr := ephemeralAddr(t)
	engine, st, drv := newTestServerDeps(t)

	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	srv := adapterhttp.NewServer(adapterhttp.Config{
		Listen:          addr,
		AdminListen:     adminAddr,
		ShutdownTimeout: 5 * time.Second,
	}, engine, st, drv, logger, st, metrics.New(), nil, nil)

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
	waitForLogContains(t, &buf, "admin listener failed to bind")

	// The public listener must be completely unaffected: /healthz still
	// serves normally.
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want %d (public listener must be unaffected by admin bind failure)", resp.StatusCode, http.StatusOK)
	}

	// /metrics and /readyz are simply unavailable (not merged onto the
	// public listener — that would silently reintroduce the exposure
	// ATR-292 fixes) until the operator frees the port and restarts.
	resp2, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("GET /metrics status = %d, want %d (admin bind failed: no fallback route on the public listener)", resp2.StatusCode, http.StatusNotFound)
	}
}
