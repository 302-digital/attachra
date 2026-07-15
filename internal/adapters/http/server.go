package http

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/storage"
)

// Server is the download adapter's HTTP server (ADR-008-style
// adapter, mirroring internal/adapters/milter.Server): it listens for
// connections, bounds their number and timeouts, and dispatches every
// request to a Handler. It depends only on internal/core (via
// Handler); internal/core never depends back on it (ADR-002).
type Server struct {
	cfg     Config
	handler *Handler
	logger  *slog.Logger

	inner    *http.Server
	listener net.Listener
}

// NewServer creates a download adapter Server. engine, st and drv are
// the core dependencies Handler needs; logger receives structured
// diagnostic and audit-relevant log entries; sink receives the same
// events as durable, append-only audit.Event records (US-7.1,
// ATR-190) — nil is accepted and treated as audit.NopSink{}. m
// receives Prometheus observations for downloads served (US-7.2/
// T-7.2.1, ATR-192) and, if non-nil, is exposed at GET /metrics
// (Prometheus text exposition format) without authentication — see
// SR-130-1's health/metrics exception; a nil m omits the route
// entirely rather than serving an always-empty registry. checks
// configures GET /readyz's dependency probes (US-7.2/T-7.2.3,
// ATR-194); GET /healthz (liveness) is always mounted regardless of
// checks. Both health routes are served without authentication
// (SR-130-1).
//
// api, if non-nil, mounts the token-authenticated admin/automation REST
// API (US-8.1/E8, ATR-196) at /api/v1/ with its own middleware chain
// (auth, roles, recovery, logging, throttling); a nil api omits the whole
// subtree, so a deployment (or a test) that does not want the API simply
// passes nil. The /p/, /healthz, /readyz and /metrics routes stay mounted
// at the server root, outside the API's auth (SR-130-1's explicit
// health/download exception).
func NewServer(cfg Config, engine *link.Engine, st downloadStore, drv storage.Driver, logger *slog.Logger, sink audit.AuditSink, m *metrics.Metrics, checks []ReadinessCheck, api *APIHandler) *Server {
	cfg = cfg.normalized()
	handler := NewHandler(engine, st, drv, logger, sink, cfg.RateLimit, cfg.TrustedProxies, m)
	health := NewHealthHandler(checks, logger)

	global := newTokenBucket(cfg.RateLimit.GlobalRequestsPerMinute, cfg.RateLimit.GlobalBurst)

	mux := http.NewServeMux()
	mux.Handle("/p/", globalRateLimit(global, handler))
	mux.HandleFunc("/healthz", health.Liveness)
	mux.HandleFunc("/readyz", health.Readiness)
	if m != nil {
		mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
	}
	if api != nil {
		// The API's own middleware chain (recover/log/body-limit/auth/roles)
		// applies to everything under /api/v1/; the global download-rate
		// bucket is intentionally not shared here, since the API has its
		// own per-IP auth-failure throttle and role-gated surface.
		mux.Handle(apiPrefix, api.Handler())
	}

	inner := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
		// ErrorLog intentionally left at the standard library default
		// (nil -> log.Default()) rather than routed through slog: the
		// only messages net/http.Server itself logs here are
		// connection-level failures after a response may already be
		// partially written, which is not audit-relevant application
		// data (T1.3 concerns headers/bodies this package renders
		// itself, not the stdlib's own transport diagnostics).
	}

	return &Server{cfg: cfg, handler: handler, logger: logger, inner: inner}
}

// globalRateLimit applies bucket as a hard ceiling across all clients
// combined (SR-125-7), ahead of Handler's own per-IP limiting.
func globalRateLimit(bucket *tokenBucket, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bucket.allow() {
			writeTooManyRequests(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ListenAndServe opens the configured listen address and serves
// requests until ctx is done or the server stops on its own (e.g. a
// listen error). It blocks until the server stops and returns nil on
// a clean shutdown.
//
// The number of concurrent connections is bounded by cfg.MaxConnections
// (SR-125-1/SR-115-2).
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("http: listen on %s: %w", s.cfg.Listen, err)
	}
	s.listener = newLimitListener(ln, s.cfg.MaxConnections)

	s.logger.Info("http: listening", "addr", s.cfg.Listen)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.inner.Serve(s.listener)
	}()

	select {
	case <-ctx.Done():
		return s.Shutdown(context.Background())
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("http: serve: %w", err)
		}
		return nil
	}
}

// Shutdown gracefully stops the server: it stops accepting new
// connections and waits (bounded by cfg.ShutdownTimeout, or ctx if it
// carries an earlier deadline) for in-flight requests to finish before
// forcibly closing any still open.
func (s *Server) Shutdown(ctx context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, s.cfg.ShutdownTimeout)
	defer cancel()

	s.logger.Info("http: shutting down")
	if err := s.inner.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http: shutdown: %w", err)
	}
	return nil
}
