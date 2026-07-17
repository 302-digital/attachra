package http

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/302-digital/attachra/internal/adapters/netutil"
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
//
// Server actually binds up to two TCP listeners (ATR-292): the public
// one (cfg.Listen, serving /p/ and, for liveness convenience, /healthz)
// and, when cfg.AdminListen is set, a second admin-only one (GET
// /metrics and the dependency-detailed GET /readyz) — see NewServer's
// doc comment for the full route map and the ATR-292 rationale.
type Server struct {
	cfg     Config
	handler *Handler
	logger  *slog.Logger

	inner    *http.Server
	listener net.Listener

	// adminInner and adminListener are nil when cfg.AdminListen is
	// empty (the admin routes are then folded into inner/mux instead;
	// see NewServer).
	adminInner    *http.Server
	adminListener net.Listener
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
// configures GET /readyz's dependency probes (US-7.2/T-7.2.3, ATR-194).
// Both health routes are served without authentication (SR-130-1).
//
// Route placement (ATR-292): GET /p/ and GET /healthz (liveness — a
// static "ok", no dependency detail, cheap to keep public for existing
// container/orchestrator/`attachra doctor` probes that already target
// cfg.Listen) are always mounted on the public listener (cfg.Listen).
// GET /metrics (build info, Go runtime stats, per-route counters — a
// fingerprinting surface, T1.3-adjacent) and GET /readyz (echoes the
// NAMES of configured dependencies — "database", "storage", "policy" —
// in its response body, SR-130-1's own "no leakage of sensitive
// details" carve-out is about error text, not the dependency list
// itself, but the list is still internal topology) are mounted on the
// separate admin listener (cfg.AdminListen) instead, so a deployment
// that ever exposes cfg.Listen to the internet does not also expose
// them. cfg.AdminListen empty folds /metrics and /readyz onto the
// public listener instead, exactly reproducing this package's
// pre-ATR-292 single-listener behavior — see the AdminListen field's
// own doc comment for who is allowed to actually produce that empty
// value. Whenever that fold happens, NewServer logs it loudly (Warn,
// or Error if cfg.Listen does not look loopback-only) so a deliberate
// hardening downgrade is never silent. GET /healthz is mounted on the
// admin listener too whenever one exists, purely for a monitoring
// agent that only ever talks to the admin surface — it costs nothing
// to duplicate (SR-130-1) and is not the source of truth
// container/orchestrator probes are expected to use.
//
// api, if non-nil, mounts the token-authenticated admin/automation REST
// API (US-8.1/E8, ATR-196) at /api/v1/ with its own middleware chain
// (auth, roles, recovery, logging, throttling); a nil api omits the whole
// subtree, so a deployment (or a test) that does not want the API simply
// passes nil. /api/v1 stays on the public listener (cfg.Listen, outside
// this ticket's scope — SR-130-1's explicit health/download exception
// does not cover it, and it already carries its own Bearer-token auth).
func NewServer(cfg Config, engine *link.Engine, st downloadStore, drv storage.Driver, logger *slog.Logger, sink audit.AuditSink, m *metrics.Metrics, checks []ReadinessCheck, api *APIHandler) *Server {
	cfg = cfg.normalized()
	handler := NewHandler(engine, st, drv, logger, sink, cfg.RateLimit, cfg.TrustedProxies, m)
	health := NewHealthHandler(checks, logger)

	global := newTokenBucket(cfg.RateLimit.GlobalRequestsPerMinute, cfg.RateLimit.GlobalBurst)

	mux := http.NewServeMux()
	mux.Handle("/p/", globalRateLimit(global, handler))
	// /about (ATR-271, Recipient Trust Kit) is a static, unauthenticated
	// page mounted at the server root alongside /p/: it shares the same
	// global rate-limit bucket (SR-125-7) and Handler's per-IP limiter
	// (applied inside serveAbout itself), but is registered as its own
	// exact mux pattern since it is not part of the token/ref path shape
	// parsePackagePath recognizes. It always stays on the public
	// listener, never adminMux, since it is meant to be reachable by
	// anyone who received a suspicious-looking link.
	mux.Handle("/about", globalRateLimit(global, http.HandlerFunc(handler.serveAbout)))
	mux.HandleFunc("/healthz", health.Liveness)
	if api != nil {
		// The API's own middleware chain (recover/log/body-limit/auth/roles)
		// applies to everything under /api/v1/; the global download-rate
		// bucket is intentionally not shared here, since the API has its
		// own per-IP auth-failure throttle and role-gated surface.
		mux.Handle(apiPrefix, api.Handler())
	}

	var adminMux *http.ServeMux
	if cfg.AdminListen != "" {
		adminMux = http.NewServeMux()
		adminMux.HandleFunc("/healthz", health.Liveness)
	} else {
		// No separate admin listener configured: fold the admin routes
		// into the public mux, matching this package's behavior before
		// ATR-292. This is always a deliberate hardening downgrade (see
		// AdminListen's own doc comment for who is allowed to produce
		// this), so it is never silent: log loudly, and escalate to
		// Error if the public listener does not even look loopback-only
		// (in which case /metrics and /readyz may be reachable from
		// outside this host, not just from other processes on it).
		adminMux = mux
		fields := []any{"http_listen", cfg.Listen}
		if isLoopbackAddr(cfg.Listen) {
			logger.Warn("admin.fold_into_http is enabled: /metrics and the dependency-detailed /readyz are served on the public download listener instead of a separate admin listener", fields...)
		} else {
			logger.Error("admin.fold_into_http is enabled AND the public download listener does not look loopback-only: /metrics and the dependency-detailed /readyz may be reachable from outside this host", fields...)
		}
	}
	adminMux.HandleFunc("/readyz", health.Readiness)
	if m != nil {
		adminMux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
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

	srv := &Server{cfg: cfg, handler: handler, logger: logger, inner: inner}

	if cfg.AdminListen != "" {
		srv.adminInner = &http.Server{
			Addr:         cfg.AdminListen,
			Handler:      adminMux,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		}
	}

	return srv
}

// isLoopbackAddr reports whether addr (a "host:port" listen address,
// e.g. cfg.Listen) looks bound to loopback only. It is deliberately
// conservative: anything it cannot positively identify as loopback
// (an unspecified/wildcard host like "0.0.0.0"/"::"/"", an
// unparsable/hostname host) is reported as NOT loopback, so the
// ATR-292 fold-warning above favors escalating to Error over silently
// staying at Warn.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
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

// ListenAndServe opens the configured listen address(es) and serves
// requests until ctx is done or the public server stops on its own
// (e.g. a listen error). It blocks until the public server has stopped
// and returns nil on a clean shutdown.
//
// The number of concurrent connections is bounded by cfg.MaxConnections
// (SR-125-1/SR-115-2) on each listener independently (a separate
// counter per listener, not a shared budget); the admin listener (when
// configured, ATR-292) reuses the same configured ceiling — it is a
// lower-traffic, operator/monitoring-only surface, not a reason to add
// a second tunable.
//
// Admin listener failure is never fatal (ATR-292 security review,
// resolving a specific either/or: never leave the process in a state
// where it looks alive but has silently stopped serving mail-adjacent
// traffic). Milter and the /p/ download surface are both load-bearing
// for actual mail delivery (a rewritten message's links point at /p/);
// /metrics and /readyz are pure observability, consumed by something
// OUTSIDE the mail path (a scraper/prober), and per the
// mail-must-never-be-lost invariant, a bind conflict on a monitoring
// port must never cascade
// into stopping — or refusing to start — anything mail-adjacent. So:
// if the admin listener fails to bind, or its Serve call later returns
// an unexpected error, this is logged at Error level and the public
// listener (and the whole process) keeps running with the admin
// surface simply unavailable until the operator frees the port/fixes
// admin.listen and restarts. The public listener's own failure remains
// fatal, unchanged from the pre-ATR-292 contract: it is core
// functionality, not an optional surface.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("http: listen on %s: %w", s.cfg.Listen, err)
	}
	s.listener = netutil.NewLimitListener(ln, s.cfg.MaxConnections, 0)

	s.logger.Info("http: listening", "addr", s.cfg.Listen)

	publicErrCh := make(chan error, 1)
	go func() { publicErrCh <- namedServeErr("http", s.inner.Serve(s.listener)) }()

	if s.adminInner != nil {
		adminLn, err := net.Listen("tcp", s.cfg.AdminListen)
		if err != nil {
			s.logger.Error("http: admin listener failed to bind — /metrics and /readyz are unavailable, the public listener is unaffected",
				"addr", s.cfg.AdminListen, "error", err.Error())
		} else {
			s.adminListener = netutil.NewLimitListener(adminLn, s.cfg.MaxConnections, 0)
			s.logger.Info("http: admin listening", "addr", s.cfg.AdminListen)

			go func() {
				if err := namedServeErr("http-admin", s.adminInner.Serve(s.adminListener)); err != nil {
					s.logger.Error("http: admin listener stopped unexpectedly — /metrics and /readyz are unavailable, the public listener is unaffected", "error", err.Error())
				}
			}()
		}
	}

	select {
	case <-ctx.Done():
		return s.Shutdown(context.Background())
	case err := <-publicErrCh:
		if err != nil {
			// The public listener is core functionality (serves /p/ and
			// /healthz); its failure is fatal for the whole adapter,
			// matching the pre-ATR-292 single-server contract. Shut down
			// the admin server too (best-effort) before surfacing the
			// error, so ListenAndServe never returns with a listener
			// left open.
			_ = s.Shutdown(context.Background())
			return err
		}
		return nil
	}
}

// namedServeErr wraps a http.Server.Serve result with a component name
// prefix, ignoring the expected http.ErrServerClosed sentinel from a
// clean Shutdown (mirroring the previous single-server behavior).
func namedServeErr(name string, err error) error {
	if err == nil || err == http.ErrServerClosed {
		return nil
	}
	return fmt.Errorf("%s: serve: %w", name, err)
}

// Shutdown gracefully stops both servers: it stops accepting new
// connections and waits (bounded by cfg.ShutdownTimeout, or ctx if it
// carries an earlier deadline) for in-flight requests to finish before
// forcibly closing any still open. Shutting down the admin server (when
// configured) is best-effort alongside the public one — both errors are
// reported if both fail.
func (s *Server) Shutdown(ctx context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, s.cfg.ShutdownTimeout)
	defer cancel()

	s.logger.Info("http: shutting down")

	err := s.inner.Shutdown(shutdownCtx)
	if err != nil {
		err = fmt.Errorf("http: shutdown: %w", err)
	}

	if s.adminInner != nil {
		if adminErr := s.adminInner.Shutdown(shutdownCtx); adminErr != nil {
			adminErr = fmt.Errorf("http-admin: shutdown: %w", adminErr)
			if err == nil {
				err = adminErr
			} else {
				err = fmt.Errorf("%w; %w", err, adminErr)
			}
		}
	}

	return err
}
