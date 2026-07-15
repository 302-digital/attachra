package http

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/storage"
	"github.com/302-digital/attachra/internal/core/store"
)

// downloadStore is the subset of store.MetadataStore the handler needs
// directly (beyond what it reaches through link.Engine), namely
// resolving an attachment's display metadata for the package page.
// Declaring it narrowly here (rather than depending on the whole
// store.MetadataStore interface) keeps the handler's dependency
// surface honest about what it actually calls.
type downloadStore interface {
	GetAttachment(ctx context.Context, id string) (store.Attachment, error)
}

// Handler implements the two-step package-page download flow (US-6.2)
// as an http.Handler, routing GET /p/<token> and POST
// /p/<token>/d/<link-id> itself (see ServeHTTP) rather than depending
// on a specific mux implementation, since the routing here is only two
// fixed patterns. <link-id> is the store-assigned, non-secret Link.ID
// (see internal/core/link.Engine.RegisterPackageDownload's doc comment
// for why this — not a second bearer token — is the correct and safe
// path segment: the package token already is the authorization).
type Handler struct {
	engine  *link.Engine
	store   downloadStore
	storage storage.Driver
	logger  *slog.Logger
	audit   audit.AuditSink
	metrics *metrics.Metrics

	limiter *perIPLimiter
	tarpit  RateLimitConfig

	trustedProxies []netip.Prefix
}

// NewHandler constructs a Handler. engine resolves and registers
// downloads against tokens; st resolves attachment display metadata;
// drv streams object bytes; logger receives structured audit/log
// output; sink receives the same events durably as append-only
// audit.Event records (US-7.1, ATR-190) — a nil sink is treated as
// audit.NopSink{}, so callers/tests that do not care about the audit
// trail may pass nil; rl configures the per-IP/global rate limiting
// and tarpit behavior (SR-125-7). rl's global limiting is applied by
// the caller via NewServer, not by Handler itself, so Handler can be
// exercised directly in tests without a global limiter in the way.
// trusted configures which reverse-proxy CIDR ranges clientIP honors
// X-Forwarded-For/X-Real-IP from (ATR-311); nil (the default) means no
// proxy is trusted, matching the pre-ATR-311 behavior. m receives
// Prometheus observations for downloads served (US-7.2/T-7.2.1,
// ATR-192) — a nil m is valid (metrics.Metrics methods are nil-safe).
func NewHandler(engine *link.Engine, st downloadStore, drv storage.Driver, logger *slog.Logger, sink audit.AuditSink, rl RateLimitConfig, trusted []netip.Prefix, m *metrics.Metrics) *Handler {
	return &Handler{
		engine:         engine,
		store:          st,
		storage:        drv,
		logger:         logger,
		audit:          auditSinkOrNop(sink),
		metrics:        m,
		limiter:        newPerIPLimiter(rl.PerIPRequestsPerMinute, rl.PerIPBurst, rl.NotFoundPerIPPerMinute),
		tarpit:         rl,
		trustedProxies: trusted,
	}
}

// ServeHTTP dispatches to the package page or download handler based
// on the request path, applying the per-IP rate limit first (SR-125-7)
// to every request this Handler serves.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r, h.trustedProxies)
	if !h.limiter.allowRequest(ip) {
		writeTooManyRequests(w)
		return
	}

	token, ref, ok := parsePackagePath(r.URL.Path)
	if !ok {
		h.notFound(w, r, "route", "", "unrecognized path")
		return
	}

	switch {
	case r.Method == http.MethodGet && ref == "":
		h.servePackagePage(w, r, token)
	case r.Method == http.MethodPost && ref != "":
		h.serveDownload(w, r, token, ref)
	case ref == "":
		w.Header().Set("Allow", http.MethodGet)
		h.notFound(w, r, "route", token, "method not allowed on package page: "+r.Method)
	default:
		w.Header().Set("Allow", http.MethodPost)
		h.notFound(w, r, "route", token, "method not allowed on download: "+r.Method)
	}
}

// notFound applies the tarpit/backoff check (SR-125-7) before
// rendering the single generic error response (SR-125-5).
func (h *Handler) notFound(w http.ResponseWriter, r *http.Request, action, token, reason string) {
	ip := clientIP(r, h.trustedProxies)
	if !h.limiter.allowNotFound(ip) && h.tarpit.TarpitDelay > 0 {
		tarpitSleep(h.tarpit.TarpitDelay)
	}
	writeNotFound(w, r, h.logger, h.audit, h.trustedProxies, action, token, reason)
}

// resolvePackage resolves token to its MessageLink, folding every
// negative outcome (not found, expired, revoked) into the generic
// not-found response per SR-125-5; ok is false if the caller should
// stop (the response has already been written).
func (h *Handler) resolvePackage(w http.ResponseWriter, r *http.Request, token string) (mlMessageID string, ok bool) {
	ml, err := h.engine.ResolvePackage(r.Context(), token)
	if err != nil {
		reason := "package link resolve failed"
		if !errors.Is(err, link.ErrNotFound) {
			reason = "package link resolve error: " + err.Error()
		}
		h.notFound(w, r, "package_page_view", token, reason)
		return "", false
	}
	return ml.MessageID, true
}
