package http

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/store"
)

// apiPrefix is the single versioned mount point for the admin/automation
// REST API (api/openapi.yaml `servers: [{url: /api/v1}]`). Every route
// this handler serves lives under it; a backward-incompatible change
// would move to /api/v2 rather than mutate a shape in place.
const apiPrefix = "/api/v1/"

// APIConfig holds the operator-tunable knobs for the REST API surface
// (US-8.1/T-8.1.2). Zero values are filled in by normalized() with safe
// defaults, so a caller may leave the whole struct empty and still get a
// working, bounded server.
type APIConfig struct {
	// MaxBodyBytes caps the size of any request body a handler will read
	// (SR-130-5). A value <= 0 defaults to defaultAPIMaxBodyBytes.
	MaxBodyBytes int64

	// AuthFailuresPerMinute is the sustained number of authentication
	// failures a single source IP may make before further failures are
	// answered with 429 instead of 401 (SR-130-5, anti-brute-force). A
	// value <= 0 defaults to defaultAuthFailuresPerMinute.
	AuthFailuresPerMinute int

	// AuthFailuresBurst is the burst size for the per-IP auth-failure
	// limiter. A value <= 0 defaults to AuthFailuresPerMinute.
	AuthFailuresBurst int

	// TrustedProxies is the parsed form of internal/config.HTTPConfig.
	// TrustedProxies (see ParseTrustedProxies), the set of reverse-proxy
	// CIDR ranges clientIP trusts to set X-Forwarded-For/X-Real-IP for
	// this API's access log and per-IP auth-failure throttle (ATR-311).
	// nil (the default) means no proxy is trusted: every request's
	// client identity is RemoteAddr, ignoring both headers.
	TrustedProxies []netip.Prefix

	// EvictionMaxEntries bounds the number of distinct client IPs the
	// auth-failure throttle tracks at once (ATR-297): once exceeded, the
	// least-recently-used entries are evicted first, giving a hard
	// ceiling on memory under a distributed brute-force attempt. A value
	// <= 0 defaults to defaultBucketMapMaxEntries.
	EvictionMaxEntries int

	// EvictionTTL evicts an auth-failure throttle entry once it has been
	// idle this long (ATR-297). A value <= 0 defaults to
	// defaultBucketMapTTL.
	EvictionTTL time.Duration

	// MaxConcurrentHeavyRequests bounds how many of the API's
	// unpaginated/full-window-scan endpoints (GET /audit/export, GET
	// /stats/summary, GET /stats/deliverability) may run at once, across
	// every caller combined (ATR-298: a single low-privilege token's
	// blast radius should stay small — ADR-015's rationale for the
	// viewer/auditor roles in the first place). A value <= 0 defaults to
	// defaultMaxConcurrentHeavyRequests.
	MaxConcurrentHeavyRequests int
}

const (
	// defaultAPIMaxBodyBytes bounds request bodies at 1 MiB: the only
	// bodied endpoints in this task carry a tiny JSON token-create
	// request, and the largest body the full contract ever accepts is a
	// policy YAML document, comfortably under this. Resource handlers that
	// need a different cap can raise it via config.
	defaultAPIMaxBodyBytes = 1 << 20

	// defaultAuthFailuresPerMinute / defaultAuthFailuresBurst give a
	// legitimate operator plenty of room for an occasional fat-fingered
	// token while cutting off a brute-force sweep quickly.
	defaultAuthFailuresPerMinute = 10
	defaultAuthFailuresBurst     = 10

	// defaultMaxConcurrentHeavyRequests bounds concurrent audit-export/
	// stats-aggregation requests (ATR-298). internal/core/store/sqlite's
	// reader pool is intentionally left unbounded by database/sql
	// (WAL-mode readers don't block the writer — see
	// internal/core/store/sqlite/conn.go), so nothing else caps how many
	// full-window scans can run in parallel; 4 is a conservative default
	// that still lets a small operator's automation (a dashboard plus an
	// ad hoc export, say) run without contention, while keeping a single
	// token from opening an unbounded number of expensive scans at once.
	defaultMaxConcurrentHeavyRequests = 4
)

// normalized returns a copy of c with defaulted fields filled in.
func (c APIConfig) normalized() APIConfig {
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = defaultAPIMaxBodyBytes
	}
	if c.AuthFailuresPerMinute <= 0 {
		c.AuthFailuresPerMinute = defaultAuthFailuresPerMinute
	}
	if c.AuthFailuresBurst <= 0 {
		c.AuthFailuresBurst = defaultAuthFailuresPerMinute
	}
	if c.EvictionMaxEntries <= 0 {
		c.EvictionMaxEntries = defaultBucketMapMaxEntries
	}
	if c.EvictionTTL <= 0 {
		c.EvictionTTL = defaultBucketMapTTL
	}
	if c.MaxConcurrentHeavyRequests <= 0 {
		c.MaxConcurrentHeavyRequests = defaultMaxConcurrentHeavyRequests
	}
	return c
}

// APIHandler is the /api/v1 admin/automation REST API adapter
// (US-8.1/E8, ATR-196). It depends only on internal/core (the
// store.APITokenStore interface and metrics), never the reverse
// (ADR-002), mirroring the download Handler's dependency direction.
//
// It owns an internal http.ServeMux of resource routes and exposes the
// full middleware-wrapped tree via Handler(), which the download Server
// mounts at apiPrefix. The route table is built so ATR-197..200 add
// their resources by registering more patterns on the same mux — no
// change to the middleware chain, auth, error model or mount wiring.
type APIHandler struct {
	tokens       store.APITokenStore
	metadata     store.MetadataStore
	links        *link.Engine
	policies     *policy.Store
	logger       *slog.Logger
	audit        audit.AuditSink
	auditReader  audit.ReaderLister
	metrics      *metrics.Metrics
	throttle     *authThrottle
	heavyLimiter *heavyRequestLimiter
	cfg          APIConfig

	mux *http.ServeMux
}

// NewAPIHandler constructs an APIHandler. tokens backs both the auth
// middleware's token lookup and the api-tokens management endpoints;
// metadata backs every read-only resource listing/lookup (messages,
// attachments, links) that does not need to go through link.Engine, and
// also backs the recipient-domain deliverability aggregation
// (stats.ComputeDeliverability, ATR-274) via its ListLinks method;
// links is the Link Engine (US-6.1/6.3, ATR-257) that every link
// mutation (revoke, hold, unhold — ATR-197/T-8.1.3) is driven through,
// so its own audit recording (US-7.1) covers API-originated mutations
// exactly like it already covers the CLI (ATR-258). policies is the
// policy Store (US-4.2) the /policies endpoints (get/reload/dry-run —
// ATR-199/T-8.1.5) read and reload; it may be nil, matching
// cmd/attachra's own community-edition passthrough mode (empty
// config.Policy.Path), in which case those three operations answer 500
// (see policies.go's noPolicyConfigured) — POST /policies/validate
// alone needs no Store, since it only parses the submitted document.
// logger receives structured, secret-redacted request and diagnostic
// logs (SR-113-3); sink receives durable, tamper-evident records of
// every API-token lifecycle change (ATR-296, SR-128-2) — a nil sink is
// treated as audit.NopSink{}, mirroring the download Handler's own
// nil-safety, so callers/tests that do not care about the audit trail
// may pass nil; auditReader backs GET /stats/summary (via
// stats.Compute) and the GET /audit, GET /audit/export resources
// (T-8.1.6) — it is typically the same underlying store value passed
// as sink, since MVP's internal/core/store/sqlite implements both
// audit.AuditSink and audit.ReaderLister; m receives the auth-failure
// counter observations and may be nil (metrics methods are nil-safe).
// cfg is normalized in place.
func NewAPIHandler(tokens store.APITokenStore, metadata store.MetadataStore, links *link.Engine, policies *policy.Store, logger *slog.Logger, sink audit.AuditSink, auditReader audit.ReaderLister, m *metrics.Metrics, cfg APIConfig) *APIHandler {
	cfg = cfg.normalized()
	h := &APIHandler{
		tokens:       tokens,
		metadata:     metadata,
		links:        links,
		policies:     policies,
		logger:       logger,
		audit:        auditSinkOrNop(sink),
		auditReader:  auditReader,
		metrics:      m,
		throttle:     newAuthThrottleWithBounds(cfg.AuthFailuresPerMinute, cfg.AuthFailuresBurst, cfg.EvictionMaxEntries, cfg.EvictionTTL),
		heavyLimiter: newHeavyRequestLimiter(cfg.MaxConcurrentHeavyRequests),
		cfg:          cfg,
	}
	h.mux = h.newMux()
	return h
}

// apiRoute pairs one /api/v1 resource pattern with the dispatcher
// function newMux registers it to.
type apiRoute struct {
	pattern string
	handler http.HandlerFunc
}

// routes returns every /api/v1 resource pattern this handler serves
// (excluding the "/" catch-all), each paired with its dispatcher. This
// is the single declarative table newMux registers from — and that a
// route-derived regression test (auditRoleMatrixTest in
// auditrolematrix_test.go) walks to enumerate every resource an
// auditor token must NOT reach (ADR-015: /audit and /audit/export are
// the only two an auditor may reach). Routing a new resource through
// this slice, rather than adding a bare mux.HandleFunc call
// elsewhere, is what keeps that regression test fail-closed: a
// resource added here without an explicit auditor allowance is
// automatically included in the test's negative-access sweep, with no
// second, hand-maintained list of paths that could silently drift out
// of sync with the real route table (the gap a prior version of that
// test had — see its doc comment).
func (h *APIHandler) routes() []apiRoute {
	return []apiRoute{
		{apiPrefix + "api-tokens", h.handleAPITokensCollection},
		{apiPrefix + "api-tokens/{tokenId}", h.handleAPITokenItem},
		{apiPrefix + "messages", h.handleMessagesCollection},
		{apiPrefix + "messages/{messageId}", h.handleMessageItem},
		{apiPrefix + "attachments", h.handleAttachmentsCollection},
		{apiPrefix + "attachments/{attachmentId}", h.handleAttachmentItem},
		{apiPrefix + "links", h.handleLinksCollection},
		{apiPrefix + "links/revoke-by-message", h.handleRevokeByMessage},
		{apiPrefix + "links/revoke-by-sender", h.handleRevokeBySender},
		{apiPrefix + "links/{linkId}", h.handleLinkItem},
		{apiPrefix + "links/{linkId}/revoke", h.handleLinkRevoke},
		{apiPrefix + "links/{linkId}/hold", h.handleLinkHold},
		{apiPrefix + "links/{linkId}/unhold", h.handleLinkUnhold},
		{apiPrefix + "policies/current", h.handlePoliciesCurrent},
		{apiPrefix + "policies/validate", h.handlePoliciesValidate},
		{apiPrefix + "policies/reload", h.handlePoliciesReload},
		{apiPrefix + "policies/dry-run", h.handlePoliciesDryRun},
		{apiPrefix + "stats/summary", h.heavyLimitMiddleware(h.handleStatsSummary)},
		{apiPrefix + "stats/deliverability", h.heavyLimitMiddleware(h.handleStatsDeliverability)},
		{apiPrefix + "audit", h.handleAuditCollection},
		{apiPrefix + "audit/export", h.heavyLimitMiddleware(h.handleAuditExport)},
	}
}

// newMux builds the resource route table from routes(). Patterns are
// registered by path only (not Go 1.22 method patterns), and each
// handler switches on the method itself, so every method mismatch and
// every error renders through this package's single JSON Error
// envelope rather than net/http's default plain-text 404/405 — a
// uniform contract surface. The "/" fallback catches any unknown
// /api/v1 path (the auth middleware still runs first, so an
// unauthenticated probe of an unknown path gets 401, not a 404 that
// would confirm the path space).
func (h *APIHandler) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	for _, rt := range h.routes() {
		mux.HandleFunc(rt.pattern, rt.handler)
	}
	mux.HandleFunc("/", h.handleUnknown)
	return mux
}

// Handler returns the fully wrapped http.Handler to mount at apiPrefix.
// The chain, outermost first: recover (turn any panic into a clean 500),
// log (one redacted access line per request), body-limit (cap the
// readable request body), auth (deny-by-default Bearer authentication),
// then the resource mux (which applies per-endpoint role checks). It also
// wraps the ResponseWriter in a statusWriter once, at the top, so the
// logging and recovery layers can observe the final status.
func (h *APIHandler) Handler() http.Handler {
	chain := h.recoverMiddleware(
		h.logMiddleware(
			h.bodyLimitMiddleware(
				h.authMiddleware(h.mux),
			),
		),
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chain.ServeHTTP(&statusWriter{ResponseWriter: w}, r)
	})
}

// handleUnknown renders the JSON 404 for any /api/v1 path with no
// registered route. It is only reachable after successful authentication
// (the auth middleware runs first), so it does not leak path existence to
// an anonymous caller.
func (h *APIHandler) handleUnknown(w http.ResponseWriter, _ *http.Request) {
	writeAPIError(w, h.logger, http.StatusNotFound, errCodeNotFound, "no resource found for the given identifier")
}

// writeMethodNotAllowed renders the JSON 405 for a known resource path
// reached with an unsupported method, advertising the permitted methods
// in the Allow header per RFC 7231.
func (h *APIHandler) writeMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeAPIError(w, h.logger, http.StatusMethodNotAllowed, errCodeBadRequest, "method not allowed on this resource")
}

// constantTimeHashEqual reports whether two hex-encoded SHA-256 hashes
// are equal in constant time (SR-130-2). Both inputs are non-secret
// hashes of equal length in the expected case, so subtle.ConstantTimeCompare
// — which returns 0 immediately for unequal lengths — is exactly the
// right primitive.
func constantTimeHashEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
