package http

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
)

// statusWriter wraps an http.ResponseWriter to capture the status code
// and whether a response has been committed, so the logging and recovery
// middleware can observe the outcome and recovery can tell "nothing
// written yet" (safe to emit a 500 envelope) from "response already
// started" (must not).
type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.written {
		w.status = status
		w.written = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.written {
		// A handler that writes a body without an explicit WriteHeader
		// implies 200, matching net/http's own behavior.
		w.status = http.StatusOK
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

// reqLogFields is a mutable, per-request holder the auth middleware
// populates and the logging middleware reads. It exists because the
// logging middleware sits outside auth in the chain and so cannot see the
// principal auth installs on the (inner) request context directly; a
// shared pointer lets auth annotate the access log line with the
// authenticated token's non-secret identity without the logger ever
// touching the Authorization header or the secret itself (SR-113-3).
type reqLogFields struct {
	tokenID string
	role    string
}

type reqLogKey struct{}

func reqLogFieldsFrom(ctx context.Context) *reqLogFields {
	lf, _ := ctx.Value(reqLogKey{}).(*reqLogFields)
	return lf
}

// recoverMiddleware is the outermost middleware: it converts any panic
// in a downstream middleware or handler into a generic 500 JSON error,
// logging the recovered value server-side but never returning it to the
// client (SR-130-1/SR-130-5: recovery without leaking the stack or any
// internal detail). If a response was already partly written when the
// panic happened, it cannot safely emit a new status line, so it only
// logs.
func (h *APIHandler) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw, ok := w.(*statusWriter)
		defer func() {
			if rec := recover(); rec != nil {
				// Log the recovered value (and let the runtime's own stack
				// capture surface in the log if the deployment enables it),
				// but never send it to the client.
				h.logger.Error("api: recovered from panic",
					"method", r.Method,
					"path", r.URL.Path,
					"panic", rec,
				)
				if ok && sw.written {
					return
				}
				writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// logMiddleware records one structured access-log line per request after
// the response completes. It logs only safe, bounded fields — method,
// request path (never the raw query string, which could carry filter
// values), status, duration, client IP, truncated User-Agent, and, when
// the request authenticated, the token's non-secret ID and role — and
// never the Authorization header or any token secret (SR-113-3). Every
// value is passed as a structured attribute, never concatenated into the
// message text (SR-113-3/SR-128-2 logging-injection guard).
func (h *APIHandler) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lf := &reqLogFields{}
		r = r.WithContext(context.WithValue(r.Context(), reqLogKey{}, lf))

		sw, ok := w.(*statusWriter)
		next.ServeHTTP(w, r)

		status := 0
		if ok {
			status = sw.status
		}
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_ip", clientIP(r, h.cfg.TrustedProxies),
			"user_agent", truncateUserAgent(r.UserAgent()),
		}
		if lf.tokenID != "" {
			attrs = append(attrs, "token_id", lf.tokenID, "role", lf.role)
		}
		h.logger.Info("api request", attrs...)
	})
}

// bodyLimitMiddleware caps the request body every downstream handler may
// read (SR-130-5's mandatory request-size limit) by wrapping r.Body in an
// http.MaxBytesReader. A handler that reads past the cap gets a
// *http.MaxBytesError, which the JSON-decoding handlers translate into a
// 413 payload_too_large; endpoints with no body (GET/DELETE) are
// unaffected.
func (h *APIHandler) bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && h.cfg.MaxBodyBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// bearerPrefix is the case-sensitive scheme token an Authorization header
// must start with. Bearer is the only accepted scheme (SR-130-2: tokens
// are never read from a query parameter or any other location).
const bearerPrefix = "Bearer "

// authMiddleware enforces deny-by-default authentication on every
// /api/v1 request (SR-130-1): a request with no valid Bearer token never
// reaches a handler. On success it installs the authenticated principal
// on the request context and records the token's non-secret identity for
// the access log; on failure it answers a generic 401 (or 429 once the
// source IP has exhausted its repeated-failure budget, SR-130-5) and
// never reveals which of "no header", "malformed", "unknown token" or
// "revoked token" occurred.
func (h *APIHandler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, ok := bearerSecret(r)
		if !ok {
			h.rejectAuth(w, r, "missing_bearer")
			return
		}

		tok, err := h.tokens.LookupActiveAPIToken(r.Context(), store.HashAPISecret(secret))
		if err != nil {
			// Every lookup failure — unknown hash or revoked token (the
			// store folds both into ErrNotFound) — is one indistinguishable
			// 401. A non-ErrNotFound error is a genuine store failure; it
			// is still resolved to 401 (never leaking the store error to
			// the client) but logged as an internal condition.
			if !errors.Is(err, store.ErrNotFound) {
				h.logger.Error("api: token lookup failed", "error", err.Error())
			}
			h.rejectAuth(w, r, "invalid_token")
			return
		}

		// Defense-in-depth constant-time comparison (SR-130-2): the SQL
		// lookup above is already an indexed equality on the hash (no
		// linear scan, no timing oracle from the query), but comparing the
		// returned hash against the recomputed one with crypto/subtle
		// guards against any future change to the lookup that might not be,
		// and makes the constant-time requirement explicit at the call
		// site.
		if !constantTimeHashEqual(tok.TokenHash, store.HashAPISecret(secret)) {
			h.rejectAuth(w, r, "invalid_token")
			return
		}

		h.recordAuthSuccess(r, tok)

		ctx := withPrincipal(r.Context(), principal{TokenID: tok.ID, Name: tok.Name, Role: tok.Role})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// rejectAuth answers a failed authentication. It charges the source IP's
// repeated-failure budget: while the budget holds it returns a generic
// 401, and once exhausted it returns 429 rate_limited to slow a
// brute-force sweep (SR-130-5). reason is a closed-set label for the
// auth-failure metric only — never returned to the client.
func (h *APIHandler) rejectAuth(w http.ResponseWriter, r *http.Request, reason string) {
	ip := clientIP(r, h.cfg.TrustedProxies)
	if !h.throttle.failAllowed(ip) {
		h.metrics.ObserveAPIAuthFailure("throttled")
		h.logger.Warn("api: auth failures throttled", "remote_ip", ip)
		w.Header().Set("Retry-After", "60")
		writeAPIError(w, h.logger, http.StatusTooManyRequests, errCodeRateLimited, "too many requests, slow down")
		return
	}

	h.metrics.ObserveAPIAuthFailure(reason)
	h.logger.Warn("api: authentication failed", "reason", reason, "remote_ip", ip)
	writeAPIError(w, h.logger, http.StatusUnauthorized, errCodeUnauthorized, "missing or invalid bearer token")
}

// recordAuthSuccess annotates the access log with the authenticated
// token's non-secret identity and best-effort updates its last_used_at.
// The touch is throttled (only issued when the recorded last_used_at is
// older than authTouchInterval, or never set) so a busy client does not
// serialize a write through the single-writer pool on every request, and
// its failure is logged but never blocks the request.
func (h *APIHandler) recordAuthSuccess(r *http.Request, tok store.APIToken) {
	if lf := reqLogFieldsFrom(r.Context()); lf != nil {
		lf.tokenID = tok.ID
		lf.role = string(tok.Role)
	}

	now := time.Now().UTC()
	if tok.LastUsedAt.IsZero() || now.Sub(tok.LastUsedAt) >= authTouchInterval {
		if err := h.tokens.TouchAPIToken(r.Context(), tok.ID, now.Format(time.RFC3339Nano)); err != nil {
			h.logger.Warn("api: failed to update token last_used_at", "token_id", tok.ID, "error", err.Error())
		}
	}
}

// authTouchInterval bounds how often a token's last_used_at is rewritten
// (see recordAuthSuccess): last_used_at is coarse observability, not an
// audit record, so minute-granularity is ample and keeps the hot path
// from issuing a write per request.
const authTouchInterval = time.Minute

// bearerSecret extracts the raw secret from an Authorization: Bearer
// header, or ok=false if the header is absent or not a well-formed Bearer
// credential. The token is accepted only from this header, never from a
// query parameter or any other location (SR-130-2).
func bearerSecret(r *http.Request) (secret string, ok bool) {
	h := r.Header.Get("Authorization")
	if h == "" || !strings.HasPrefix(h, bearerPrefix) {
		return "", false
	}
	secret = strings.TrimSpace(h[len(bearerPrefix):])
	if secret == "" {
		return "", false
	}
	return secret, true
}

// authorize enforces an endpoint's x-required-role set (SR-130-3): it
// returns the authenticated principal when its role is in allowed, and
// otherwise writes the appropriate error (401 if — impossibly, behind
// the auth middleware — no principal is present; 403 if the role is not
// permitted) and returns ok=false. Handlers call it at the top of every
// operation so the role check is per-endpoint, not assumed from mount
// position.
func (h *APIHandler) authorize(w http.ResponseWriter, r *http.Request, allowed ...store.Role) (principal, bool) {
	p, ok := principalFrom(r.Context())
	if !ok {
		// Reaching a handler without a principal means the auth middleware
		// was bypassed — a wiring bug, not a client condition. Fail closed.
		h.logger.Error("api: handler reached without an authenticated principal", "path", r.URL.Path)
		writeAPIError(w, h.logger, http.StatusUnauthorized, errCodeUnauthorized, "missing or invalid bearer token")
		return principal{}, false
	}
	for _, role := range allowed {
		if p.Role == role {
			return p, true
		}
	}
	writeAPIError(w, h.logger, http.StatusForbidden, errCodeForbidden, "this token's role is not permitted to perform this action")
	return principal{}, false
}
