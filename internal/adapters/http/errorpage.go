package http

import (
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/302-digital/attachra/internal/core/audit"
)

// genericNotFoundStatus is the single HTTP status code returned for
// every negative outcome on this adapter's routes (SR-125-5): token
// never existed, expired, revoked, or download-limit exhausted are all
// indistinguishable to the caller. 404 is used uniformly (rather than
// mixing 404/410/429) so a response code itself cannot be used as an
// oracle to tell "never existed" apart from "gone".
const genericNotFoundStatus = http.StatusNotFound

// writeNotFound renders the single generic error page and status code
// used for every "not found/expired/revoked/exhausted" outcome
// (SR-125-5, T1.1, T1.3). reason is never sent to the client — it
// exists only for the audit log line this function writes, via
// logger, so operators can still tell these cases apart internally.
func writeNotFound(w http.ResponseWriter, r *http.Request, logger *slog.Logger, sink audit.AuditSink, trusted []netip.Prefix, action, token, reason string) {
	recordAudit(r.Context(), sink, logger, auditEvent{
		Action:    action,
		Token:     token,
		Reason:    reason,
		RemoteIP:  clientIP(r, trusted),
		UserAgent: truncateUserAgent(r.UserAgent()),
	})

	setPageSecurityHeaders(w)
	w.WriteHeader(genericNotFoundStatus)
	// Best-effort render: the status code and headers are already
	// committed, so a write failure here (client disconnected) has no
	// further remedy and is not itself a security-relevant condition.
	_ = errorPageTemplate.Execute(w, nil)
}

// writeTooManyRequests renders a minimal, static rate-limit response
// (SR-125-7). It reuses the anti-cache headers but not the full page
// template, since no per-request content is needed and keeping it
// separate makes the rate-limit path allocate as little as possible
// under load.
func writeTooManyRequests(w http.ResponseWriter) {
	setAntiCacheHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte("too many requests\n"))
}

// maxUserAgentLogLen bounds how much of a request's User-Agent header
// is retained in audit/log output, guarding against a maliciously
// oversized header inflating log storage (the header itself is capped
// far earlier by net/http's own header-size limits, but this keeps log
// lines bounded independent of that).
const maxUserAgentLogLen = 256

func truncateUserAgent(ua string) string {
	if len(ua) > maxUserAgentLogLen {
		return ua[:maxUserAgentLogLen]
	}
	return ua
}
