package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
)

// downloadAdapterActor identifies this adapter as the Actor for every
// audit event it records (US-7.1, ATR-190), distinguishing it from the
// pipeline's "milter" actor and from API-originated events.
const downloadAdapterActor = "download-adapter"

// auditEvent is a single download-adapter occurrence recorded for
// operational/audit purposes (T-6.2.3, ATR-190). It is written both to
// the structured logger (for local operational visibility) and, via
// recordAudit, to the configured audit.AuditSink (the append-only,
// exportable log, US-7.1).
type auditEvent struct {
	Action    string // "package_page_view", "download", "download_denied"
	Token     string // opaque token identifier for correlation, never the raw bearer token
	MessageID string // the store.Message.ID this event relates to, if already known (empty before token resolution)
	Reason    string // populated only for denied/error outcomes; never sent to the client (SR-125-5)
	RemoteIP  string
	UserAgent string
	At        time.Time
}

// auditType maps this adapter's Action/denied-reason combination to an
// audit.Type: every denied outcome (Reason != "", covering
// expired/revoked/not-found/rate-limit across every route this adapter
// serves) is TypeError, matching how pipeline.AttachmentProcessor uses
// TypeError for its own failure paths. A successful outcome — either
// "download" or the read-only "package_page_view" (see
// servePackagePage's doc comment) — is recorded as TypeDownload:
// audit.Type's small, stable enum has no dedicated Type for a
// page-view, so the distinction between the two successful actions is
// carried in Details.action rather than by growing a Type per adapter
// route.
func auditType(denied bool) audit.Type {
	if denied {
		return audit.TypeError
	}
	return audit.TypeDownload
}

// recordAudit writes ev to logger at info level (or warn, for denied
// outcomes), using structured fields so no attacker-controlled value
// (RemoteIP is validated by net.SplitHostPort/reasonable UA truncation
// is applied by the caller) is concatenated into the message text
// (SR-113-3, T2.3-style logging injection guard). It also appends ev
// to sink (US-7.1, ATR-190) as a TypeDownload event carrying the same
// fields in Details; every value derived from the request (token
// reference, remote IP, user agent, reason) is placed in Details as
// data, never formatted into a query or log message template
// (SR-128-2).
//
// Recording to sink is best-effort: a failure to append the audit
// event is logged but never changes the HTTP response already decided
// by the caller (the mail-must-never-be-lost invariant extends here —
// a download or page view must not be blocked or altered by an
// audit-sink outage).
func recordAudit(ctx context.Context, sink audit.AuditSink, logger *slog.Logger, ev auditEvent) {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}

	attrs := []any{
		"action", ev.Action,
		"token_ref", tokenRef(ev.Token),
		"remote_ip", ev.RemoteIP,
		"user_agent", ev.UserAgent,
		"at", ev.At.Format(time.RFC3339Nano),
	}
	if ev.Reason != "" {
		attrs = append(attrs, "reason", ev.Reason)
		logger.Warn("download adapter event", attrs...)
	} else {
		logger.Info("download adapter event", attrs...)
	}

	details := map[string]any{
		"action":     ev.Action,
		"token_ref":  tokenRef(ev.Token),
		"remote_ip":  ev.RemoteIP,
		"user_agent": ev.UserAgent,
	}
	if ev.Reason != "" {
		details["reason"] = ev.Reason
	}

	if _, err := auditSinkOrNop(sink).Record(ctx, audit.Event{
		Timestamp: ev.At,
		Type:      auditType(ev.Reason != ""),
		Actor:     downloadAdapterActor,
		MessageID: ev.MessageID,
		Details:   details,
	}); err != nil {
		logger.Warn("http: failed to record audit event", "action", ev.Action, "error", err.Error())
	}
}

// auditSinkOrNop returns sink, or audit.NopSink{} if sink is nil, so
// call sites (and Handler/Server construction in tests that omit an
// AuditSink) never need their own nil check.
func auditSinkOrNop(sink audit.AuditSink) audit.AuditSink {
	if sink != nil {
		return sink
	}
	return audit.NopSink{}
}

// tokenRef returns a short, non-reversible reference to token suitable
// for correlating log lines without logging (or letting an operator
// reconstruct) the bearer secret itself: the same HashToken value
// already computed for lookup, truncated further for log brevity. This
// is deliberately not the full SHA-256 hash used for storage lookups,
// to avoid encouraging copy-paste reuse of a log line as a lookup key.
func tokenRef(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	h := hex.EncodeToString(sum[:])
	const refLen = 12
	if len(h) > refLen {
		h = h[:refLen]
	}
	return h
}
