// Package metrics defines Attachra's Prometheus instrumentation
// (US-7.2/T-7.2.1, ATR-192): counters and histograms for messages
// processed, attachment policy decisions, downloads and errors,
// exposed by internal/adapters/http's /metrics endpoint via
// promhttp.HandlerFor(Metrics.Registry, ...).
//
// This package depends only on github.com/prometheus/client_golang's
// metrics primitives (Counter/Histogram/Registry), never on any
// adapter-specific package (ADR-002): the HTTP exposition format is
// wired up by internal/adapters/http, not here.
//
// Every label used below is a small, closed set of enum-like values
// (a verdict/action/stage name) chosen specifically to avoid ever
// exposing mail content or recipient/sender identity as a metric
// label or value (T-7.2.1 acceptance criterion "no leakage of
// sensitive data in labels"): unlike audit.Event.Details, a
// Prometheus label is not access-controlled or redacted by this
// package, so nothing derived from message content (filenames,
// addresses, tokens, error text) may ever be passed as a label value.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// namespace prefixes every metric name this package registers, per
// Prometheus naming convention (<namespace>_<subsystem>_<name>).
const namespace = "attachra"

// Metrics bundles every Prometheus collector Attachra's core exposes.
// The zero value is not usable; construct with New. A nil *Metrics is
// valid everywhere Observe* methods are called (they are nil-safe),
// so callers that do not want metrics (most existing unit tests) can
// simply leave a Metrics field unset.
type Metrics struct {
	// Registry is the Prometheus registry every collector below is
	// registered against. internal/adapters/http mounts
	// promhttp.HandlerFor(Registry, ...) at /metrics.
	Registry *prometheus.Registry

	// MessagesProcessed counts every message.pipeline.AttachmentProcessor.Process
	// call by its terminal result: "accept", "rewrite", "reject",
	// "tempfail", or "error" (a Process call that returned a non-nil
	// error instead of a Verdict).
	MessagesProcessed *prometheus.CounterVec

	// AttachmentsDecided counts every attachment the policy engine
	// evaluated, by decided action: "pass", "replace", or "block"
	// (policy.Action's three values), plus protective-downgrade labels
	// recorded in addition to (not instead of) that same attachment's
	// "pass" observation: "inline_protected" (ADR-016,
	// pipeline.protectInlineAssets — a presentation-inline asset under
	// the configured size, downgraded from replace to pass),
	// "inline_protected_unverified" (a subset of "inline_protected":
	// the asset's cid: reference could not be verified — its text/html
	// body was truncated beyond the scan bound or unreadable — so it was
	// protected on ADR-016 phase-1 grounds alone; ATR-307, threat-model
	// T2.8) and "body_protected" (pipeline.protectStructuralBodies — the
	// message's own text/plain or text/html body, downgraded from
	// replace to pass; ATR-306).
	AttachmentsDecided *prometheus.CounterVec

	// PolicyDecisions counts every message-level policy decision, by
	// action and whether dry-run suppressed enforcement.
	PolicyDecisions *prometheus.CounterVec

	// Downloads counts every download attempt served by the download
	// adapter's /p/<token>/d/<ref> endpoint, by outcome: "success" or
	// "denied" (not-found/expired/revoked/exhausted/error, folded into
	// one label per SR-125-5's generic-denial posture).
	Downloads *prometheus.CounterVec

	// Errors counts processing failures by stage: "pipeline" (any
	// pipeline.AttachmentProcessor.Process error), "milter_fail_open"
	// and "milter_fail_closed" (the milter adapter's configured
	// failure-mode resolution, SR-116-1).
	Errors *prometheus.CounterVec

	// MessageProcessingSeconds observes pipeline.AttachmentProcessor.Process's
	// wall-clock duration, by terminal result (same label values as
	// MessagesProcessed).
	MessageProcessingSeconds *prometheus.HistogramVec

	// RetentionCleanups counts every attachment the background
	// retention sweep (internal/core/retention, US-5.3/ATR-179) has
	// processed, by outcome: "deleted" (object + metadata removed),
	// "held_skipped" (expired but excluded because a link on it is
	// under legal hold, ATR-259), or "error" (storage/metadata deletion
	// failed for that attachment; the sweep continues with the rest).
	// The total number of attachments a sweep pass scanned is the sum
	// across all three labels — a separate "scanned" counter would only
	// double the same count under a different name (ATR-295).
	RetentionCleanups *prometheus.CounterVec

	// RetentionExpiredLinks counts every Link row the background
	// retention sweep (internal/core/retention, US-5.3/ATR-179) marks
	// LinkStatusExpired via its ExpireStaleLinks step, each sweep pass
	// (ATR-295). This is a distinct bookkeeping population from
	// RetentionCleanups: a link can and typically does expire (its own
	// ExpiresAt elapses) well before its underlying attachment's
	// separate RetainUntil deadline is reached, so it is not derivable
	// from RetentionCleanups' outcome counts.
	RetentionExpiredLinks prometheus.Counter

	// AuditEventsTruncated counts audit-log events removed by the
	// background retention sweep's checkpoint truncation (ATR-308,
	// ADR-017). It stays at zero while audit retention is disabled (the
	// default). No labels: truncation has a single outcome (events
	// removed), and the accompanying checkpoint audit event carries the
	// detailed accounting (anchor seq/hash, cutoff, held-clamped).
	AuditEventsTruncated prometheus.Counter

	// APIAuthFailures counts every REST API request rejected by the
	// auth middleware (US-8.1/T-8.1.2, ATR-196), by reason:
	// "missing_bearer" (no or malformed Authorization: Bearer header),
	// "invalid_token" (a Bearer that matched no active token), or
	// "throttled" (rejected with 429 because the source IP exceeded the
	// repeated-auth-failure budget, SR-130-5's rate limit on auth
	// failures). The reason label is a small closed set and never carries
	// any part of the presented token or client-supplied content.
	APIAuthFailures *prometheus.CounterVec
}

// New creates a Metrics value with a fresh, private Registry and every
// collector registered against it, ready to record observations and to
// be exposed via promhttp.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		Registry: reg,
		MessagesProcessed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "messages_processed_total",
			Help:      "Total number of messages processed by the attachment pipeline, by terminal result.",
		}, []string{"result"}),
		AttachmentsDecided: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "attachments_decided_total",
			Help:      "Total number of attachments evaluated by the policy engine, by decided action.",
		}, []string{"action"}),
		PolicyDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "policy_decisions_total",
			Help:      "Total number of message-level policy decisions, by action and dry-run status.",
		}, []string{"action", "dry_run"}),
		Downloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "downloads_total",
			Help:      "Total number of download attempts served, by outcome.",
		}, []string{"result"}),
		Errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "errors_total",
			Help:      "Total number of processing errors, by stage.",
		}, []string{"stage"}),
		MessageProcessingSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "message_processing_duration_seconds",
			Help:      "Duration of pipeline message processing, by terminal result.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"result"}),
		RetentionCleanups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "retention_cleanups_total",
			Help:      "Total number of attachments processed by the background retention sweep, by outcome.",
		}, []string{"result"}),
		RetentionExpiredLinks: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "retention_expired_links_total",
			Help:      "Total number of link rows marked expired by the background retention sweep.",
		}),
		AuditEventsTruncated: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "audit_events_truncated_total",
			Help:      "Total number of audit-log events removed by retention checkpoint truncation (0 while audit retention is disabled).",
		}),
		APIAuthFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "api_auth_failures_total",
			Help:      "Total number of REST API requests rejected by the auth middleware, by reason.",
		}, []string{"reason"}),
	}

	reg.MustRegister(
		m.MessagesProcessed,
		m.AttachmentsDecided,
		m.PolicyDecisions,
		m.Downloads,
		m.Errors,
		m.MessageProcessingSeconds,
		m.RetentionCleanups,
		m.RetentionExpiredLinks,
		m.AuditEventsTruncated,
		m.APIAuthFailures,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return m
}

// ObserveMessage records one pipeline.AttachmentProcessor.Process
// call's terminal result and duration. result must be one of "accept",
// "rewrite", "reject", "tempfail", or "error".
func (m *Metrics) ObserveMessage(result string, dur time.Duration) {
	if m == nil {
		return
	}
	m.MessagesProcessed.WithLabelValues(result).Inc()
	m.MessageProcessingSeconds.WithLabelValues(result).Observe(dur.Seconds())
}

// ObserveAttachmentAction records one attachment's decided policy
// action ("pass", "replace", or "block").
func (m *Metrics) ObserveAttachmentAction(action string) {
	if m == nil {
		return
	}
	m.AttachmentsDecided.WithLabelValues(action).Inc()
}

// ObservePolicyDecision records one message-level policy decision.
func (m *Metrics) ObservePolicyDecision(action string, dryRun bool) {
	if m == nil {
		return
	}
	m.PolicyDecisions.WithLabelValues(action, boolLabel(dryRun)).Inc()
}

// ObserveDownload records one download attempt's outcome ("success" or
// "denied").
func (m *Metrics) ObserveDownload(result string) {
	if m == nil {
		return
	}
	m.Downloads.WithLabelValues(result).Inc()
}

// ObserveError records one processing failure at the given stage (see
// the Errors field's doc comment for the recognized stage values).
func (m *Metrics) ObserveError(stage string) {
	if m == nil {
		return
	}
	m.Errors.WithLabelValues(stage).Inc()
}

// ObserveRetentionCleanup records one attachment processed by the
// background retention sweep, by outcome (see the RetentionCleanups
// field's doc comment for the recognized result values).
func (m *Metrics) ObserveRetentionCleanup(result string) {
	if m == nil {
		return
	}
	m.RetentionCleanups.WithLabelValues(result).Inc()
}

// ObserveRetentionExpiredLinks adds n to the count of link rows marked
// expired by one Sweep call's ExpireStaleLinks step (see the
// RetentionExpiredLinks field's doc comment). n may be 0, a harmless
// no-op Add: callers are not required to skip the call when nothing
// was expired.
func (m *Metrics) ObserveRetentionExpiredLinks(n int) {
	if m == nil {
		return
	}
	m.RetentionExpiredLinks.Add(float64(n))
}

// ObserveAuditTruncation records that one audit checkpoint truncation
// removed n events (ATR-308, ADR-017). n <= 0 is a no-op, so a pass that
// truncated nothing does not perturb the counter.
func (m *Metrics) ObserveAuditTruncation(n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.AuditEventsTruncated.Add(float64(n))
}

// ObserveAPIAuthFailure records one REST API request rejected by the
// auth middleware, by reason (see the APIAuthFailures field's doc
// comment for the recognized reason values). It is nil-safe like every
// other Observe* method, so the HTTP adapter can call it unconditionally.
func (m *Metrics) ObserveAPIAuthFailure(reason string) {
	if m == nil {
		return
	}
	m.APIAuthFailures.WithLabelValues(reason).Inc()
}

// boolLabel renders b as the Prometheus label convention "true"/"false"
// string, matching how other Attachra-adjacent tooling stringifies
// boolean labels.
func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
