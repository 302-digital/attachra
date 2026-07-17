// Package stats computes aggregated statistics over the audit log and
// link table for API/UI consumption: message volume by day, policy
// decisions by action and by policy name, download counts (US-7.2/
// T-7.2.2, ATR-193), and link/download counts grouped by recipient
// domain (ATR-231/ATR-273/ATR-274).
//
// This package depends only on internal/core interfaces — audit.Reader
// (StreamEvents) for Compute, and a narrow LinkSource view of
// store.MetadataStore (ListLinks) for ComputeDeliverability — never on
// a concrete store or driver package (ADR-002, ADR-011): both work
// identically against any implementation, MVP's
// internal/core/store/sqlite today and a future Postgres-backed store
// (v0.2) without any change here, since the portable, indexed queries
// they rely on (StreamEvents' WHERE type = ? AND created_at >= ? AND
// created_at < ?, backed by idx_audit_events_type and
// idx_audit_events_created_at; ListLinks' equivalent created_at range
// scan over the links table) already live in that implementation.
// Aggregating per-event JSON Details fields (policy name, decided
// action) is done here, in Go, specifically to avoid dialect-specific
// JSON-extraction SQL (SQLite's json_extract vs. Postgres' ->>
// operator), keeping the underlying query itself dialect-neutral.
//
// Compute streams every matching event exactly once and
// ComputeDeliverability pages through every matching link exactly once
// (the streaming invariant): each function's running totals are bounded
// by the number of distinct days/actions/policy names/domains in the
// window, never by the number of events or links themselves.
package stats

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
)

// dayLayout is the UTC calendar-day bucket key used by MessagesByDay,
// e.g. "2026-07-09".
const dayLayout = "2006-01-02"

// Query bounds one statistics request to a specific, explicit time
// window. Both fields are required: an unbounded query (the entire
// audit log's history) would take time proportional to the log's full
// size, which is exactly the "limits on selection size" constraint
// T-7.2.2's acceptance criteria calls for, enforced here at the core
// layer even before an API surface (T-8.1.6) exists to add its own
// pagination on top.
type Query struct {
	// From is the inclusive lower bound (matches audit.Filter.From).
	From time.Time
	// To is the exclusive upper bound (matches audit.Filter.To).
	To time.Time
}

// validate returns an error if q is not a well-formed, bounded query.
func (q Query) validate() error {
	if q.From.IsZero() || q.To.IsZero() {
		return fmt.Errorf("stats: query: From and To must both be set")
	}
	if !q.To.After(q.From) {
		return fmt.Errorf("stats: query: To (%s) must be after From (%s)", q.To, q.From)
	}
	return nil
}

// DailyCount is the number of TypeMessageProcessed events recorded on
// one UTC calendar day.
type DailyCount struct {
	Day   string // YYYY-MM-DD, UTC.
	Count int64
}

// LabeledCount is a generic (label, count) pair used for the action and
// policy breakdowns below.
type LabeledCount struct {
	Label string
	Count int64
}

// Summary is the full aggregated statistics payload for one Query
// window (US-7.2/T-7.2.2).
type Summary struct {
	Query Query

	// MessagesByDay is the count of TypeMessageProcessed events per UTC
	// calendar day, in ascending Day order.
	MessagesByDay []DailyCount

	// ActionBreakdown is the count of TypePolicyDecision events per
	// decided message-level action (policy.ActionPass/Replace/Block's
	// string form), in descending Count order (ties broken by Label,
	// ascending, for deterministic output).
	ActionBreakdown []LabeledCount

	// PolicyBreakdown is the count of TypePolicyDecision events per
	// policy name, in the same ordering as ActionBreakdown.
	PolicyBreakdown []LabeledCount

	// Downloads is the number of successful download completions in
	// the window: TypeDownload events whose Details["action"] ==
	// "download" (excluding package-page views, which share the same
	// audit.Type — see internal/adapters/http's auditType doc comment
	// — and excluding denied/error outcomes, which are recorded as
	// TypeError, not TypeDownload).
	Downloads int64

	// Errors is the number of TypeError events in the window (any
	// processing failure: parse, policy, storage, link, rewrite, or a
	// denied/expired/revoked/not-found download or package-page
	// request).
	Errors int64
}

// Compute streams every event in q's window from src exactly once via
// audit.Reader.StreamEvents, aggregating counts into small,
// label-cardinality-bounded running totals (the streaming invariant:
// the full set of matching events is never held in memory at once).
func Compute(ctx context.Context, src audit.Reader, q Query) (Summary, error) {
	if err := q.validate(); err != nil {
		return Summary{}, err
	}

	byDay := map[string]int64{}
	byAction := map[string]int64{}
	byPolicy := map[string]int64{}
	var downloads, errs int64

	filter := audit.Filter{From: q.From, To: q.To}
	err := src.StreamEvents(ctx, filter, func(rec audit.Recorded) error {
		switch rec.Type {
		case audit.TypeMessageProcessed:
			byDay[rec.Timestamp.UTC().Format(dayLayout)]++
		case audit.TypePolicyDecision:
			if action, ok := stringDetail(rec.Details, "action"); ok {
				byAction[action]++
			}
			if policyName, ok := stringDetail(rec.Details, "policy_name"); ok {
				byPolicy[policyName]++
			}
		case audit.TypeDownload:
			if action, ok := stringDetail(rec.Details, "action"); ok && action == "download" {
				downloads++
			}
		case audit.TypeError:
			errs++
		}
		return nil
	})
	if err != nil {
		return Summary{}, fmt.Errorf("stats: compute: %w", err)
	}

	return Summary{
		Query:           q,
		MessagesByDay:   sortedDaily(byDay),
		ActionBreakdown: sortedLabeled(byAction),
		PolicyBreakdown: sortedLabeled(byPolicy),
		Downloads:       downloads,
		Errors:          errs,
	}, nil
}

// stringDetail returns details[key] as a string, and whether it was
// present and non-empty. Event.Details is a map[string]any decoded
// from JSON (internal/core/audit.Event's doc comment), so a field
// recorded as a Go string comes back as a string after the
// json.Unmarshal round-trip every audit.Reader implementation performs.
func stringDetail(details map[string]any, key string) (string, bool) {
	v, ok := details[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// sortedDaily returns m's entries as a slice sorted by ascending Day,
// for deterministic output.
func sortedDaily(m map[string]int64) []DailyCount {
	out := make([]DailyCount, 0, len(m))
	for day, count := range m {
		out = append(out, DailyCount{Day: day, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day < out[j].Day })
	return out
}

// sortedLabeled returns m's entries sorted by descending Count, ties
// broken by ascending Label, for deterministic output.
func sortedLabeled(m map[string]int64) []LabeledCount {
	out := make([]LabeledCount, 0, len(m))
	for label, count := range m {
		out = append(out, LabeledCount{Label: label, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})
	return out
}
