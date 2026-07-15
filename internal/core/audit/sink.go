package audit

import "context"

// AuditSink is the domain interface every audit-event producer
// (pipeline, download adapter, link engine callers) depends on.
// Implementations live under internal/core/store/<driver> (MVP:
// sqlite, alongside store.MetadataStore) and must never depend on any
// adapter-specific package (ADR-002). Core code must depend only on
// this interface, never on a concrete store implementation.
//
// AuditSink is append-only by contract: no method in this interface
// updates or deletes a previously recorded Event. Implementations must
// not expose such an operation even internally reachable from this
// package (SR-128-1).
//
// All methods must be safe for concurrent use by multiple goroutines.
//
// The name AuditSink stutters as audit.AuditSink, but it is the exact
// name docs/security/requirements-for-backlog.md (ATR-128) and this
// task's brief use throughout; keeping it matches the project's own
// vocabulary for this interface rather than diverging from the
// specified name to satisfy the linter.
//
//nolint:revive
type AuditSink interface {
	// Record durably appends ev to the audit log, assigning it a Seq
	// and PrevHash (SR-128-1) and returning the fully populated
	// Recorded row. If ev.Timestamp is the zero value, Record stamps
	// the current UTC time.
	//
	// Record must treat every field of ev as a parameterized value,
	// never format it into a query string (SR-128-2): Actor,
	// MessageID, Recipient and Details in particular may originate
	// from mail content or other untrusted input.
	Record(ctx context.Context, ev Event) (Recorded, error)
}

// NopSink is an AuditSink that discards every event without an error.
// It exists for callers that are not yet wired to a real sink (tests,
// or an operator who has not configured one) so audit call sites do
// not need a nil check at every call (SR-128-2 call sites always have
// a non-nil sink to call).
type NopSink struct{}

var _ AuditSink = NopSink{}

// Record implements AuditSink by discarding ev.
func (NopSink) Record(_ context.Context, ev Event) (Recorded, error) {
	return Recorded{Event: ev}, nil
}
