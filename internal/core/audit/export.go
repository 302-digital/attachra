package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Filter selects which recorded events ExportJSONL includes. A zero
// value (all fields empty/zero) matches every event. From/To are
// inclusive-from, exclusive-to bounds on Recorded.Timestamp, matching
// common log-export conventions; either may be left zero to leave that
// bound open.
type Filter struct {
	From time.Time
	To   time.Time
	Type Type // Empty matches every Type.
}

// Reader is the read side of the audit log, separate from AuditSink's
// write side so producers (which only need Record) do not have to
// depend on export/query methods, and so the export path's dependency
// surface is explicit. Implementations live alongside their AuditSink
// counterpart (MVP: internal/core/store/sqlite).
type Reader interface {
	// StreamEvents calls fn once per Recorded event matching filter, in
	// ascending Seq order, stopping and returning fn's error immediately
	// if fn returns one. Implementations must not buffer the full
	// result set in memory (CLAUDE.md invariant #4): each row is
	// streamed from the underlying store as it is scanned. Used by
	// ExportJSONL (unbounded, filter-only) and by
	// internal/core/stats.Compute.
	StreamEvents(ctx context.Context, filter Filter, fn func(Recorded) error) error
}

// ReaderLister extends Reader with bounded, cursor-paginated listing
// (US-8.1/T-8.1.6, api/openapi.yaml `GET /audit`). It is a separate,
// wider interface — rather than adding ListEvents to Reader directly —
// so that consumers needing only StreamEvents (ExportJSONL,
// internal/core/stats.Compute, and every existing test fake for
// either) are unaffected by this addition; only a consumer that
// specifically needs the paginated list view (the REST API's audit
// list handler) depends on the wider interface. Implementations live
// alongside their Reader/AuditSink counterpart (MVP:
// internal/core/store/sqlite).
type ReaderLister interface {
	Reader

	// ListEvents returns one page of events matching p, in ascending
	// Seq order, paginated via p.Limit/p.Cursor (SR-130-5's mandatory
	// pagination and response-size limit on the audit list resource).
	// Unlike StreamEvents, this method is meant for a bounded,
	// client-paged view, not a full unbounded export. An invalid
	// p.Cursor returns an error wrapping ErrInvalidCursor so the HTTP
	// layer can answer 400, not 500.
	ListEvents(ctx context.Context, p ListParams) (Page, error)
}

// jsonlRecord is the exact on-the-wire shape of one exported line: a
// flat, stable JSON object independent of the in-memory Recorded/Event
// struct layout, so a future refactor of those types does not silently
// change the export format consumed by external SIEM/log tooling
// (SR-128-3).
type jsonlRecord struct {
	ID        string          `json:"id"`
	Seq       int64           `json:"seq"`
	PrevHash  string          `json:"prev_hash"`
	Timestamp string          `json:"timestamp"` // RFC3339Nano UTC.
	Type      Type            `json:"type"`
	Actor     string          `json:"actor,omitempty"`
	MessageID string          `json:"message_id,omitempty"`
	Recipient string          `json:"recipient,omitempty"`
	Details   json.RawMessage `json:"details,omitempty"`
}

// ExportJSONL streams every event matching filter to w as JSON Lines
// (one compact JSON object per line, newline-terminated), in ascending
// Seq order, for ingestion into an external immutable
// store/SIEM (SR-128-3). It never buffers the full result set: each
// row read from src is encoded and written before the next is
// fetched, so export scales independently of memory (CLAUDE.md
// invariant #4).
//
// ExportJSONL returns the first error encountered from either src or
// from writing to w. A partial write to w may already have occurred
// when an error is returned; callers exporting to a file should treat
// a non-nil error as "discard/truncate the output", not "resume from
// here".
func ExportJSONL(ctx context.Context, src Reader, w io.Writer, filter Filter) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)

	err := src.StreamEvents(ctx, filter, func(rec Recorded) error {
		details, err := json.Marshal(rec.Details)
		if err != nil {
			return fmt.Errorf("audit: export: marshal details for event %q: %w", rec.ID, err)
		}

		line := jsonlRecord{
			ID:        rec.ID,
			Seq:       rec.Seq,
			PrevHash:  rec.PrevHash,
			Timestamp: rec.Timestamp.UTC().Format(time.RFC3339Nano),
			Type:      rec.Type,
			Actor:     rec.Actor,
			MessageID: rec.MessageID,
			Recipient: rec.Recipient,
			Details:   details,
		}
		if err := enc.Encode(line); err != nil {
			return fmt.Errorf("audit: export: encode event %q: %w", rec.ID, err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("audit: export: %w", err)
	}

	if err := bw.Flush(); err != nil {
		return fmt.Errorf("audit: export: flush: %w", err)
	}
	return nil
}
