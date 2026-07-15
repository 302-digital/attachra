package stats_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/stats"
)

// fakeReader is a minimal in-memory audit.Reader for unit-testing
// stats.Compute's aggregation logic without a real store: it filters
// and streams a fixed slice of audit.Recorded exactly the way a real
// implementation (internal/core/store/sqlite) is documented to (see
// audit.Reader's own doc comment), so Compute cannot tell the
// difference.
type fakeReader struct {
	events []audit.Recorded
}

func (f *fakeReader) StreamEvents(_ context.Context, filter audit.Filter, fn func(audit.Recorded) error) error {
	for _, rec := range f.events {
		if !filter.From.IsZero() && rec.Timestamp.Before(filter.From) {
			continue
		}
		if !filter.To.IsZero() && !rec.Timestamp.Before(filter.To) {
			continue
		}
		if filter.Type != "" && rec.Type != filter.Type {
			continue
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return nil
}

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("time.Parse(%q) error = %v, want nil", s, err)
	}
	return ts
}

func TestComputeAggregatesAcrossEventTypes(t *testing.T) {
	src := &fakeReader{events: []audit.Recorded{
		{Event: audit.Event{
			Type: audit.TypeMessageProcessed, Timestamp: mustParse(t, "2026-07-01T10:00:00Z"),
		}},
		{Event: audit.Event{
			Type: audit.TypeMessageProcessed, Timestamp: mustParse(t, "2026-07-01T11:00:00Z"),
		}},
		{Event: audit.Event{
			Type: audit.TypeMessageProcessed, Timestamp: mustParse(t, "2026-07-02T09:00:00Z"),
		}},
		{Event: audit.Event{
			Type: audit.TypePolicyDecision, Timestamp: mustParse(t, "2026-07-01T10:00:00Z"),
			Details: map[string]any{"action": "replace", "policy_name": "default"},
		}},
		{Event: audit.Event{
			Type: audit.TypePolicyDecision, Timestamp: mustParse(t, "2026-07-01T11:00:00Z"),
			Details: map[string]any{"action": "pass", "policy_name": "default"},
		}},
		{Event: audit.Event{
			Type: audit.TypePolicyDecision, Timestamp: mustParse(t, "2026-07-02T09:00:00Z"),
			Details: map[string]any{"action": "replace", "policy_name": "strict"},
		}},
		{Event: audit.Event{
			Type: audit.TypeDownload, Timestamp: mustParse(t, "2026-07-01T12:00:00Z"),
			Details: map[string]any{"action": "download"},
		}},
		{Event: audit.Event{
			// Package-page view: same Type, different Details.action —
			// must not count toward Downloads (see auditType's doc
			// comment in internal/adapters/http).
			Type: audit.TypeDownload, Timestamp: mustParse(t, "2026-07-01T12:05:00Z"),
			Details: map[string]any{"action": "package_page_view"},
		}},
		{Event: audit.Event{
			Type: audit.TypeError, Timestamp: mustParse(t, "2026-07-01T13:00:00Z"),
		}},
		{Event: audit.Event{
			// Outside the query window: must be excluded from every
			// aggregate below.
			Type: audit.TypeMessageProcessed, Timestamp: mustParse(t, "2026-06-01T00:00:00Z"),
		}},
	}}

	q := stats.Query{
		From: mustParse(t, "2026-07-01T00:00:00Z"),
		To:   mustParse(t, "2026-07-03T00:00:00Z"),
	}

	got, err := stats.Compute(context.Background(), src, q)
	if err != nil {
		t.Fatalf("Compute() error = %v, want nil", err)
	}

	wantDaily := []stats.DailyCount{
		{Day: "2026-07-01", Count: 2},
		{Day: "2026-07-02", Count: 1},
	}
	if !equalDaily(got.MessagesByDay, wantDaily) {
		t.Errorf("MessagesByDay = %+v, want %+v", got.MessagesByDay, wantDaily)
	}

	wantAction := []stats.LabeledCount{
		{Label: "replace", Count: 2},
		{Label: "pass", Count: 1},
	}
	if !equalLabeled(got.ActionBreakdown, wantAction) {
		t.Errorf("ActionBreakdown = %+v, want %+v", got.ActionBreakdown, wantAction)
	}

	wantPolicy := []stats.LabeledCount{
		{Label: "default", Count: 2},
		{Label: "strict", Count: 1},
	}
	if !equalLabeled(got.PolicyBreakdown, wantPolicy) {
		t.Errorf("PolicyBreakdown = %+v, want %+v", got.PolicyBreakdown, wantPolicy)
	}

	if got.Downloads != 1 {
		t.Errorf("Downloads = %d, want 1", got.Downloads)
	}
	if got.Errors != 1 {
		t.Errorf("Errors = %d, want 1", got.Errors)
	}
}

func TestComputeEmptyWindow(t *testing.T) {
	src := &fakeReader{}
	q := stats.Query{
		From: mustParse(t, "2026-07-01T00:00:00Z"),
		To:   mustParse(t, "2026-07-02T00:00:00Z"),
	}

	got, err := stats.Compute(context.Background(), src, q)
	if err != nil {
		t.Fatalf("Compute() error = %v, want nil", err)
	}
	if len(got.MessagesByDay) != 0 || len(got.ActionBreakdown) != 0 || len(got.PolicyBreakdown) != 0 {
		t.Errorf("Compute() on empty log = %+v, want all aggregates empty", got)
	}
	if got.Downloads != 0 || got.Errors != 0 {
		t.Errorf("Compute() on empty log: Downloads=%d Errors=%d, want 0/0", got.Downloads, got.Errors)
	}
}

func TestComputeRejectsUnboundedQuery(t *testing.T) {
	src := &fakeReader{}

	tests := []struct {
		name string
		q    stats.Query
	}{
		{"zero From", stats.Query{To: mustParse(t, "2026-07-02T00:00:00Z")}},
		{"zero To", stats.Query{From: mustParse(t, "2026-07-01T00:00:00Z")}},
		{"zero both", stats.Query{}},
		{"To before From", stats.Query{
			From: mustParse(t, "2026-07-02T00:00:00Z"),
			To:   mustParse(t, "2026-07-01T00:00:00Z"),
		}},
		{"To equal From", stats.Query{
			From: mustParse(t, "2026-07-01T00:00:00Z"),
			To:   mustParse(t, "2026-07-01T00:00:00Z"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := stats.Compute(context.Background(), src, tt.q); err == nil {
				t.Error("Compute() error = nil, want non-nil for an unbounded/invalid query")
			}
		})
	}
}

// erroringReader returns a fixed error from StreamEvents, used to
// verify Compute propagates a Reader failure instead of masking it.
type erroringReader struct{ err error }

func (e erroringReader) StreamEvents(_ context.Context, _ audit.Filter, _ func(audit.Recorded) error) error {
	return e.err
}

func TestComputePropagatesReaderError(t *testing.T) {
	wantErr := errors.New("boom")
	q := stats.Query{
		From: mustParse(t, "2026-07-01T00:00:00Z"),
		To:   mustParse(t, "2026-07-02T00:00:00Z"),
	}

	_, err := stats.Compute(context.Background(), erroringReader{err: wantErr}, q)
	if !errors.Is(err, wantErr) {
		t.Errorf("Compute() error = %v, want it to wrap %v", err, wantErr)
	}
}

func equalDaily(got, want []stats.DailyCount) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func equalLabeled(got, want []stats.LabeledCount) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
