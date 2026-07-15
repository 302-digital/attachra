package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/stats"
)

// TestStatsComputeAgainstRealStore exercises stats.Compute against a
// real *sqlite.Store (rather than a fake audit.Reader), confirming the
// aggregation package works end-to-end through the actual
// StreamEvents/indexed-query implementation (US-7.2/T-7.2.2, ATR-193),
// not just against a hand-rolled test double.
func TestStatsComputeAgainstRealStore(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	day1 := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	outOfWindow := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)

	events := []audit.Event{
		{Type: audit.TypeMessageProcessed, Timestamp: day1, Details: map[string]any{"action": "accept"}},
		{Type: audit.TypeMessageProcessed, Timestamp: day1, Details: map[string]any{"action": "rewrite"}},
		{Type: audit.TypeMessageProcessed, Timestamp: day2, Details: map[string]any{"action": "accept"}},
		{Type: audit.TypePolicyDecision, Timestamp: day1, Details: map[string]any{"action": "replace", "policy_name": "default"}},
		{Type: audit.TypePolicyDecision, Timestamp: day2, Details: map[string]any{"action": "pass", "policy_name": "default"}},
		{Type: audit.TypeDownload, Timestamp: day1, Details: map[string]any{"action": "download"}},
		{Type: audit.TypeDownload, Timestamp: day1, Details: map[string]any{"action": "package_page_view"}},
		{Type: audit.TypeError, Timestamp: day1, Details: map[string]any{"error": "boom"}},
		{Type: audit.TypeMessageProcessed, Timestamp: outOfWindow},
	}
	for _, ev := range events {
		if _, err := st.Record(ctx, ev); err != nil {
			t.Fatalf("Record(%q) error = %v, want nil", ev.Type, err)
		}
	}

	q := stats.Query{
		From: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC),
	}
	summary, err := stats.Compute(ctx, st, q)
	if err != nil {
		t.Fatalf("stats.Compute() error = %v, want nil", err)
	}

	if len(summary.MessagesByDay) != 2 {
		t.Fatalf("MessagesByDay = %+v, want 2 days", summary.MessagesByDay)
	}
	if summary.MessagesByDay[0].Day != "2026-07-01" || summary.MessagesByDay[0].Count != 2 {
		t.Errorf("MessagesByDay[0] = %+v, want {2026-07-01 2}", summary.MessagesByDay[0])
	}
	if summary.MessagesByDay[1].Day != "2026-07-02" || summary.MessagesByDay[1].Count != 1 {
		t.Errorf("MessagesByDay[1] = %+v, want {2026-07-02 1}", summary.MessagesByDay[1])
	}

	if summary.Downloads != 1 {
		t.Errorf("Downloads = %d, want 1 (package_page_view must not count)", summary.Downloads)
	}
	if summary.Errors != 1 {
		t.Errorf("Errors = %d, want 1", summary.Errors)
	}
	if len(summary.PolicyBreakdown) != 1 || summary.PolicyBreakdown[0].Label != "default" || summary.PolicyBreakdown[0].Count != 2 {
		t.Errorf("PolicyBreakdown = %+v, want [{default 2}]", summary.PolicyBreakdown)
	}
}
