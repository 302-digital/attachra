package sqlite_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
)

// TestAuditRecordAllTypes exercises Record with every recognized
// audit.Type, asserting each round-trips through StreamEvents with its
// content intact.
func TestAuditRecordAllTypes(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	types := []audit.Type{
		audit.TypeMessageProcessed,
		audit.TypePolicyDecision,
		audit.TypeAttachmentStored,
		audit.TypeLinksCreated,
		audit.TypeDownload,
		audit.TypeRevoke,
		audit.TypeError,
	}

	for _, typ := range types {
		rec, err := st.Record(ctx, audit.Event{
			Type:      typ,
			Actor:     "test",
			MessageID: "msg-1",
			Recipient: "user@example.com",
			Details:   map[string]any{"type": string(typ)},
		})
		if err != nil {
			t.Fatalf("Record(%q) error = %v, want nil", typ, err)
		}
		if rec.ID == "" {
			t.Errorf("Record(%q).ID is empty, want non-empty", typ)
		}
		if rec.Seq <= 0 {
			t.Errorf("Record(%q).Seq = %d, want > 0", typ, rec.Seq)
		}
	}

	var got []audit.Recorded
	if err := st.StreamEvents(ctx, audit.Filter{}, func(r audit.Recorded) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	if len(got) != len(types) {
		t.Fatalf("StreamEvents() returned %d events, want %d", len(got), len(types))
	}
	for i, typ := range types {
		if got[i].Type != typ {
			t.Errorf("event %d Type = %q, want %q", i, got[i].Type, typ)
		}
		if got[i].Details["type"] != string(typ) {
			t.Errorf("event %d Details[type] = %v, want %q", i, got[i].Details["type"], typ)
		}
	}
}

// TestAuditRecordUntrustedValuesAreNotInjected exercises the SR-128-2
// requirement that untrusted values (recipient, details containing
// SQL-meaningful characters) are stored verbatim as data, never able to
// alter query structure or corrupt subsequent rows.
func TestAuditRecordUntrustedValuesAreNotInjected(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	maliciousRecipient := `attacker@example.com'); DROP TABLE audit_events; --`
	maliciousDetail := `"; DROP TABLE audit_events; --`

	if _, err := st.Record(ctx, audit.Event{
		Type:      audit.TypeError,
		Actor:     "test",
		Recipient: maliciousRecipient,
		Details:   map[string]any{"error": maliciousDetail},
	}); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}

	var got []audit.Recorded
	if err := st.StreamEvents(ctx, audit.Filter{}, func(r audit.Recorded) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil (table must survive)", err)
	}
	if len(got) != 1 {
		t.Fatalf("StreamEvents() returned %d events, want 1", len(got))
	}
	if got[0].Recipient != maliciousRecipient {
		t.Errorf("Recipient = %q, want %q stored verbatim", got[0].Recipient, maliciousRecipient)
	}
	if got[0].Details["error"] != maliciousDetail {
		t.Errorf("Details[error] = %v, want %q stored verbatim", got[0].Details["error"], maliciousDetail)
	}
}

// TestAuditChainConsistency asserts that each recorded event's PrevHash
// matches the previous event's own computed hash, and that Seq is
// strictly increasing by 1 — the tamper-evidence hook SR-128-1
// requires be structurally present, even though full verification
// tooling is out of scope for this task.
func TestAuditChainConsistency(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	const n = 5
	recs := make([]audit.Recorded, n)
	for i := 0; i < n; i++ {
		rec, err := st.Record(ctx, audit.Event{Type: audit.TypeError, Actor: "test"})
		if err != nil {
			t.Fatalf("Record() #%d error = %v, want nil", i, err)
		}
		recs[i] = rec
	}

	if recs[0].PrevHash != "" {
		t.Errorf("first record PrevHash = %q, want empty (no predecessor)", recs[0].PrevHash)
	}
	for i := 1; i < n; i++ {
		if recs[i].Seq != recs[i-1].Seq+1 {
			t.Errorf("record %d Seq = %d, want %d (previous + 1)", i, recs[i].Seq, recs[i-1].Seq+1)
		}
		if recs[i].PrevHash == "" {
			t.Errorf("record %d PrevHash is empty, want a non-empty hash of its predecessor", i)
		}
	}

	// Every non-first record's PrevHash must be distinct: each depends
	// on its own predecessor's unique id/seq/timestamp, so a collision
	// here would indicate the hash is not actually chaining on
	// per-row content (e.g. a constant or seq-independent hash).
	seen := make(map[string]bool)
	for i := 1; i < n; i++ {
		if seen[recs[i].PrevHash] {
			t.Errorf("record %d PrevHash %q duplicates an earlier record's PrevHash, want each derived from a distinct predecessor", i, recs[i].PrevHash)
		}
		seen[recs[i].PrevHash] = true
	}

	// Read back via StreamEvents and confirm the persisted prev_hash
	// values are exactly what Record returned (i.e. Recorded.PrevHash
	// is not synthesized only in memory; it is what actually got
	// durably stored).
	var got []audit.Recorded
	if err := st.StreamEvents(ctx, audit.Filter{}, func(r audit.Recorded) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	if len(got) != n {
		t.Fatalf("StreamEvents() returned %d, want %d", len(got), n)
	}
	for i := 0; i < n; i++ {
		if got[i].PrevHash != recs[i].PrevHash {
			t.Errorf("stored record %d PrevHash = %q, want %q (as returned by Record)", i, got[i].PrevHash, recs[i].PrevHash)
		}
	}
}

// TestAuditRecordConcurrentSeqIsStrictlyOrdered hammers Record from many
// goroutines at once and asserts every assigned Seq is unique and forms
// a contiguous 1..N range: the single-writer serialization ADR-011
// mandates must make concurrent seq assignment race-free (run with
// -race; critical counters must be race-safe).
func TestAuditRecordConcurrentSeqIsStrictlyOrdered(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	const n = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	seqs := make(map[int64]bool)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, err := st.Record(ctx, audit.Event{Type: audit.TypeError, Actor: "concurrent"})
			if err != nil {
				t.Errorf("Record() error = %v, want nil", err)
				return
			}
			mu.Lock()
			seqs[rec.Seq] = true
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(seqs) != n {
		t.Fatalf("got %d distinct seq values, want %d (no duplicates/collisions)", len(seqs), n)
	}
	for i := int64(1); i <= int64(n); i++ {
		if !seqs[i] {
			t.Errorf("seq %d missing from assigned set, want contiguous 1..%d", i, n)
		}
	}
}

// TestAuditStreamEventsFilters exercises StreamEvents' From/To/Type
// filter combination.
func TestAuditStreamEventsFilters(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	past := time.Now().Add(-1 * time.Hour).UTC()
	present := time.Now().UTC()
	future := time.Now().Add(1 * time.Hour).UTC()

	mustRecord := func(typ audit.Type, ts time.Time) {
		t.Helper()
		if _, err := st.Record(ctx, audit.Event{Type: typ, Timestamp: ts, Actor: "test"}); err != nil {
			t.Fatalf("Record(%q) error = %v, want nil", typ, err)
		}
	}

	mustRecord(audit.TypeDownload, past)
	mustRecord(audit.TypeRevoke, present)
	mustRecord(audit.TypeDownload, future)

	var got []audit.Recorded
	filter := audit.Filter{Type: audit.TypeDownload, From: past.Add(-time.Minute), To: present.Add(time.Minute)}
	if err := st.StreamEvents(ctx, filter, func(r audit.Recorded) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	if len(got) != 1 {
		t.Fatalf("StreamEvents() with filter returned %d events, want 1: %+v", len(got), got)
	}
	if got[0].Type != audit.TypeDownload {
		t.Errorf("filtered event Type = %q, want %q", got[0].Type, audit.TypeDownload)
	}
}

// TestAuditExportJSONLIntegration exercises audit.ExportJSONL end to
// end against the real sqlite Reader implementation.
func TestAuditExportJSONLIntegration(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := st.Record(ctx, audit.Event{
			Type:      audit.TypeDownload,
			Actor:     "test",
			MessageID: "msg-export",
			Details:   map[string]any{"i": i},
		}); err != nil {
			t.Fatalf("Record() #%d error = %v, want nil", i, err)
		}
	}

	var buf countingWriter
	if err := audit.ExportJSONL(ctx, st, &buf, audit.Filter{}); err != nil {
		t.Fatalf("ExportJSONL() error = %v, want nil", err)
	}
	if buf.lines != 3 {
		t.Errorf("exported %d lines, want 3", buf.lines)
	}
}

// countingWriter counts newline-terminated lines written to it,
// avoiding a dependency on bufio.Scanner in this test file.
type countingWriter struct {
	lines int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			c.lines++
		}
	}
	return len(p), nil
}

// TestAuditListEventsPagination exercises ListEvents' keyset pagination
// over seq (US-8.1/T-8.1.6): it walks every page via NextCursor and
// asserts the concatenated result is every recorded event, in
// ascending seq order, with no gaps or duplicates.
func TestAuditListEventsPagination(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	const n = 12
	var want []audit.Recorded
	for i := 0; i < n; i++ {
		rec, err := st.Record(ctx, audit.Event{Type: audit.TypeError, Actor: "test"})
		if err != nil {
			t.Fatalf("Record() #%d error = %v, want nil", i, err)
		}
		want = append(want, rec)
	}

	var got []audit.Recorded
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > n {
			t.Fatalf("ListEvents() did not terminate after %d pages", pages)
		}
		page, err := st.ListEvents(ctx, audit.ListParams{Limit: 5, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListEvents() error = %v, want nil", err)
		}
		got = append(got, page.Events...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if len(got) != n {
		t.Fatalf("ListEvents() paged %d events total, want %d", len(got), n)
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].Seq != want[i].Seq {
			t.Errorf("event %d = (id=%s, seq=%d), want (id=%s, seq=%d)", i, got[i].ID, got[i].Seq, want[i].ID, want[i].Seq)
		}
	}
}

// TestAuditListEventsFilters exercises ListEvents' From/To/Type/
// MessageID filter combination (api/openapi.yaml `GET /audit`).
func TestAuditListEventsFilters(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	past := time.Now().Add(-1 * time.Hour).UTC()
	present := time.Now().UTC()
	future := time.Now().Add(1 * time.Hour).UTC()

	mustRecord := func(typ audit.Type, ts time.Time, messageID string) {
		t.Helper()
		if _, err := st.Record(ctx, audit.Event{Type: typ, Timestamp: ts, Actor: "test", MessageID: messageID}); err != nil {
			t.Fatalf("Record(%q) error = %v, want nil", typ, err)
		}
	}

	mustRecord(audit.TypeDownload, past, "msg-a")
	mustRecord(audit.TypeRevoke, present, "msg-a")
	mustRecord(audit.TypeDownload, future, "msg-b")

	page, err := st.ListEvents(ctx, audit.ListParams{
		Type: audit.TypeDownload,
		From: past.Add(-time.Minute),
		To:   present.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("ListEvents() error = %v, want nil", err)
	}
	if len(page.Events) != 1 || page.Events[0].Type != audit.TypeDownload {
		t.Fatalf("ListEvents() with type/time filter = %+v, want exactly one download event", page.Events)
	}

	page, err = st.ListEvents(ctx, audit.ListParams{MessageID: "msg-b"})
	if err != nil {
		t.Fatalf("ListEvents() error = %v, want nil", err)
	}
	if len(page.Events) != 1 || page.Events[0].MessageID != "msg-b" {
		t.Fatalf("ListEvents() with message_id filter = %+v, want exactly one msg-b event", page.Events)
	}
}

// TestAuditListEventsInvalidCursor asserts a malformed cursor is
// reported as audit.ErrInvalidCursor (400 at the HTTP layer), never a
// generic query failure.
func TestAuditListEventsInvalidCursor(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	_, err := st.ListEvents(ctx, audit.ListParams{Cursor: "not-a-valid-cursor!!"})
	if !errors.Is(err, audit.ErrInvalidCursor) {
		t.Errorf("ListEvents() error = %v, want wrapping audit.ErrInvalidCursor", err)
	}
}
