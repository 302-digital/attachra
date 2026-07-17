package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store"
)

// This file is an internal (package sqlite) test so it can reach store
// internals (s.db.writer) to simulate direct tampering while
// independently recomputing the audit hash chain via audit.HashRecord,
// the same canonical hash the ATR-240 verifier uses (ADR-017).

// openInternalStore opens a fresh migrated Store in a temp dir. It is the
// internal-package twin of store_test.go's openTestStore (which lives in
// package sqlite_test and is therefore not visible here).
func openInternalStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attachra-audit-retention.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q) error = %v, want nil", path, err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Store.Close() error = %v, want nil", err)
		}
	})
	return st
}

// recomputeHash re-derives one recorded row's chain hash exactly as the
// store did at write time, from the row's own fields, so a test can walk
// the chain and confirm each row's PrevHash matches its predecessor. It
// delegates to audit.HashRecord — the single canonical hash the store's
// write path and the ATR-240 verifier both use.
func recomputeHash(t *testing.T, rec audit.Recorded) string {
	t.Helper()
	h, err := audit.HashRecord(rec)
	if err != nil {
		t.Fatalf("audit.HashRecord() error = %v, want nil", err)
	}
	return h
}

// verifyChain walks rows (ascending seq) confirming each row's PrevHash
// equals the recomputed hash of its predecessor. The first row's PrevHash
// must equal wantFirstPrev (either "" for a genesis-anchored segment, or
// the trusted anchor hash for a post-truncation survivor set).
func verifyChain(t *testing.T, rows []audit.Recorded, wantFirstPrev string) {
	t.Helper()
	if len(rows) == 0 {
		t.Fatalf("verifyChain: no rows to verify")
	}
	if rows[0].PrevHash != wantFirstPrev {
		t.Fatalf("first row (seq %d) PrevHash = %q, want %q", rows[0].Seq, rows[0].PrevHash, wantFirstPrev)
	}
	for i := 1; i < len(rows); i++ {
		want := recomputeHash(t, rows[i-1])
		if rows[i].PrevHash != want {
			t.Fatalf("chain broken at seq %d: PrevHash = %q, want recompute(seq %d) = %q",
				rows[i].Seq, rows[i].PrevHash, rows[i-1].Seq, want)
		}
	}
}

// streamAll collects every event in ascending seq order.
func streamAll(t *testing.T, st *Store) []audit.Recorded {
	t.Helper()
	var out []audit.Recorded
	if err := st.StreamEvents(context.Background(), audit.Filter{}, func(r audit.Recorded) error {
		out = append(out, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	return out
}

// findCheckpoint returns the single retention_checkpoint event in rows,
// failing if there is not exactly one.
func findCheckpoint(t *testing.T, rows []audit.Recorded) audit.Recorded {
	t.Helper()
	var found []audit.Recorded
	for _, r := range rows {
		if r.Type == audit.TypeRetentionCheckpoint {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d retention_checkpoint events, want exactly 1", len(found))
	}
	return found[0]
}

// recordAt records an event with an explicit timestamp so tests control
// the seq/time relationship deterministically.
func recordAt(t *testing.T, st *Store, ts time.Time, typ audit.Type, messageID string) audit.Recorded {
	t.Helper()
	rec, err := st.Record(context.Background(), audit.Event{
		Timestamp: ts,
		Type:      typ,
		Actor:     "milter",
		MessageID: messageID,
		Recipient: "r@example.com",
		Details:   map[string]any{"n": messageID},
	})
	if err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}
	return rec
}

var baseTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// TestTruncateAuditPreservesChainVerifiability records a run of events,
// truncates the old prefix, and asserts (a) a checkpoint was written,
// (b) the survivors verify from the checkpoint's anchor hash, and
// (c) the anchor hash equals the recomputed hash of the last removed row.
func TestTruncateAuditPreservesChainVerifiability(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	// 10 old events (day 0), then 5 recent events (day 100).
	old := make([]audit.Recorded, 0, 10)
	for i := 0; i < 10; i++ {
		old = append(old, recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m-old"))
	}
	recentStart := baseTime.Add(100 * 24 * time.Hour)
	for i := 0; i < 5; i++ {
		recordAt(t, st, recentStart.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m-new")
	}

	// The hash of the last old row (seq 10) is what the anchor must equal.
	wantAnchor := recomputeHash(t, old[9])

	cutoff := baseTime.Add(50 * 24 * time.Hour) // between old and recent.
	res, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: cutoff, Actor: "system"})
	if err != nil {
		t.Fatalf("TruncateAudit() error = %v, want nil", err)
	}
	if !res.Truncated {
		t.Fatalf("Truncated = false, want true")
	}
	if res.TruncatedCount != 10 {
		t.Errorf("TruncatedCount = %d, want 10", res.TruncatedCount)
	}
	if res.AnchorSeq != 10 {
		t.Errorf("AnchorSeq = %d, want 10", res.AnchorSeq)
	}
	if res.AnchorHash != wantAnchor {
		t.Errorf("AnchorHash = %q, want %q (hash of last removed row)", res.AnchorHash, wantAnchor)
	}
	if res.HeldClamped {
		t.Errorf("HeldClamped = true, want false")
	}

	rows := streamAll(t, st)
	// Survivors: 5 recent data rows + 1 checkpoint.
	if len(rows) != 6 {
		t.Fatalf("survivors = %d, want 6", len(rows))
	}
	cp := findCheckpoint(t, rows)
	if got := cp.Details[audit.DetailAnchorHash]; got != wantAnchor {
		t.Errorf("checkpoint anchor_hash = %v, want %q", got, wantAnchor)
	}

	// The survivors form a verifiable chain anchored at the checkpoint's
	// anchor hash — i.e. the first survivor's PrevHash equals the hash of
	// the removed row 10, re-supplied by the checkpoint.
	verifyChain(t, rows, wantAnchor)

	// No removed seq is reachable anymore, and the minimum surviving seq
	// is exactly anchor+1.
	if rows[0].Seq != 11 {
		t.Errorf("first surviving seq = %d, want 11", rows[0].Seq)
	}
}

// TestTruncateAuditExportedSegmentIsAutonomouslyVerifiable exports the
// to-be-removed prefix *before* truncation and confirms it stands alone
// as a genesis-anchored chain whose last row bridges to the checkpoint
// anchor (ADR-017: chained archive + live tail compose end to end).
func TestTruncateAuditExportedSegmentIsAutonomouslyVerifiable(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	for i := 0; i < 6; i++ {
		recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypePolicyDecision, "m")
	}
	for i := 0; i < 3; i++ {
		recordAt(t, st, baseTime.Add(100*24*time.Hour+time.Duration(i)*time.Minute), audit.TypePolicyDecision, "m")
	}

	cutoff := baseTime.Add(50 * 24 * time.Hour)

	// Export the segment that will be removed (created_at < cutoff), as an
	// operator would before enabling truncation.
	var segment []audit.Recorded
	if err := st.StreamEvents(ctx, audit.Filter{To: cutoff}, func(r audit.Recorded) error {
		segment = append(segment, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	if len(segment) != 6 {
		t.Fatalf("exported segment = %d rows, want 6", len(segment))
	}
	// The archived segment verifies on its own, from genesis.
	verifyChain(t, segment, "")
	segmentLastHash := recomputeHash(t, segment[len(segment)-1])

	res, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: cutoff, Actor: "system"})
	if err != nil {
		t.Fatalf("TruncateAudit() error = %v, want nil", err)
	}
	if !res.Truncated {
		t.Fatalf("Truncated = false, want true")
	}
	// The bridge: checkpoint anchor == archived segment's last-row hash.
	if res.AnchorHash != segmentLastHash {
		t.Errorf("AnchorHash = %q, want archived segment last hash %q", res.AnchorHash, segmentLastHash)
	}
}

// TestTruncateAuditRespectsLegalHold pins the acceptance criterion that
// events tied to a message under legal hold are never truncated: the
// boundary is clamped to just before the oldest held event.
func TestTruncateAuditRespectsLegalHold(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	// A held message: message + attachment + link + hold.
	if err := st.CreateMessage(ctx, store.NewMessageParams{ID: "m-held", QueueID: "q", Sender: "a@example.com"}); err != nil {
		t.Fatalf("CreateMessage() error = %v", err)
	}
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID: "att", MessageID: "m-held", PartRef: "1", Filename: "f.bin",
		DeclaredType: "application/octet-stream", DetectedType: "application/octet-stream",
		Size: 10, StorageKey: "ab/held",
	}); err != nil {
		t.Fatalf("CreateAttachment() error = %v", err)
	}
	expiresAt := baseTime.Add(200 * 24 * time.Hour).Format(time.RFC3339Nano)
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test placeholder hash, not a credential
		ID: "l", MessageID: "m-held", AttachmentID: "att", Recipient: "r@example.com",
		TokenHash: "hash-held", ExpiresAt: expiresAt, MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v", err)
	}
	if err := st.SetHold(ctx, "l", true, "officer@example.com", baseTime.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v", err)
	}

	// seq1,2: other message (old). seq3: held message (old). seq4: other
	// (old). seq5: recent.
	recordAt(t, st, baseTime.Add(1*time.Minute), audit.TypeMessageProcessed, "m-other")
	seq2 := recordAt(t, st, baseTime.Add(2*time.Minute), audit.TypeMessageProcessed, "m-other")
	recordAt(t, st, baseTime.Add(3*time.Minute), audit.TypePolicyDecision, "m-held")
	recordAt(t, st, baseTime.Add(4*time.Minute), audit.TypeMessageProcessed, "m-other")
	recordAt(t, st, baseTime.Add(100*24*time.Hour), audit.TypeMessageProcessed, "m-new")

	cutoff := baseTime.Add(50 * 24 * time.Hour)
	res, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: cutoff, Actor: "system"})
	if err != nil {
		t.Fatalf("TruncateAudit() error = %v, want nil", err)
	}
	if !res.Truncated {
		t.Fatalf("Truncated = false, want true (seq 1..2 are truncatable)")
	}
	if !res.HeldClamped {
		t.Errorf("HeldClamped = false, want true")
	}
	if res.AnchorSeq != 2 {
		t.Errorf("AnchorSeq = %d, want 2 (clamped to just before held seq 3)", res.AnchorSeq)
	}
	if res.TruncatedCount != 2 {
		t.Errorf("TruncatedCount = %d, want 2", res.TruncatedCount)
	}
	if want := recomputeHash(t, seq2); res.AnchorHash != want {
		t.Errorf("AnchorHash = %q, want hash of seq 2 = %q", res.AnchorHash, want)
	}

	// The held event (seq 3) must still be present.
	rows := streamAll(t, st)
	var heldPresent bool
	for _, r := range rows {
		if r.Seq == 3 && r.MessageID == "m-held" {
			heldPresent = true
		}
		if r.Seq == 1 || r.Seq == 2 {
			t.Errorf("removed row seq %d is still present", r.Seq)
		}
	}
	if !heldPresent {
		t.Errorf("held event (seq 3) was truncated, want preserved")
	}
	// Survivors still verify, anchored at the clamped boundary.
	verifyChain(t, rows, res.AnchorHash)
}

// TestTruncateAuditIsIdempotentAndAdvances covers repeat sweeps: a second
// truncate with the same cutoff and no new old rows is a clean no-op
// (writes no second checkpoint), while a later cutoff that now covers the
// previously-recent rows advances the truncation and re-anchors.
func TestTruncateAuditIsIdempotentAndAdvances(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m")
	}
	for i := 0; i < 4; i++ {
		recordAt(t, st, baseTime.Add(100*24*time.Hour+time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m")
	}

	cutoff1 := baseTime.Add(50 * 24 * time.Hour)
	res1, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: cutoff1, Actor: "system"})
	if err != nil {
		t.Fatalf("first TruncateAudit() error = %v", err)
	}
	if !res1.Truncated || res1.TruncatedCount != 4 {
		t.Fatalf("first pass: Truncated=%v Count=%d, want true/4", res1.Truncated, res1.TruncatedCount)
	}
	rowsAfter1 := streamAll(t, st)
	_ = findCheckpoint(t, rowsAfter1) // exactly one checkpoint.

	// Second pass, same cutoff: nothing new is old enough → no-op, and no
	// second checkpoint is written (an idle log must not accrete empty
	// checkpoints).
	res2, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: cutoff1, Actor: "system"})
	if err != nil {
		t.Fatalf("second TruncateAudit() error = %v", err)
	}
	if res2.Truncated {
		t.Errorf("second pass Truncated = true, want false (nothing newly eligible)")
	}
	if len(streamAll(t, st)) != len(rowsAfter1) {
		t.Errorf("second pass changed row count from %d, want unchanged", len(rowsAfter1))
	}

	// Later cutoff now covers the day-100 rows (and the first checkpoint):
	// truncation advances and the survivors re-anchor and still verify.
	cutoff2 := baseTime.Add(150 * 24 * time.Hour)
	res3, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: cutoff2, Actor: "system"})
	if err != nil {
		t.Fatalf("third TruncateAudit() error = %v", err)
	}
	if !res3.Truncated {
		t.Fatalf("third pass Truncated = false, want true")
	}
	rows := streamAll(t, st)
	verifyChain(t, rows, res3.AnchorHash)
}

// TestTruncateAuditEmptyAndYoungLogNoOp confirms the opt-in-safe path: a
// cutoff older than every row (or an empty table) removes nothing and
// writes no checkpoint.
func TestTruncateAuditEmptyAndYoungLogNoOp(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	// Empty table.
	res, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: baseTime, Actor: "system"})
	if err != nil {
		t.Fatalf("TruncateAudit(empty) error = %v", err)
	}
	if res.Truncated {
		t.Errorf("empty log Truncated = true, want false")
	}

	// Young rows, cutoff before all of them.
	for i := 0; i < 3; i++ {
		recordAt(t, st, baseTime.Add(100*24*time.Hour+time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m")
	}
	res, err = st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: baseTime.Add(10 * 24 * time.Hour), Actor: "system"})
	if err != nil {
		t.Fatalf("TruncateAudit(young) error = %v", err)
	}
	if res.Truncated {
		t.Errorf("young log Truncated = true, want false")
	}
	if got := len(streamAll(t, st)); got != 3 {
		t.Errorf("row count = %d, want 3 (nothing removed, no checkpoint added)", got)
	}
}

// TestListEventsCursorPastAnchorReturnsTruncated covers the seq-cursor
// safety invariant: after truncation a cursor pointing before the anchor
// gets ErrCursorTruncated (never a silent skip), while a cursor exactly
// at the anchor resumes cleanly.
func TestListEventsCursorPastAnchorReturnsTruncated(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m")
	}
	for i := 0; i < 5; i++ {
		recordAt(t, st, baseTime.Add(100*24*time.Hour+time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m")
	}

	res, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: baseTime.Add(50 * 24 * time.Hour), Actor: "system"})
	if err != nil {
		t.Fatalf("TruncateAudit() error = %v", err)
	}
	if res.AnchorSeq != 10 {
		t.Fatalf("AnchorSeq = %d, want 10", res.AnchorSeq)
	}

	// A cursor at seq 5 (before the anchor at 10): resuming would skip
	// removed rows 6..10 → must error.
	before := audit.EncodeSeqCursor(5)
	if _, err := st.ListEvents(ctx, audit.ListParams{Cursor: before, Limit: 10}); !errors.Is(err, audit.ErrCursorTruncated) {
		t.Errorf("ListEvents(cursor before anchor) error = %v, want ErrCursorTruncated", err)
	}

	// A cursor exactly at the anchor (seq 10): the next expected row is
	// 11, which survives — no error, resumes cleanly.
	atAnchor := audit.EncodeSeqCursor(10)
	page, err := st.ListEvents(ctx, audit.ListParams{Cursor: atAnchor, Limit: 10})
	if err != nil {
		t.Fatalf("ListEvents(cursor at anchor) error = %v, want nil", err)
	}
	if len(page.Events) == 0 || page.Events[0].Seq != 11 {
		t.Errorf("ListEvents(cursor at anchor) first seq = %v, want 11", page.Events)
	}
}

// TestListEventsCursorGuardSnapshotIsolation pins the exact SQLite
// mechanism ListEvents' cursor-truncation guard relies on (ATR-308 B2,
// security review): a single read-only transaction observes one fixed
// snapshot across multiple statements, immune to a concurrent commit
// from another connection landing between them. This is what actually
// closes the TOCTOU the earlier two-separate-QueryContext-calls version
// had (minAuditSeq and the paged SELECT could land on different reader-
// pool connections and straddle a commit).
//
// This test exercises that primitive directly and deterministically
// (no goroutine-scheduling luck required) rather than the production
// ListEvents call end-to-end: ListEvents runs its whole transaction in
// one synchronous call, so there is no seam to pause it mid-flight from
// a test without adding test-only instrumentation to production code,
// which this codebase avoids (per review guidance: "if hard to provoke
// a single snapshot in a test, justify"). See
// TestListEventsCursorNoSilentSkipUnderConcurrentTruncation below for a
// complementary, best-effort concurrent stress test against the real
// ListEvents call.
func TestListEventsCursorGuardSnapshotIsolation(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m")
	}

	// Open a read-only tx exactly the way ListEvents does, and take its
	// first read (fixing the snapshot per SQLite WAL semantics).
	tx, err := st.db.reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("BeginTx() error = %v, want nil", err)
	}
	defer tx.Rollback() //nolint:errcheck // read-only, test cleanup.

	minSeq, ok, err := minAuditSeqTx(ctx, tx)
	if err != nil {
		t.Fatalf("minAuditSeqTx() error = %v, want nil", err)
	}
	if !ok || minSeq != 1 {
		t.Fatalf("minAuditSeqTx() = (%d, %v), want (1, true)", minSeq, ok)
	}

	// A concurrent write, on a DIFFERENT connection (the writer pool,
	// autocommit), removes rows 1..3 and commits — exactly what a
	// TruncateAudit call landing mid-ListEvents would do.
	if _, err := st.db.writer.ExecContext(ctx, `DELETE FROM audit_events WHERE seq <= 3`); err != nil {
		t.Fatalf("concurrent DELETE error = %v, want nil", err)
	}

	// The already-open read tx must still see its ORIGINAL snapshot: a
	// second statement inside the SAME tx (mirroring ListEvents' paged
	// SELECT running after minAuditSeqTx) must not observe the commit
	// that landed after the first statement fixed the snapshot.
	var countInTx int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&countInTx); err != nil {
		t.Fatalf("in-tx COUNT() error = %v, want nil", err)
	}
	if countInTx != 5 {
		t.Fatalf("in-tx COUNT() = %d, want 5 (snapshot must predate the concurrent DELETE)", countInTx)
	}

	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback() error = %v, want nil", err)
	}

	// A fresh read (its own new snapshot) DOES see the delete, proving
	// the delete really happened and the tx above was not simply stale
	// due to a misconfiguration (e.g. a missing WAL pragma).
	var countAfter int
	if err := st.db.reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&countAfter); err != nil {
		t.Fatalf("post-rollback COUNT() error = %v, want nil", err)
	}
	if countAfter != 2 {
		t.Fatalf("post-rollback COUNT() = %d, want 2 (delete must be visible once the old tx is gone)", countAfter)
	}
}

// TestListEventsCursorNoSilentSkipUnderConcurrentTruncation is a
// best-effort concurrent regression test for ATR-308 B2: it hammers
// ListEvents with a fixed cursor concurrently with a stream of
// TruncateAudit calls advancing the cutoff, and asserts the invariant a
// split guard/SELECT could violate — a successful (err == nil) response
// must never silently skip rows. Row seq 2 is the next expected row
// while it survives; a far-future "tail" of events guarantees a
// non-empty result is always available once the guard should pass, so
// any deviation (an unexpected first Seq, or an empty page with no
// error) is unambiguously the silent-skip failure mode B2 describes,
// not a benign "nothing left to return" case.
//
// This test was validated to actually catch the regression: run against
// a deliberately reintroduced two-connection version of the guard (the
// pre-fix shape — s.db.reader.QueryContext called independently for the
// minSeq check and for the paged SELECT, instead of one BeginTx), it
// reliably failed with exactly this symptom ("first event Seq = 3/4,
// want 2"); run against the fixed, single-transaction version, it passes
// consistently. Both directions were re-run several times to confirm
// they are not a fluke.
func TestListEventsCursorNoSilentSkipUnderConcurrentTruncation(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	const oldCount = 30
	for i := 0; i < oldCount; i++ {
		recordAt(t, st, baseTime.Add(time.Duration(i)*time.Second), audit.TypeMessageProcessed, "m")
	}
	// A stable tail, far beyond any cutoff this test uses, so a passing
	// guard always has at least one survivor to return.
	const tailCount = 5
	for i := 0; i < tailCount; i++ {
		recordAt(t, st, baseTime.Add(365*24*time.Hour+time.Duration(i)*time.Second), audit.TypeMessageProcessed, "m-tail")
	}

	cursor := audit.EncodeSeqCursor(1) // afterSeq = 1; row 2 is the next expected row while it survives.

	var truncatorWG sync.WaitGroup
	truncatorWG.Add(1)
	go func() {
		defer truncatorWG.Done()
		for i := 0; i < oldCount; i++ {
			cutoff := baseTime.Add(time.Duration(i) * time.Second)
			if _, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: cutoff, Actor: "system"}); err != nil {
				t.Errorf("concurrent TruncateAudit() error = %v, want nil", err)
				return
			}
			// Paced deliberately: without it, all oldCount truncation
			// passes complete in well under a millisecond on a tiny
			// in-memory-fast SQLite file, finishing before most reader
			// iterations even run — verified empirically (against a
			// deliberately reintroduced two-connection version of the
			// guard) that an unpaced loop lets this test pass cleanly
			// even with the bug present, because the truncation state
			// is effectively binary (not-yet-started or already-done)
			// from the readers' point of view. Spreading the passes
			// across ~60ms gives the reader goroutines a real chance to
			// observe a lot of them mid-flight.
			time.Sleep(2 * time.Millisecond)
		}
	}()

	var readerWG sync.WaitGroup
	const readers = 6
	const iterationsPerReader = 150
	for r := 0; r < readers; r++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			for i := 0; i < iterationsPerReader; i++ {
				page, err := st.ListEvents(ctx, audit.ListParams{Cursor: cursor, Limit: 10})
				if err != nil {
					if errors.Is(err, audit.ErrCursorTruncated) {
						continue // correctly rejected once row 2 itself was truncated.
					}
					t.Errorf("ListEvents() error = %v, want nil or ErrCursorTruncated", err)
					return
				}
				if len(page.Events) == 0 {
					t.Errorf("ListEvents() returned an empty page with no error, want either row 2 or ErrCursorTruncated (the far-future tail always survives)")
					continue
				}
				if got := page.Events[0].Seq; got != 2 {
					t.Errorf("ListEvents() first event Seq = %d, want 2 (silent skip: guard and SELECT observed different snapshots)", got)
				}
			}
		}()
	}

	readerWG.Wait()
	truncatorWG.Wait()
}

// TestTruncateAuditDegenerateAllRowsRemovedCheckpointSelfAnchors covers
// the degenerate case documented in ADR-017 "Verification recipe" and
// docs/architecture/audit-retention.md (arch review follow-up): when
// every existing row is older than the cutoff, the retention_checkpoint
// this pass appends is the ONLY surviving row — it lands past the
// boundary (seq = old max seq + 1), so the delete never touches it. Its
// own PrevHash and its own Details.anchor_hash must be the same value
// (the hash of the last row it just deleted), making it self-anchoring:
// a future verifier (ATR-240) must recognize this shape rather than
// treating a lone checkpoint with a non-empty PrevHash as a broken or
// unlocatable chain.
func TestTruncateAuditDegenerateAllRowsRemovedCheckpointSelfAnchors(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	old := make([]audit.Recorded, 0, 4)
	for i := 0; i < 4; i++ {
		old = append(old, recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m"))
	}
	// No recent tail: every row is older than the cutoff below.
	wantAnchor := recomputeHash(t, old[len(old)-1])

	cutoff := baseTime.Add(100 * 24 * time.Hour)
	res, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: cutoff, Actor: "system"})
	if err != nil {
		t.Fatalf("TruncateAudit() error = %v, want nil", err)
	}
	if !res.Truncated || res.TruncatedCount != 4 {
		t.Fatalf("TruncateAudit() = %+v, want Truncated with TruncatedCount 4", res)
	}
	if res.AnchorHash != wantAnchor {
		t.Fatalf("AnchorHash = %q, want %q", res.AnchorHash, wantAnchor)
	}

	rows := streamAll(t, st)
	if len(rows) != 1 {
		t.Fatalf("surviving rows = %d, want exactly 1 (the checkpoint itself)", len(rows))
	}
	cp := rows[0]
	if cp.Type != audit.TypeRetentionCheckpoint {
		t.Fatalf("sole surviving row Type = %q, want %q", cp.Type, audit.TypeRetentionCheckpoint)
	}

	// Self-anchoring: PrevHash (the column) and Details.anchor_hash (the
	// self-recorded value) must agree — both are the hash of the last
	// deleted row. A verifier walking from this row treats it as its own
	// trusted starting point.
	detailAnchor, _ := cp.Details[audit.DetailAnchorHash].(string)
	if detailAnchor == "" {
		t.Fatalf("checkpoint Details[anchor_hash] is empty, want the recomputed hash of the last deleted row")
	}
	if cp.PrevHash != detailAnchor {
		t.Errorf("PrevHash = %q, Details[anchor_hash] = %q, want equal (self-anchoring)", cp.PrevHash, detailAnchor)
	}
	if cp.PrevHash != wantAnchor {
		t.Errorf("PrevHash = %q, want %q (hash of the last deleted row)", cp.PrevHash, wantAnchor)
	}

	// Unlike the genesis case (empty PrevHash), this row's PrevHash is
	// non-empty yet names no live row — anchor_seq (4) no longer exists
	// in the table. That is expected, not a defect: the verifier trusts
	// the checkpoint's self-consistency, not the liveness of anchor_seq.
	anchorSeq, _ := cp.Details[audit.DetailAnchorSeq].(float64) // JSON numbers decode as float64 via map[string]any.
	if int64(anchorSeq) != 4 {
		t.Errorf("Details[anchor_seq] = %v, want 4", cp.Details[audit.DetailAnchorSeq])
	}
	if _, found, err := auditRowHash(ctx, mustBeginTx(t, st, ctx), int64(anchorSeq)); err != nil {
		t.Fatalf("auditRowHash() error = %v, want nil (query itself should succeed even though the row is gone)", err)
	} else if found {
		t.Errorf("auditRowHash() found = true for anchor_seq %d, want false (that row was deleted; the verifier must not require it to be live)", int64(anchorSeq))
	}
}

// mustBeginTx opens a throwaway read-only transaction for a single
// lookup in a test, registering its rollback via t.Cleanup.
func mustBeginTx(t *testing.T, st *Store, ctx context.Context) *sql.Tx {
	t.Helper()
	tx, err := st.db.reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("BeginTx() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx
}
