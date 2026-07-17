package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
)

// These internal-package tests exercise audit.Verify (ATR-240) against a
// REAL sqlite store, so they prove the property the whole feature rests
// on: the prev_hash the store writes at insert time (via lastAuditRecord/
// auditRowHash -> audit.HashRecord) is exactly what the verifier
// recomputes. They also reach store internals (s.db.writer) to simulate
// out-of-band tampering the append-only API cannot itself perform.

func countAuditRows(t *testing.T, st *Store) int64 {
	t.Helper()
	var n int64
	if err := st.db.reader.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events`).Scan(&n); err != nil {
		t.Fatalf("count audit_events error = %v", err)
	}
	return n
}

// TestVerifyLiveGenesisChain: a freshly written run of events verifies as
// an intact genesis chain.
func TestVerifyLiveGenesisChain(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	for i := 0; i < 6; i++ {
		recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m")
	}

	rep, err := audit.Verify(ctx, st)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if !rep.OK {
		t.Fatalf("Verify() OK = false, want true; break = %+v", rep.Break)
	}
	if rep.StartMode != audit.StartGenesis {
		t.Errorf("StartMode = %v, want StartGenesis", rep.StartMode)
	}
	if rep.EventsChecked != 6 {
		t.Errorf("EventsChecked = %d, want 6", rep.EventsChecked)
	}
}

// TestVerifyDetectsRawTamper mutates a stored row out-of-band (the exact
// threat tamper-evidence exists for) and asserts Verify catches it at the
// following seq.
func TestVerifyDetectsRawTamper(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m")
	}

	// Alter the actor of seq 3 directly in the database. This changes seq
	// 3's recomputed hash, so seq 4's stored prev_hash no longer matches.
	if _, err := st.db.writer.ExecContext(ctx,
		`UPDATE audit_events SET actor = 'attacker' WHERE seq = 3`); err != nil {
		t.Fatalf("tamper UPDATE error = %v", err)
	}

	rep, err := audit.Verify(ctx, st)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if rep.OK {
		t.Fatal("Verify() OK = true, want false after out-of-band tamper")
	}
	if rep.Break == nil || rep.Break.Seq != 4 {
		t.Fatalf("Break = %+v, want a break at seq 4", rep.Break)
	}
}

// TestVerifyLiveAnchoredResume records old + recent events, truncates the
// old prefix, and verifies the survivors resume from the checkpoint anchor.
func TestVerifyLiveAnchoredResume(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	for i := 0; i < 8; i++ {
		recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m-old")
	}
	recentStart := baseTime.Add(100 * 24 * time.Hour)
	for i := 0; i < 4; i++ {
		recordAt(t, st, recentStart.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m-new")
	}

	cutoff := baseTime.Add(50 * 24 * time.Hour)
	res, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: cutoff, Actor: "system"})
	if err != nil {
		t.Fatalf("TruncateAudit() error = %v, want nil", err)
	}
	if !res.Truncated {
		t.Fatalf("TruncateAudit() Truncated = false, want true")
	}

	rep, err := audit.Verify(ctx, st)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if !rep.OK {
		t.Fatalf("Verify() OK = false, want true; break = %+v", rep.Break)
	}
	if rep.StartMode != audit.StartAnchoredResume {
		t.Errorf("StartMode = %v, want StartAnchoredResume", rep.StartMode)
	}
	if rep.CheckpointsPresent != 1 {
		t.Errorf("CheckpointsPresent = %d, want 1", rep.CheckpointsPresent)
	}
}

// TestVerifyLiveDegenerateCheckpoint truncates the ENTIRE table so only the
// self-anchoring checkpoint survives, and verifies that shape.
func TestVerifyLiveDegenerateCheckpoint(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m")
	}

	// Cutoff after every event: the whole table is eligible, leaving only
	// the appended checkpoint.
	cutoff := baseTime.Add(100 * 24 * time.Hour)
	res, err := st.TruncateAudit(ctx, audit.TruncateRequest{Cutoff: cutoff, Actor: "system"})
	if err != nil {
		t.Fatalf("TruncateAudit() error = %v, want nil", err)
	}
	if !res.Truncated {
		t.Fatalf("TruncateAudit() Truncated = false, want true")
	}
	if n := countAuditRows(t, st); n != 1 {
		t.Fatalf("audit rows after full truncation = %d, want 1 (checkpoint only)", n)
	}

	rep, err := audit.Verify(ctx, st)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if !rep.OK {
		t.Fatalf("Verify() OK = false, want true; break = %+v", rep.Break)
	}
	if rep.StartMode != audit.StartSelfAnchoringCheckpoint {
		t.Errorf("StartMode = %v, want StartSelfAnchoringCheckpoint", rep.StartMode)
	}
}

// TestVerifyIsReadOnly asserts running Verify appends no audit event and
// removes none — verifying must never perturb the chain it checks.
func TestVerifyIsReadOnly(t *testing.T) {
	st := openInternalStore(t)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		recordAt(t, st, baseTime.Add(time.Duration(i)*time.Minute), audit.TypeMessageProcessed, "m")
	}
	before := countAuditRows(t, st)

	for i := 0; i < 3; i++ {
		if _, err := audit.Verify(ctx, st); err != nil {
			t.Fatalf("Verify() error = %v, want nil", err)
		}
	}

	if after := countAuditRows(t, st); after != before {
		t.Fatalf("audit row count changed across Verify: before %d, after %d (verify must be read-only)", before, after)
	}
}
