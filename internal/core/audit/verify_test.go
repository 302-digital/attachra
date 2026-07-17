package audit

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// sliceReader is a minimal audit.Reader that replays a fixed slice of
// records in order, letting the verifier be tested without a store.
type sliceReader struct{ recs []Recorded }

func (s sliceReader) StreamEvents(_ context.Context, _ Filter, fn func(Recorded) error) error {
	for _, r := range s.recs {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

// chainOf builds a valid genesis chain of n events, each row's PrevHash
// set to the recomputed hash of its predecessor (the first is empty),
// exactly as the store would persist it.
func chainOf(t *testing.T, n int) []Recorded {
	t.Helper()
	recs := make([]Recorded, 0, n)
	prev := ""
	base := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		r := Recorded{
			Event: Event{
				Timestamp: base.Add(time.Duration(i) * time.Second),
				Type:      TypeError,
				Actor:     "test",
				MessageID: "m",
				Details:   map[string]any{"i": i},
			},
			ID:       string(rune('a'+i)) + "-id",
			Seq:      int64(i),
			PrevHash: prev,
		}
		h, err := HashRecord(r)
		if err != nil {
			t.Fatalf("HashRecord() error = %v", err)
		}
		prev = h
		recs = append(recs, r)
	}
	return recs
}

// checkpointAfter builds a retention_checkpoint anchoring anchorSeq, with
// its PrevHash chained onto tailHash, landing at seq checkpointSeq.
func checkpointAfter(t *testing.T, checkpointSeq, anchorSeq int64, anchorHash, tailHash string) Recorded {
	t.Helper()
	return Recorded{
		Event: Event{
			Timestamp: time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC),
			Type:      TypeRetentionCheckpoint,
			Actor:     "system",
			Details: map[string]any{
				DetailAnchorSeq:      anchorSeq,
				DetailAnchorHash:     anchorHash,
				DetailTruncatedCount: anchorSeq,
				DetailCutoff:         "2026-07-16T00:00:00Z",
				DetailHeldClamped:    false,
			},
		},
		ID:       "cp-id",
		Seq:      checkpointSeq,
		PrevHash: tailHash,
	}
}

func TestVerifyGenesisChainOK(t *testing.T) {
	recs := chainOf(t, 5)
	rep, err := Verify(context.Background(), sliceReader{recs})
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if !rep.OK {
		t.Fatalf("Verify() OK = false, want true; break = %+v", rep.Break)
	}
	if rep.StartMode != StartGenesis {
		t.Errorf("StartMode = %v, want StartGenesis", rep.StartMode)
	}
	if rep.EventsChecked != 5 {
		t.Errorf("EventsChecked = %d, want 5", rep.EventsChecked)
	}
	if rep.CheckpointsPresent != 0 {
		t.Errorf("CheckpointsPresent = %d, want 0", rep.CheckpointsPresent)
	}
}

func TestVerifyEmptyLogOK(t *testing.T) {
	rep, err := Verify(context.Background(), sliceReader{nil})
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if !rep.OK || rep.StartMode != StartEmpty {
		t.Errorf("Verify(empty) = %+v, want OK StartEmpty", rep)
	}
}

// TestVerifyDetectsAlteredEvent mutates one row's Actor after its hash was
// fixed. The tamper changes that row's hash, so the break surfaces at the
// NEXT row (whose stored PrevHash no longer matches).
func TestVerifyDetectsAlteredEvent(t *testing.T) {
	recs := chainOf(t, 5)
	recs[2].Actor = "attacker" // seq 3 altered; break shows at seq 4
	rep, err := Verify(context.Background(), sliceReader{recs})
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if rep.OK {
		t.Fatal("Verify() OK = true, want false for an altered event")
	}
	if rep.Break == nil || rep.Break.Seq != 4 {
		t.Fatalf("Break = %+v, want a break at seq 4", rep.Break)
	}
}

// TestVerifyDetectsDeletedEvent removes a middle row, leaving a seq gap.
func TestVerifyDetectsDeletedEvent(t *testing.T) {
	recs := chainOf(t, 5)
	recs = append(recs[:2], recs[3:]...) // drop seq 3
	rep, err := Verify(context.Background(), sliceReader{recs})
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if rep.OK {
		t.Fatal("Verify() OK = true, want false for a deleted event")
	}
	if rep.Break == nil || rep.Break.Seq != 4 {
		t.Fatalf("Break = %+v, want a break at seq 4 (gap where seq 3 was)", rep.Break)
	}
}

// TestVerifyDetectsReorderedEvents swaps two adjacent rows' payloads while
// keeping their seq positions, breaking continuity.
func TestVerifyDetectsReorderedEvents(t *testing.T) {
	recs := chainOf(t, 5)
	recs[1].Actor, recs[2].Actor = recs[2].Actor, "swapped"
	rep, err := Verify(context.Background(), sliceReader{recs})
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if rep.OK {
		t.Fatal("Verify() OK = true, want false for reordered events")
	}
	if rep.Break == nil {
		t.Fatal("Break = nil, want a continuity break")
	}
}

// TestVerifyDoesNotDetectTailDeletion pins a documented, accepted
// limitation (ADR-017 "Limitations", R1 of the ATR-240 security review):
// deleting the NEWEST events (the tail) — as opposed to an old prefix via
// the audited Truncator, or a middle row as in
// TestVerifyDetectsDeletedEvent above — is invisible to a purely backward
// chain walk. Each surviving row's prev_hash still correctly matches its
// predecessor; nothing about the surviving data reveals that even-newer
// rows used to exist. Verify legitimately reports OK here: this test
// exists so that fact is pinned and intentional, not an accidental gap
// discovered later. Detecting tail deletion requires an external,
// independently maintained high-water mark (e.g. a periodically exported
// max seq, or an offsite/WORM export whose latest line reveals the log
// grew further) — out of scope for ATR-240.
func TestVerifyDoesNotDetectTailDeletion(t *testing.T) {
	full := chainOf(t, 5)
	truncatedTail := full[:3] // seq 4 and 5 (the newest) deleted; 1-3 survive intact.

	rep, err := Verify(context.Background(), sliceReader{truncatedTail})
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if !rep.OK {
		t.Fatalf("Verify() OK = false, want true (tail deletion is a documented blind spot); break = %+v", rep.Break)
	}
	if rep.StartMode != StartGenesis {
		t.Errorf("StartMode = %v, want StartGenesis", rep.StartMode)
	}
	if rep.EventsChecked != 3 {
		t.Errorf("EventsChecked = %d, want 3", rep.EventsChecked)
	}
}

// TestVerifyAnchoredResumeOK simulates a prefix truncation: rows 1..2 were
// removed, rows 3..5 survive, and a checkpoint at seq 6 anchors seq 2.
func TestVerifyAnchoredResumeOK(t *testing.T) {
	full := chainOf(t, 5)
	anchorHash, err := HashRecord(full[1]) // hash of seq 2 (the boundary)
	if err != nil {
		t.Fatalf("HashRecord() error = %v", err)
	}
	tailHash, err := HashRecord(full[4]) // hash of seq 5 (the tail)
	if err != nil {
		t.Fatalf("HashRecord() error = %v", err)
	}
	cp := checkpointAfter(t, 6, 2, anchorHash, tailHash)

	live := []Recorded{full[2], full[3], full[4], cp} // seq 3,4,5, checkpoint@6
	rep, err := Verify(context.Background(), sliceReader{live})
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if !rep.OK {
		t.Fatalf("Verify() OK = false, want true; break = %+v", rep.Break)
	}
	if rep.StartMode != StartAnchoredResume {
		t.Errorf("StartMode = %v, want StartAnchoredResume", rep.StartMode)
	}
	if rep.CheckpointsPresent != 1 {
		t.Errorf("CheckpointsPresent = %d, want 1", rep.CheckpointsPresent)
	}
}

// TestVerifySelfAnchoringCheckpointOK is the degenerate case: the whole
// table was older than the cutoff, so the only surviving row is the
// checkpoint, whose PrevHash equals its own anchor_hash.
func TestVerifySelfAnchoringCheckpointOK(t *testing.T) {
	full := chainOf(t, 3)
	anchorHash, err := HashRecord(full[2]) // hash of seq 3 (max seq = boundary)
	if err != nil {
		t.Fatalf("HashRecord() error = %v", err)
	}
	// Checkpoint at seq 4, prev_hash == anchor_hash (both are hash of seq 3).
	cp := checkpointAfter(t, 4, 3, anchorHash, anchorHash)

	rep, err := Verify(context.Background(), sliceReader{[]Recorded{cp}})
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if !rep.OK {
		t.Fatalf("Verify() OK = false, want true; break = %+v", rep.Break)
	}
	if rep.StartMode != StartSelfAnchoringCheckpoint {
		t.Errorf("StartMode = %v, want StartSelfAnchoringCheckpoint", rep.StartMode)
	}
}

// TestVerifyUnanchoredNonGenesisFails: a first row with a non-empty
// prev_hash and no checkpoint vouching for it cannot establish trust.
func TestVerifyUnanchoredNonGenesisFails(t *testing.T) {
	full := chainOf(t, 5)
	live := []Recorded{full[2], full[3], full[4]} // seq 3,4,5 but NO checkpoint
	rep, err := Verify(context.Background(), sliceReader{live})
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if rep.OK {
		t.Fatal("Verify() OK = true, want false: earliest row is unanchored")
	}
	if rep.Break == nil || rep.Break.Seq != 3 {
		t.Fatalf("Break = %+v, want a break at seq 3", rep.Break)
	}
}

// TestVerifyJSONLRoundTripOK exports a chain to JSONL and verifies the
// offline segment stands on its own.
func TestVerifyJSONLRoundTripOK(t *testing.T) {
	recs := chainOf(t, 4)
	var buf bytes.Buffer
	if err := ExportJSONL(context.Background(), sliceReader{recs}, &buf, Filter{}); err != nil {
		t.Fatalf("ExportJSONL() error = %v, want nil", err)
	}

	rep, err := VerifyJSONL(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("VerifyJSONL() error = %v, want nil", err)
	}
	if !rep.OK || rep.StartMode != StartGenesis {
		t.Fatalf("VerifyJSONL() = %+v, want OK StartGenesis; break = %+v", rep, rep.Break)
	}
	if rep.EventsChecked != 4 {
		t.Errorf("EventsChecked = %d, want 4", rep.EventsChecked)
	}
}

// TestVerifyJSONLDetectsTamper flips a byte in an exported line's actor
// field and confirms offline verification catches it.
func TestVerifyJSONLDetectsTamper(t *testing.T) {
	recs := chainOf(t, 4)
	var buf bytes.Buffer
	if err := ExportJSONL(context.Background(), sliceReader{recs}, &buf, Filter{}); err != nil {
		t.Fatalf("ExportJSONL() error = %v, want nil", err)
	}
	tampered := bytes.Replace(buf.Bytes(), []byte(`"actor":"test"`), []byte(`"actor":"evil"`), 1)

	rep, err := VerifyJSONL(bytes.NewReader(tampered))
	if err != nil {
		t.Fatalf("VerifyJSONL() error = %v, want nil", err)
	}
	if rep.OK {
		t.Fatal("VerifyJSONL() OK = true, want false for a tampered segment")
	}
}

// TestVerifyJSONLMalformedInput: a non-JSON line is an operational error,
// not a clean tamper verdict.
func TestVerifyJSONLMalformedInput(t *testing.T) {
	_, err := VerifyJSONL(bytes.NewReader([]byte("this is not json\n")))
	if err == nil {
		t.Fatal("VerifyJSONL(malformed) error = nil, want an error")
	}
}
