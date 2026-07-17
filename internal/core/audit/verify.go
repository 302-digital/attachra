package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// StartMode classifies how a verified chain begins — the trusted point a
// verifier anchored its walk on. The four shapes correspond exactly to
// the cases ADR-017's "Verification recipe" enumerates.
type StartMode int

const (
	// StartEmpty is the mode for a log with no events at all. Trivially
	// verified.
	StartEmpty StartMode = iota
	// StartGenesis is the mode where the earliest surviving event has an
	// empty prev_hash — it is the first event ever written, so the chain
	// is complete from the beginning (no truncation has happened, or none
	// that removed the genesis row).
	StartGenesis
	// StartAnchoredResume is the mode where a prefix was truncated
	// (ADR-017): the earliest surviving data event has a non-empty
	// prev_hash equal to the anchor_hash of a surviving
	// retention_checkpoint, which vouches for the removed prefix's
	// boundary. The walk resumes from that trusted anchor forward.
	StartAnchoredResume
	// StartSelfAnchoringCheckpoint is the degenerate truncation mode where
	// the whole table was older than the cutoff, so the only surviving row
	// is the retention_checkpoint itself, with prev_hash == its own
	// Details.anchor_hash (ADR-017). It is treated as an established,
	// trusted start, exactly like genesis, with nothing further to walk.
	StartSelfAnchoringCheckpoint
)

// String renders a StartMode for human-readable command output.
func (m StartMode) String() string {
	switch m {
	case StartEmpty:
		return "empty log"
	case StartGenesis:
		return "genesis (complete chain from the first event)"
	case StartAnchoredResume:
		return "anchored resume (a truncation checkpoint vouches for the earliest surviving event)"
	case StartSelfAnchoringCheckpoint:
		return "self-anchoring checkpoint (whole log truncated; only the checkpoint survives)"
	default:
		return "unknown"
	}
}

// Break describes the first point at which chain verification failed: the
// seq at which the mismatch was observed, the hash the chain required
// there, the hash that was actually present, and a human-readable reason.
// For a continuity break, Seq is the row whose stored prev_hash did not
// match the recomputed hash of its predecessor — so the tampered/removed
// event is that row or the one immediately before it (seq Seq-1).
type Break struct {
	Seq              int64
	ExpectedPrevHash string
	ActualPrevHash   string
	Reason           string
}

// VerifyReport is the outcome of a chain verification pass. It is
// read-only with respect to the audit log: verifying the chain records
// nothing and mutates nothing (doing so would append events and recurse).
type VerifyReport struct {
	// OK is true when the surviving chain verified end-to-end from its
	// trusted start. When false, Break explains the first failure.
	OK bool
	// EventsChecked is how many events the walk examined.
	EventsChecked int64
	// CheckpointsPresent is how many retention_checkpoint events are in
	// the verified range. When > 0 the log has been truncated at least
	// once, so verification only covers history from the earliest trusted
	// anchor forward — pre-anchor events are gone and their legitimacy
	// cannot be proven from the live log alone (ADR-017 "Limitations").
	CheckpointsPresent int
	// StartMode is the trusted start the walk anchored on (meaningful only
	// when OK).
	StartMode StartMode
	// FirstSeq is the seq of the earliest surviving event (0 for an empty
	// log).
	FirstSeq int64
	// Break is nil when OK; otherwise it locates the first failure.
	Break *Break
}

// Verify walks the live audit log in ascending seq order and checks its
// tamper-evidence chain (SR-128-1, ADR-017 "Verification recipe"). It is
// strictly read-only: it streams via src.StreamEvents and records
// nothing. It detects an altered event, a removed event, and a reordered
// event as a continuity break, and reports the first such break with its
// seq and the expected/actual hashes. The returned error is non-nil only
// for an infrastructure failure while reading (e.g. the store is
// unreachable); a detected tamper is a normal VerifyReport with OK ==
// false, not an error.
func Verify(ctx context.Context, src Reader) (VerifyReport, error) {
	w := newChainWalker()
	err := src.StreamEvents(ctx, Filter{}, func(rec Recorded) error {
		return w.step(rec)
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		return VerifyReport{}, fmt.Errorf("audit: verify: %w", err)
	}
	return w.report()
}

// VerifyJSONL verifies an audit segment previously written by ExportJSONL
// (offline, without a database). It decodes one record per line in
// ascending seq order and runs the identical chain walk Verify uses, so
// an offsite/WORM export can be checked on its own — the archive-plus-live
// composition ADR-017 describes. Malformed JSON or a decode failure is
// returned as an error (the input is not a valid export), distinct from a
// clean tamper verdict (OK == false).
//
// Scope of the guarantee (R2, ATR-240 security review): a clean verdict
// here proves only the segment's OWN internal chain consistency — that
// its rows, taken together, form an unbroken hash chain. It does NOT by
// itself prove the file handed to this function is the genuine article an
// operator originally exported: an attacker who can replace the file on
// disk can regenerate a fully self-consistent (but fabricated) segment
// from scratch, since nothing here binds the file's bytes to anything
// outside the file. This offline check has real anti-tamper value only
// when the file itself is protected by something outside this process —
// stored on immutable/WORM media, or checked against a hash recorded
// independently (e.g. at export time, in a separately retained log) —
// the same "external reference predating the alleged truncation"
// principle ADR-017's "Limitations" section states for the live-anchor
// case.
func VerifyJSONL(r io.Reader) (VerifyReport, error) {
	w := newChainWalker()
	sc := bufio.NewScanner(r)
	// Audit lines are small, but Details is unbounded in principle; raise
	// the token limit well above bufio's 64KiB default so a large event
	// does not spuriously fail an otherwise-valid export.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue // tolerate blank lines between records
		}
		rec, err := decodeJSONLRecord(raw)
		if err != nil {
			return VerifyReport{}, fmt.Errorf("audit: verify jsonl: line %d: %w", line, err)
		}
		if err := w.step(rec); err != nil {
			if errors.Is(err, errStopWalk) {
				break
			}
			return VerifyReport{}, fmt.Errorf("audit: verify jsonl: line %d: %w", line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return VerifyReport{}, fmt.Errorf("audit: verify jsonl: read: %w", err)
	}
	return w.report()
}

// decodeJSONLRecord parses one ExportJSONL line back into a Recorded,
// reversing the jsonlRecord shape ExportJSONL emits (including the
// RFC3339Nano timestamp and the raw Details object).
func decodeJSONLRecord(raw []byte) (Recorded, error) {
	var jr jsonlRecord
	if err := json.Unmarshal(raw, &jr); err != nil {
		return Recorded{}, fmt.Errorf("decode: %w", err)
	}

	ts, err := time.Parse(time.RFC3339Nano, jr.Timestamp)
	if err != nil {
		return Recorded{}, fmt.Errorf("parse timestamp %q: %w", jr.Timestamp, err)
	}

	var details map[string]any
	if len(jr.Details) > 0 {
		if err := json.Unmarshal(jr.Details, &details); err != nil {
			return Recorded{}, fmt.Errorf("decode details: %w", err)
		}
	}

	return Recorded{
		Event: Event{
			Timestamp: ts,
			Type:      jr.Type,
			Actor:     jr.Actor,
			MessageID: jr.MessageID,
			Recipient: jr.Recipient,
			Details:   details,
		},
		ID:       jr.ID,
		Seq:      jr.Seq,
		PrevHash: jr.PrevHash,
	}, nil
}

// errStopWalk is an internal sentinel used to stop a StreamEvents/JSONL
// walk early once the first break is found. It never escapes Verify/
// VerifyJSONL — both translate it back into the recorded Break.
var errStopWalk = errors.New("audit: stop walk")

// checkpointInfo records the anchor a retention_checkpoint declares, used
// after the walk to confirm a non-genesis start is vouched for.
type checkpointInfo struct {
	seq       int64
	anchorSeq int64
}

// chainWalker accumulates verification state across a single ascending-seq
// pass. It is not safe for concurrent use; each Verify/VerifyJSONL call
// owns its own walker.
type chainWalker struct {
	n               int64
	firstSeq        int64
	firstPrevHash   string
	firstType       Type
	firstAnchorHash string
	prevSeq         int64
	prevHash        string // recomputed hash of the previous row
	checkpoints     map[string]checkpointInfo
	brk             *Break
}

func newChainWalker() *chainWalker {
	return &chainWalker{checkpoints: make(map[string]checkpointInfo)}
}

// step processes one record in ascending seq order. It returns errStopWalk
// once a break is recorded so the caller can stop reading; any other
// non-nil error is a genuine failure (e.g. Details that cannot be
// canonicalized) that should abort verification.
func (w *chainWalker) step(rec Recorded) error {
	h, err := HashRecord(rec)
	if err != nil {
		return fmt.Errorf("hash event seq %d: %w", rec.Seq, err)
	}

	if w.n == 0 {
		w.firstSeq = rec.Seq
		w.firstPrevHash = rec.PrevHash
		w.firstType = rec.Type
		if rec.Type == TypeRetentionCheckpoint {
			w.firstAnchorHash = detailString(rec.Details, DetailAnchorHash)
		}
	} else {
		// Seq contiguity: the live log is always a contiguous suffix
		// (retention only ever removes a whole prefix), so an internal gap
		// means a row was removed or its seq was altered. Checking this
		// before the hash gives a clearer message for a deletion.
		if rec.Seq != w.prevSeq+1 {
			w.brk = &Break{
				Seq:              rec.Seq,
				ExpectedPrevHash: w.prevHash,
				ActualPrevHash:   rec.PrevHash,
				Reason: fmt.Sprintf("sequence gap: expected seq %d after %d, got %d (an event was removed or its seq altered)",
					w.prevSeq+1, w.prevSeq, rec.Seq),
			}
			return errStopWalk
		}
		if rec.PrevHash != w.prevHash {
			w.brk = &Break{
				Seq:              rec.Seq,
				ExpectedPrevHash: w.prevHash,
				ActualPrevHash:   rec.PrevHash,
				Reason: fmt.Sprintf("prev_hash of seq %d does not match the recomputed hash of seq %d "+
					"(an event was altered, removed, or reordered)", rec.Seq, rec.Seq-1),
			}
			return errStopWalk
		}
	}

	if rec.Type == TypeRetentionCheckpoint {
		w.checkpoints[detailString(rec.Details, DetailAnchorHash)] = checkpointInfo{
			seq:       rec.Seq,
			anchorSeq: detailInt(rec.Details, DetailAnchorSeq),
		}
	}

	w.prevSeq = rec.Seq
	w.prevHash = h
	w.n++
	return nil
}

// report renders the accumulated state into a VerifyReport once the walk
// has finished (or stopped at a break).
func (w *chainWalker) report() (VerifyReport, error) {
	if w.brk != nil {
		return VerifyReport{
			OK:                 false,
			EventsChecked:      w.n,
			CheckpointsPresent: len(w.checkpoints),
			FirstSeq:           w.firstSeq,
			Break:              w.brk,
		}, nil
	}

	if w.n == 0 {
		return VerifyReport{OK: true, StartMode: StartEmpty}, nil
	}

	rep := VerifyReport{
		EventsChecked:      w.n,
		CheckpointsPresent: len(w.checkpoints),
		FirstSeq:           w.firstSeq,
	}

	// Genesis: the earliest surviving event has no predecessor. The chain
	// is complete from the beginning; nothing anchors it and nothing needs
	// to.
	if w.firstPrevHash == "" {
		rep.OK = true
		rep.StartMode = StartGenesis
		return rep, nil
	}

	// A non-empty first prev_hash means a prefix was truncated (ADR-017).
	// The removal is trusted only if a surviving retention_checkpoint
	// recorded exactly this prev_hash as its anchor_hash. Without one, the
	// anchor cannot be established from the live log — the checkpoint that
	// would vouch for it is itself gone — so the trust root is unproven.
	cp, ok := w.checkpoints[w.firstPrevHash]
	if !ok {
		rep.OK = false
		rep.Break = &Break{
			Seq:            w.firstSeq,
			ActualPrevHash: w.firstPrevHash,
			Reason: "the earliest surviving event has a non-empty prev_hash but no retention_checkpoint " +
				"anchoring it is present: the truncation anchor cannot be established from the live log",
		}
		return rep, nil
	}

	// The checkpoint's declared anchor_seq must be exactly one below the
	// earliest surviving seq. This holds for both the normal anchored
	// resume (first row is the data row after the boundary) and the
	// degenerate self-anchoring case (the checkpoint at old_max+1 anchors
	// old_max), so it is a uniform consistency check.
	if cp.anchorSeq != w.firstSeq-1 {
		rep.OK = false
		rep.Break = &Break{
			Seq:            w.firstSeq,
			ActualPrevHash: w.firstPrevHash,
			Reason: fmt.Sprintf("anchoring checkpoint records anchor_seq=%d but the earliest surviving "+
				"event is seq=%d (expected anchor_seq=%d)", cp.anchorSeq, w.firstSeq, w.firstSeq-1),
		}
		return rep, nil
	}

	rep.OK = true
	// Degenerate self-anchoring checkpoint: the only surviving row is the
	// checkpoint itself, whose prev_hash equals its own anchor_hash.
	if w.n == 1 && w.firstType == TypeRetentionCheckpoint && w.firstAnchorHash == w.firstPrevHash {
		rep.StartMode = StartSelfAnchoringCheckpoint
	} else {
		rep.StartMode = StartAnchoredResume
	}
	return rep, nil
}

// detailString reads a string-valued Details field, returning "" when
// absent or of another type. Details always arrives here from a JSON
// unmarshal (live scan or JSONL decode), so a stored string is a Go
// string.
func detailString(details map[string]any, key string) string {
	if details == nil {
		return ""
	}
	if v, ok := details[key].(string); ok {
		return v
	}
	return ""
}

// detailInt reads an integer-valued Details field. JSON unmarshaling
// yields float64 for numbers (and json.Number if a decoder set UseNumber);
// both are handled so the anchor_seq check works regardless of the decode
// path. Returns -1 when absent or non-numeric, a value that cannot equal a
// real firstSeq-1 (>= 0) and so surfaces a malformed checkpoint as a
// mismatch rather than a silent pass.
func detailInt(details map[string]any, key string) int64 {
	if details == nil {
		return -1
	}
	switch v := details[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
	}
	return -1
}
