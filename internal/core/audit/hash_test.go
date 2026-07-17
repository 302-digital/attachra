package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func baseRecord() Recorded {
	return Recorded{
		Event: Event{
			Timestamp: time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC),
			Type:      TypeDownload,
			Actor:     "actor",
			MessageID: "msg-1",
			Recipient: "user@example.com",
			Details:   map[string]any{"k": "v"},
		},
		ID:       "id-1",
		Seq:      1,
		PrevHash: "prev",
	}
}

// TestHashRecordDeterministic asserts HashRecord is a pure function of
// its input: the same record hashes to the same value every time.
func TestHashRecordDeterministic(t *testing.T) {
	a, err := HashRecord(baseRecord())
	if err != nil {
		t.Fatalf("HashRecord() error = %v, want nil", err)
	}
	b, err := HashRecord(baseRecord())
	if err != nil {
		t.Fatalf("HashRecord() error = %v, want nil", err)
	}
	if a != b {
		t.Errorf("HashRecord() is not deterministic: %q != %q", a, b)
	}
}

// TestHashRecordSensitiveToEveryField asserts that changing any single
// field changes the hash — the property SR-128-1 tamper-evidence relies
// on. PrevHash is included because that is how a tampered/removed earlier
// row is detected (it changes the next row's recomputed hash).
func TestHashRecordSensitiveToEveryField(t *testing.T) {
	base, err := HashRecord(baseRecord())
	if err != nil {
		t.Fatalf("HashRecord() error = %v, want nil", err)
	}

	mutators := map[string]func(*Recorded){
		"prevHash":  func(r *Recorded) { r.PrevHash = "different" },
		"id":        func(r *Recorded) { r.ID = "id-2" },
		"seq":       func(r *Recorded) { r.Seq = 2 },
		"timestamp": func(r *Recorded) { r.Timestamp = r.Timestamp.Add(time.Second) },
		"type":      func(r *Recorded) { r.Type = TypeRevoke },
		"actor":     func(r *Recorded) { r.Actor = "other" },
		"messageID": func(r *Recorded) { r.MessageID = "msg-2" },
		"recipient": func(r *Recorded) { r.Recipient = "other@example.com" },
		"details":   func(r *Recorded) { r.Details = map[string]any{"k": "other"} },
	}

	for field, mutate := range mutators {
		rec := baseRecord()
		mutate(&rec)
		got, err := HashRecord(rec)
		if err != nil {
			t.Fatalf("HashRecord() error = %v, want nil", err)
		}
		if got == base {
			t.Errorf("changing %s did not change HashRecord() output", field)
		}
	}
}

// legacyChainHash independently reproduces the exact construction
// internal/core/store/sqlite's chainHash used before HashRecord existed
// (SHA-256 of "%s|%s|%d|%s|%s|%s|%s|%s|%s" over prevHash, id, seq,
// UTC-RFC3339Nano timestamp, type, actor, messageID, recipient,
// detailsJSON), computed here from scratch rather than by calling
// HashRecord, so TestHashRecordMatchesLegacyFormat is a genuine
// byte-for-byte comparison against an independent reference
// implementation of the pre-ATR-240 format — not a tautology that would
// pass even if HashRecord's construction silently changed.
func legacyChainHash(t *testing.T, rec Recorded) string {
	t.Helper()
	detailsJSON, err := canonicalDetailsJSON(rec.Details)
	if err != nil {
		t.Fatalf("canonicalDetailsJSON() error = %v", err)
	}
	h := sha256.New()
	msg := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s",
		rec.PrevHash, rec.ID, rec.Seq, rec.Timestamp.UTC().Format(time.RFC3339Nano),
		rec.Type, rec.Actor, rec.MessageID, rec.Recipient, string(detailsJSON))
	if _, err := h.Write([]byte(msg)); err != nil {
		t.Fatalf("hash.Write() error = %v", err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestHashRecordMatchesLegacyFormat pins HashRecord to the existing
// "|"-delimited chain-hash construction (ATR-240 review: length-prefixed
// framing was deferred to ATR-353 specifically because switching the
// construction would make `attachra audit verify` report a false
// "tampered" verdict against every pre-existing audit log, including the
// live pilot database). If this test ever fails, HashRecord no longer
// reproduces the format existing on-disk logs were hashed with, and
// `attachra audit verify` will break backward compatibility.
func TestHashRecordMatchesLegacyFormat(t *testing.T) {
	recs := []Recorded{
		baseRecord(),
		{
			Event: Event{
				Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Type:      TypeRetentionCheckpoint,
				Actor:     "system",
				Details: map[string]any{
					DetailAnchorSeq:  10,
					DetailAnchorHash: "somehash",
				},
			},
			ID:       "cp-1",
			Seq:      11,
			PrevHash: "",
		},
		{
			Event: Event{Timestamp: time.Date(2026, 3, 4, 5, 6, 7, 8, time.UTC), Type: TypeError, Actor: ""},
			ID:    "e-1", Seq: 3, PrevHash: "abc",
		},
	}

	for i, rec := range recs {
		got, err := HashRecord(rec)
		if err != nil {
			t.Fatalf("HashRecord(#%d) error = %v", i, err)
		}
		want := legacyChainHash(t, rec)
		if got != want {
			t.Errorf("HashRecord(#%d) = %q, want legacy format %q", i, got, want)
		}
	}
}

// TestHashRecordDetailsCanonicalization asserts an empty and a nil Details
// map hash identically (both canonicalize to "{}"), and that a record's
// hash is stable across a marshal/unmarshal round-trip of its Details —
// the property that makes a live-DB hash and a JSONL-round-tripped hash
// agree.
func TestHashRecordDetailsCanonicalization(t *testing.T) {
	nilDetails := baseRecord()
	nilDetails.Details = nil
	emptyDetails := baseRecord()
	emptyDetails.Details = map[string]any{}

	hn, err := HashRecord(nilDetails)
	if err != nil {
		t.Fatalf("HashRecord(nil details) error = %v", err)
	}
	he, err := HashRecord(emptyDetails)
	if err != nil {
		t.Fatalf("HashRecord(empty details) error = %v", err)
	}
	if hn != he {
		t.Errorf("nil and empty Details hash differently: %q != %q", hn, he)
	}

	// A number that survived a JSON round-trip arrives as float64; it must
	// hash the same as the int the store originally held (both encode to
	// the same canonical JSON text).
	asInt := baseRecord()
	asInt.Details = map[string]any{"n": int64(42)}
	asFloat := baseRecord()
	asFloat.Details = map[string]any{"n": float64(42)}

	hi, err := HashRecord(asInt)
	if err != nil {
		t.Fatalf("HashRecord(int details) error = %v", err)
	}
	hf, err := HashRecord(asFloat)
	if err != nil {
		t.Fatalf("HashRecord(float details) error = %v", err)
	}
	if hi != hf {
		t.Errorf("int and round-tripped float Details hash differently: %q != %q", hi, hf)
	}
}
