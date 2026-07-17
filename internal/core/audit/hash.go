package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// hashTimeLayout is the exact text form of the Timestamp field as it is
// fed into the chain hash. It matches the layout every timestamp column
// is stored with in internal/core/store/sqlite (time.RFC3339Nano) and the
// layout ExportJSONL writes, so a Recorded reconstructed from either the
// live database or an exported JSONL segment hashes byte-for-byte
// identically (the whole point of a verifiable chain).
const hashTimeLayout = time.RFC3339Nano

// HashRecord computes the tamper-evidence chain hash of one audit record
// (SR-128-1). The hash covers the record's own PrevHash plus every field
// of the record, so that altering or removing any earlier row — which
// changes that row's hash and therefore the PrevHash the next row was
// written with — makes every subsequent recomputed hash diverge. This is
// the single canonical hash used on BOTH sides of the tamper-evidence
// contract: the store computes it at write time to fill the next row's
// prev_hash column, and Verify/VerifyJSONL recompute it to check the
// chain. Both sides therefore MUST call this one function (ADR-017's
// "the canonical row-hash function ... will need it lifted to a shared
// location"): keeping it here, in the adapter-independent core/audit
// package, lets a verifier outside internal/core/store/sqlite reuse it
// without importing store internals (ADR-002).
//
// Field framing: this reproduces the SAME "|"-delimited construction
// that internal/core/store/sqlite's (now-removed) chainHash used before
// this function existed — byte-for-byte, field for field, in the same
// order — so `attachra audit verify` (ATR-240) can verify an EXISTING
// audit log (including the live grommunio pilot database and any
// offsite/WORM exports taken before this change) without a re-hash
// migration. A stricter, collision-proof length-prefixed framing was
// drafted during ATR-240 review but deliberately deferred to ATR-353
// (to ship with an explicit hash-format version so a verifier can tell
// which construction a given segment was written with) rather than
// shipped here: switching the construction unilaterally would make
// `attachra audit verify` report a false "FAILED: tampered" on every
// untouched pre-existing log on its very first run — worse than the
// residual risk deferring the hardening leaves open. Per ATR-240
// security review: the theoretical boundary collision this delimiter
// construction admits (a field containing the literal "|" separator
// shifting where one field ends and the next begins) is NOT practically
// exploitable here — Seq is a unique, strictly monotonic integer and ID
// is 128 bits of crypto/rand entropy, both present in every hashed
// tuple, so no attacker-controlled field combination can reproduce
// another row's full tuple. See ATR-353 for the tracked hardening.
//
// Details canonicalization. Details is serialized via canonicalDetailsJSON
// so the hashed bytes depend only on the record's logical content, not on
// incidental encoding differences between the map that produced a stored
// row and the map reconstructed by unmarshaling it back (Go's json.Marshal
// emits object keys in sorted order and is a deterministic, idempotent
// canonical form for the scalar/map/slice values audit Details holds, for
// every value shape any current producer writes — see canonicalDetailsJSON's
// own doc comment for the one known, accepted edge case).
func HashRecord(rec Recorded) (string, error) {
	detailsJSON, err := canonicalDetailsJSON(rec.Details)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	msg := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s",
		rec.PrevHash, rec.ID, rec.Seq, rec.Timestamp.UTC().Format(hashTimeLayout),
		rec.Type, rec.Actor, rec.MessageID, rec.Recipient, string(detailsJSON))
	// hash.Hash.Write never returns an error (its doc comment guarantees
	// this); the error is still checked to satisfy errcheck and to fail
	// loudly rather than silently if that contract is ever violated by a
	// future Go version.
	if _, err := h.Write([]byte(msg)); err != nil {
		panic(fmt.Sprintf("audit: HashRecord: hash.Hash.Write returned an error, violating its documented contract: %v", err))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// canonicalDetailsJSON returns the canonical JSON serialization of an
// event's Details map used inside the chain hash: an empty/nil map
// encodes to "{}" (never "null"), matching how the store persists an
// empty details column, and a populated map encodes via json.Marshal,
// which sorts object keys and is deterministic. Because json.Marshal is
// idempotent on values it produced (marshal(unmarshal(marshal(m))) ==
// marshal(m)), a record hashed from the live database and the same record
// hashed after a JSONL round-trip yield identical bytes here for every
// Details shape any current event producer writes.
//
// Known, accepted edge case: JSON numbers unmarshal into Go float64,
// which cannot exactly represent every integer above 2^53. A Details
// value written as an integer larger than that would round-trip to a
// different (rounded) float64 and therefore re-marshal to different
// digits, making a live-DB hash and a post-JSONL-round-trip hash of the
// same logical record diverge. No current event producer places a
// number that large in Details (message/attachment counts, byte sizes,
// and seq values recorded there stay far below 2^53), so this is a
// latent constraint on future producers, not an active gap.
func canonicalDetailsJSON(details map[string]any) ([]byte, error) {
	if len(details) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(details)
}
