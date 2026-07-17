package audit

import (
	"context"
	"errors"
	"time"
)

// ErrCursorTruncated is returned (wrapped) by ListEvents when a
// caller-supplied pagination cursor points strictly before the oldest
// surviving event, i.e. it references a range that audit retention
// (ADR-017) has since truncated. The HTTP layer maps this to 410 Gone:
// it is a distinct, explicit signal that the requested continuation
// range no longer exists, never a silent skip over the removed rows
// (SR-128-1 tamper-evidence would be meaningless if a client could lose
// events without noticing). A cursor positioned exactly at the anchor
// (the last truncated seq) resumes cleanly and does not trigger this.
var ErrCursorTruncated = errors.New("audit: cursor references truncated events")

// Detail keys for a TypeRetentionCheckpoint event's Details map
// (ADR-017). They are part of the on-the-wire audit contract consumed by
// export tooling and the future verifier (ATR-240), so they are named
// constants, not inline string literals scattered across producers.
const (
	// DetailAnchorSeq is the seq of the last truncated row (the anchor).
	// The first surviving data row has seq == DetailAnchorSeq + 1.
	DetailAnchorSeq = "anchor_seq"
	// DetailAnchorHash is the recomputed chain hash of the row at
	// DetailAnchorSeq: the trusted continuation point a verifier resumes
	// the surviving chain from. It equals the prev_hash of the first
	// surviving data row.
	DetailAnchorHash = "anchor_hash"
	// DetailTruncatedCount is how many rows this truncation removed.
	DetailTruncatedCount = "truncated_count"
	// DetailCutoff is the retention cutoff used, RFC3339Nano UTC: every
	// truncated row was strictly older than this instant.
	DetailCutoff = "cutoff"
	// DetailHeldClamped is true when the truncation boundary was lowered
	// (below the plain cutoff boundary) to avoid removing an event tied
	// to a message under legal hold (ATR-257/258).
	DetailHeldClamped = "held_clamped"
)

// TruncateRequest parameterizes a single audit-log truncation pass
// (ADR-017).
type TruncateRequest struct {
	// Cutoff is the retention boundary: only events strictly older than
	// Cutoff are eligible for removal. A contiguous seq-prefix, every row
	// of which is older than Cutoff, is truncated (see Truncator.
	// TruncateAudit for the exact boundary rule and the legal-hold
	// clamp).
	Cutoff time.Time

	// Actor identifies who or what initiated the truncation, recorded as
	// the checkpoint event's Actor (e.g. "system" for the background
	// sweeper). Never a bearer token or secret.
	Actor string
}

// TruncateResult reports the outcome of a TruncateAudit call.
type TruncateResult struct {
	// Truncated is true only when at least one row was removed (and,
	// therefore, a checkpoint event was written). A pass with nothing
	// eligible — an empty/young log, or one fully pinned by legal hold —
	// returns Truncated == false and writes no checkpoint, so an idle log
	// never accretes empty checkpoints (which would themselves defeat the
	// bounded-growth goal).
	Truncated bool

	// AnchorSeq is the seq of the last removed row; the first surviving
	// data row has seq == AnchorSeq + 1. Zero when Truncated is false.
	AnchorSeq int64

	// AnchorHash is the recomputed chain hash of the row at AnchorSeq,
	// echoed into the checkpoint event's DetailAnchorHash. Empty when
	// Truncated is false.
	AnchorHash string

	// TruncatedCount is the number of rows removed. Zero when Truncated
	// is false.
	TruncatedCount int64

	// HeldClamped is true when the boundary was lowered to spare an event
	// tied to a message under legal hold (see DetailHeldClamped). It can
	// be true even when Truncated is false (the whole eligible prefix was
	// pinned by a hold, so nothing was removed).
	HeldClamped bool

	// Checkpoint is the retention_checkpoint event that was appended,
	// populated only when Truncated is true.
	Checkpoint Recorded
}

// Truncator is the audit log's controlled truncation capability
// (ADR-017), kept deliberately separate from AuditSink so the SR-128-1
// "no update/delete reachable from an event producer" contract stays
// intact: mail-path and API producers depend only on AuditSink and can
// never reach a delete. Only the background retention sweeper
// (internal/core/retention), wired explicitly, depends on this
// interface. Implementations live alongside their AuditSink/Reader
// counterpart (MVP: internal/core/store/sqlite).
type Truncator interface {
	// TruncateAudit removes the contiguous seq-prefix of the audit log
	// whose every row is older than req.Cutoff, after clamping the
	// boundary down to spare any event tied to a message under legal
	// hold, and appends a TypeRetentionCheckpoint event anchoring the
	// survivors — all atomically (ADR-017, docs/architecture/
	// audit-retention.md). It must write no checkpoint and remove no rows
	// when nothing is eligible. It must never remove a row that is not
	// strictly older than req.Cutoff, nor one tied to a currently held
	// message. Safe for concurrent use.
	TruncateAudit(ctx context.Context, req TruncateRequest) (TruncateResult, error)
}
