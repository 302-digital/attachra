// Package retention implements the background storage-retention
// cleanup job (US-5.3/ATR-179, T-5.3.2): periodically it finds
// attachments whose configured retention deadline has elapsed
// (internal/core/link.Engine.CreateLinks writes that deadline at
// creation time, ATR-178/SR-123-1) and deletes both the storage object
// and its metadata, consistently and idempotently (SR-123-2).
//
// Legal hold (ATR-259, docs/compliance/journaling-position.md §4) is
// enforced in two layers, not one, because a chunked sweep pass can
// take seconds to tens of seconds to work through a single chunk (each
// attachment's storage delete is a network call), which is a real
// window for a hold to be set in reaction to litigation (a "race to
// preserve") after this pass already started:
//
//  1. store.MetadataStore.ListExpiredAttachments excludes held
//     attachments at the SQL query level (T0): Sweeper is never handed
//     an attachment that was already held at listing time.
//  2. Sweeper.purgeOne re-checks store.MetadataStore.IsAttachmentHeld
//     immediately before the storage delete for each individual
//     attachment, narrowing (not eliminating) the window between T0 and
//     that attachment's own turn; store.MetadataStore.DeleteAttachment's
//     own guarded DELETE is the final, atomic backstop for the metadata
//     half of the deletion, catching a hold set even after the re-check
//     above passed.
//
// What this package does NOT claim: storage.Driver.Delete and
// store.MetadataStore.DeleteAttachment are two separate calls against
// two separate systems that cannot share one transaction. If a hold is
// set in the narrow interval between the re-check in (2) and the
// storage delete completing, the object's bytes are already gone by the
// time DeleteAttachment's guard refuses to remove the metadata row —
// the Attachment row survives (so the fact of what existed is not
// lost), but its payload cannot be un-deleted by this package. Closing
// that last, sub-operation window would require a distributed
// transaction spanning the object store and the metadata store, which
// this codebase does not have; see purgeOne's doc comment for exactly
// where this residual case surfaces and how it is reported (a held
// skip, distinct from a clean deletion, per ATR-259's own requirement
// that a hold-skip be visible separately from ordinary cleanup — never
// silently folded into a successful Deleted count).
//
// Sweeper depends only on internal/core packages (store, storage,
// audit, metrics) and holds no adapter-specific state (ADR-002); the
// periodic trigger (a time.Ticker loop bound to a shutdown context) is
// wired up by cmd/attachra, mirroring how cmd/attachra owns the SIGHUP
// policy-reload loop for internal/core/policy.Store.
package retention

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/storage"
	"github.com/302-digital/attachra/internal/core/store"
)

// defaultChunkSize is used when Params.ChunkSize is not positive.
const defaultChunkSize = 100

// sweepActor identifies the background retention sweep as the Actor
// for every audit event Sweep records: it is an unattended, scheduled
// action with no human or API principal behind it, matching the
// "system"/"milter" actor-attribution convention link.Engine and
// pipeline already use for their own non-interactive audit events.
const sweepActor = "system"

// Params bundles Sweeper's dependencies.
type Params struct {
	// Metadata is the metadata store the sweep reads expired
	// attachments from and deletes them via. Must not be nil.
	Metadata store.MetadataStore

	// Storage deletes each expired attachment's payload before its
	// metadata row is removed. Must not be nil.
	Storage storage.Driver

	// AuditSink receives one audit.Event per deleted (or
	// failed-to-delete) attachment, plus, when applicable, one
	// held-skip summary event per Sweep call (ATR-259). A nil
	// AuditSink is replaced with audit.NopSink{}, matching
	// link.Engine's own nil-defaulting posture.
	AuditSink audit.AuditSink

	// AuditTruncator, when non-nil together with a positive
	// AuditRetention, lets each Sweep pass also truncate the tamper-
	// evident audit log's old, contiguous, hold-respecting prefix
	// (ATR-308, ADR-017). Nil (or a non-positive AuditRetention) leaves
	// the audit log append-only forever — the default, opt-in-off
	// behavior. cmd/attachra wires the sqlite Store here, which
	// implements audit.Truncator.
	AuditTruncator audit.Truncator

	// AuditRetention is how long audit events are kept before Sweep
	// truncates them (config retention.audit_retention_seconds). A
	// non-positive value disables audit truncation regardless of
	// AuditTruncator. Separate from the file/link retention deadline,
	// which is written per-attachment at link creation.
	AuditRetention time.Duration

	// Metrics receives Prometheus observations for each attachment
	// processed. A nil Metrics is valid: every metrics.Metrics method
	// is nil-safe, so Sweeper never needs its own nil check before
	// calling it.
	Metrics *metrics.Metrics

	// Logger receives structured diagnostics, in particular one
	// warning per attachment Sweep failed to purge (Sweep does not
	// abort the whole pass on a single failure — see its doc comment).
	// May be nil.
	Logger *slog.Logger

	// ChunkSize bounds how many expired attachments Sweep fetches per
	// ListExpiredAttachments call (ADR-011's "chunked DELETE"
	// guidance): a large backlog is drained over several short,
	// independent database round trips instead of one big one, so no
	// single call holds the sqlite single-writer connection for long.
	// Non-positive falls back to defaultChunkSize.
	ChunkSize int
}

// Sweeper runs the periodic retention cleanup pass described in this
// package's doc comment. It is safe for concurrent use, though in
// practice cmd/attachra drives exactly one Sweeper from a single
// ticker-owned goroutine.
type Sweeper struct {
	metadata       store.MetadataStore
	storage        storage.Driver
	audit          audit.AuditSink
	auditTruncator audit.Truncator
	auditRetention time.Duration
	metrics        *metrics.Metrics
	logger         *slog.Logger
	chunkSize      int

	// now is overridable for deterministic tests; production code
	// always uses the zero value, which falls back to time.Now.
	now func() time.Time
}

// New constructs a Sweeper from p. It returns an error if a required
// dependency is missing.
func New(p Params) (*Sweeper, error) {
	if p.Metadata == nil {
		return nil, fmt.Errorf("retention: new sweeper: Metadata must not be nil")
	}
	if p.Storage == nil {
		return nil, fmt.Errorf("retention: new sweeper: Storage must not be nil")
	}

	sink := p.AuditSink
	if sink == nil {
		sink = audit.NopSink{}
	}

	chunkSize := p.ChunkSize
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}

	return &Sweeper{
		metadata:       p.Metadata,
		storage:        p.Storage,
		audit:          sink,
		auditTruncator: p.AuditTruncator,
		auditRetention: p.AuditRetention,
		metrics:        p.Metrics,
		logger:         p.Logger,
		chunkSize:      chunkSize,
	}, nil
}

func (s *Sweeper) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Sweeper) nowText() string {
	return s.clock().UTC().Format(time.RFC3339Nano)
}

func (s *Sweeper) log() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// recordAudit appends ev via the configured AuditSink, never
// propagating a failure: a deletion that already durably happened
// (or a hold-skip fact that already happened) must not be treated as
// failed just because the audit trail could not be written, mirroring
// link.Engine.recordAudit's identical contract and rationale.
func (s *Sweeper) recordAudit(ctx context.Context, ev audit.Event) {
	_, _ = s.audit.Record(ctx, ev) //nolint:errcheck // best-effort, see doc comment above.
}

// Result summarizes one Sweep call's outcome.
type Result struct {
	// Deleted is the number of attachments whose storage object and
	// metadata were both successfully removed.
	Deleted int

	// HeldSkipped is the number of attachments whose retention had
	// elapsed but were skipped because at least one of their links is
	// under legal hold (ATR-259). It combines two populations: those
	// excluded up front by ListExpiredAttachments' own query-level hold
	// check (left entirely untouched, both storage object and metadata
	// intact) and those detected as held mid-purge by purgeOne (a rarer
	// race; see purgeOne's doc comment for why the object's bytes may
	// already be gone in that case even though the metadata row
	// survives). Both are reported under this one field and as
	// individually distinguishable audit events, since both represent
	// "this attachment was not cleanly deleted because of a hold" from
	// an operator's point of view.
	HeldSkipped int

	// Failed is the number of attachments Sweep attempted to purge but
	// could not (a storage or metadata error); each is logged and
	// audited individually, and Sweep continues with the rest of the
	// pass rather than aborting.
	Failed int

	// ExpiredLinks is the number of Link rows marked LinkStatusExpired
	// by this pass — the parent US-5.3 acceptance criterion "marks
	// links as expired" (see store.MetadataStore.ExpireStaleLinks'
	// doc comment for why this is a non-destructive, not
	// hold-sensitive, bookkeeping update).
	ExpiredLinks int

	// AuditTruncated is the number of audit-log events this pass removed
	// via checkpoint truncation (ATR-308, ADR-017). Zero whenever audit
	// retention is disabled (the default) or nothing was eligible.
	AuditTruncated int64
}

// Sweep runs one retention cleanup pass: it marks stale links expired,
// records upfront how many expired attachments are excluded from every
// batch it is about to fetch by ListExpiredAttachments' own hold check
// (a single summary audit event, distinct from the per-attachment
// deletion events recorded during the loop below — ATR-259: "audit
// reflects hold-skips separately"), then repeatedly fetches and
// purges chunks of the remaining expired attachments until none
// remain. A held attachment detected later — during an individual
// attachment's own purge, per purgeOne's doc comment, because a hold
// landed after this pass had already started — is also counted in
// Result.HeldSkipped and audited with its own per-attachment event,
// alongside (not double-counting) the upfront summary: the upfront
// count and the mid-loop detections cover disjoint populations only
// because the count is taken before the loop runs, not after (see the
// implementation's own comment on this ordering).
//
// Sweep never aborts early because a single attachment's purge failed:
// each failure is logged, audited as its own TypeRetentionCleanup event
// with ok=false, counted in the returned Result.Failed, and the pass
// continues onto the next attachment/chunk — a background job must not
// let one bad row block cleanup of the rest of an expired backlog. A
// failure caused by ctx being canceled mid-purge is not counted or
// audited as a failure at all (see purgeAndRecord's doc comment): it is
// simply left for the next Sweep call to retry.
//
// Sweep does return a non-nil error if listing expired attachments
// itself fails (a store outage): no useful work can continue past that
// without silently skipping an unknown portion of the backlog.
//
// ctx cancellation is checked both between chunks and before each
// individual attachment within a chunk: once ctx is done, Sweep stops
// issuing new destructive calls as promptly as it can and returns
// immediately with whatever partial Result has accumulated so far, no
// error. Any attachment left mid-purge by this (storage deleted, its
// metadata not yet, or vice versa where DeleteAttachment tolerates
// ErrNotFound) is not a permanent inconsistency: the next Sweep call
// re-lists it (its metadata row, if not yet removed, is unchanged) and
// completes the purge, tolerating the half already done exactly as
// purgeOne's own idempotency contract already requires for any other
// interrupted run (a process crash, not just a graceful ctx
// cancellation).
func (s *Sweeper) Sweep(ctx context.Context) (Result, error) {
	var res Result

	now := s.nowText()

	if expired, err := s.metadata.ExpireStaleLinks(ctx, now); err != nil {
		s.log().Warn("retention: failed to mark stale links expired", "error", err.Error())
	} else {
		res.ExpiredLinks = expired
		s.metrics.ObserveRetentionExpiredLinks(expired)
	}

	// The held-at-T0 count is taken here, immediately before the first
	// ListExpiredAttachments call below (and using the same now
	// cutoff), so it captures exactly the population
	// ListExpiredAttachments' own query excludes from every batch this
	// pass will see: attachments already held at this instant. Taking
	// it here — rather than after the purge loop below, once purging
	// has had time to run and any race-injected holds have already
	// landed — avoids double-counting an attachment that purgeAndRecord
	// separately reports as HeldSkipped when a hold lands on it mid-loop
	// (see purgeOne's doc comment for that scenario): these two
	// counting mechanisms cover disjoint populations only if the count
	// below is taken before the loop runs, not after.
	heldAtStart, err := s.metadata.CountHeldExpiredAttachments(ctx, now)
	if err != nil {
		s.log().Warn("retention: failed to count held expired attachments", "error", err.Error())
	} else if heldAtStart > 0 {
		res.HeldSkipped += heldAtStart
		for i := 0; i < heldAtStart; i++ {
			s.metrics.ObserveRetentionCleanup("held_skipped")
		}
		s.recordAudit(ctx, audit.Event{
			Type:  audit.TypeRetentionCleanup,
			Actor: sweepActor,
			Details: map[string]any{
				"scope":              "held_summary",
				"held_skipped_count": heldAtStart,
			},
		})
	}

chunkLoop:
	for {
		if err := ctx.Err(); err != nil {
			break
		}

		batch, err := s.metadata.ListExpiredAttachments(ctx, now, s.chunkSize)
		if err != nil {
			return res, fmt.Errorf("retention: sweep: list expired attachments: %w", err)
		}
		if len(batch) == 0 {
			break
		}

		for _, a := range batch {
			if err := ctx.Err(); err != nil {
				break chunkLoop
			}
			s.purgeAndRecord(ctx, a, &res)
		}

		if len(batch) < s.chunkSize {
			// The store returned fewer rows than requested: the
			// backlog is drained for this now cutoff, no point issuing
			// another round trip that would return the same (or an
			// empty) result.
			break
		}
	}

	s.sweepAudit(ctx, &res)

	return res, nil
}

// sweepAudit truncates the tamper-evident audit log's old, contiguous,
// hold-respecting prefix (ATR-308, ADR-017), when — and only when —
// audit retention is configured (a non-nil Truncator and a positive
// retention window). It is a no-op otherwise, keeping the log
// append-only forever by default.
//
// Like every other step of a Sweep pass, a failure here is logged and
// swallowed rather than propagated: audit truncation is background
// housekeeping, and a store hiccup on it must not fail the whole sweep
// (which also purges expired attachments). The truncation itself is
// atomic and records its own checkpoint event, so a failure simply
// leaves the log un-truncated for the next pass to retry — never a
// half-truncated, unverifiable chain. A canceled ctx is treated the same
// way (nothing to report; the next pass retries).
func (s *Sweeper) sweepAudit(ctx context.Context, res *Result) {
	if s.auditTruncator == nil || s.auditRetention <= 0 {
		return
	}
	if err := ctx.Err(); err != nil {
		return
	}

	cutoff := s.clock().Add(-s.auditRetention)
	out, err := s.auditTruncator.TruncateAudit(ctx, audit.TruncateRequest{
		Cutoff: cutoff,
		Actor:  sweepActor,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		s.log().Warn("retention: failed to truncate audit log", "error", err.Error())
		return
	}
	if out.Truncated {
		res.AuditTruncated = out.TruncatedCount
		s.metrics.ObserveAuditTruncation(out.TruncatedCount)
		return
	}
	if out.HeldClamped {
		// The entire eligible prefix was pinned by legal hold (N1, per
		// security review): without this log line, a pass that removes
		// nothing is silent — an operator who enabled
		// audit_retention_seconds and sees no growth relief has no signal
		// why. This is also a documented footgun (ADR-017 "Limitations",
		// docs/architecture/audit-retention.md): an authorized insider
		// with hold-setting privileges can set (and never lift) a hold on
		// one old, low-value message to indefinitely defeat truncation of
		// the whole prefix behind it, with no DB-level access required.
		s.log().Warn("retention: audit truncation fully blocked by legal hold",
			"cutoff", cutoff.UTC().Format(time.RFC3339Nano))
	}
}

// purgeAndRecord purges a single attachment, updates res and metrics,
// and records the corresponding per-attachment audit event — except
// when purgeOne's only error is ctx having been canceled mid-purge, in
// which case nothing is recorded at all (N2, per security review): a
// shutdown/timeout landing on one particular attachment is not a
// per-attachment failure, and treating it as one would flood the audit
// log with ok=false events for attachments that were never genuinely
// attempted to completion, every single time a sweep pass happens to
// be interrupted. The next Sweep call simply retries that attachment
// (purgeOne's own idempotency contract), so there is nothing meaningful
// to report for this occurrence.
func (s *Sweeper) purgeAndRecord(ctx context.Context, a store.Attachment, res *Result) {
	heldSkip, err := s.purgeOne(ctx, a)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		res.Failed++
		s.metrics.ObserveRetentionCleanup("error")
		s.log().Warn("retention: failed to purge expired attachment",
			"attachment_id", a.ID, "message_id", a.MessageID, "error", err.Error())
		s.recordAudit(ctx, audit.Event{
			Type:      audit.TypeRetentionCleanup,
			Actor:     sweepActor,
			MessageID: a.MessageID,
			Details: map[string]any{
				"scope":         "deletion",
				"attachment_id": a.ID,
				"storage_key":   a.StorageKey,
				"ok":            false,
				"error":         err.Error(),
			},
		})
		return
	}

	if heldSkip {
		res.HeldSkipped++
		s.metrics.ObserveRetentionCleanup("held_skipped")
		s.recordAudit(ctx, audit.Event{
			Type:      audit.TypeRetentionCleanup,
			Actor:     sweepActor,
			MessageID: a.MessageID,
			Details: map[string]any{
				"scope":         "deletion",
				"attachment_id": a.ID,
				"storage_key":   a.StorageKey,
				"ok":            false,
				"held":          true,
			},
		})
		return
	}

	res.Deleted++
	s.metrics.ObserveRetentionCleanup("deleted")
	s.recordAudit(ctx, audit.Event{
		Type:      audit.TypeRetentionCleanup,
		Actor:     sweepActor,
		MessageID: a.MessageID,
		Details: map[string]any{
			"scope":         "deletion",
			"attachment_id": a.ID,
			"storage_key":   a.StorageKey,
			"ok":            true,
		},
	})
}

// purgeOne re-checks hold status, then, if still not held, deletes a's
// storage object (tolerating storage.ErrNotFound — a previous,
// partially-completed sweep may have already removed it, SR-123-2's
// idempotency requirement) and only then deletes its Attachment + Link
// metadata rows (tolerating store.ErrNotFound for the same reason).
// heldSkip is true whenever this attachment was left untouched because
// of a hold, whether detected by the re-check up front or by
// DeleteAttachment's own guard afterward; it is mutually exclusive with
// a non-nil err.
//
// The re-check (store.MetadataStore.IsAttachmentHeld) exists because
// this specific attachment may have sat in its chunk for a while behind
// other attachments' own storage deletes before its own turn arrived
// (ATR-259 B1 fix, added after security review identified the gap
// between ListExpiredAttachments' T0 exclusion and an individual
// attachment's actual purge as a real window for a hold to land in). It
// must run before storage.Delete, not after: a hold set after the
// bytes are already gone cannot be un-done by refusing to delete
// metadata alone (see this package's doc comment for that residual
// case, which DeleteAttachment's own guard still catches for the
// metadata half even though the object is already gone by then).
//
// Storage is always deleted before metadata otherwise. If a crash (or a
// canceled ctx, per Sweep's own doc comment) lands between the two
// steps, the metadata row — and therefore this attachment's continued
// ListExpiredAttachments candidacy — is untouched, so the next Sweep
// call simply retries the same attachment, this time finding the
// storage object already gone and treating that as success. No such
// interruption can therefore leave a storage object permanently
// orphaned with no metadata ever pointing back to it again, which is
// the failure direction retention cleanup specifically exists to close
// off (the opposite asymmetry — metadata surviving with a dangling
// storage key after a rollback — is the direction
// pipeline.AttachmentProcessor already accepts as safe for the upload
// path; see Process's own doc comment for why that is a different,
// already-documented trade-off, not a precedent this method follows).
func (s *Sweeper) purgeOne(ctx context.Context, a store.Attachment) (heldSkip bool, err error) {
	held, err := s.metadata.IsAttachmentHeld(ctx, a.ID)
	if err != nil {
		return false, fmt.Errorf("check hold status: %w", err)
	}
	if held {
		return true, nil
	}

	if err := s.storage.Delete(ctx, a.StorageKey); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return false, fmt.Errorf("delete storage object %q: %w", a.StorageKey, err)
	}

	if err := s.metadata.DeleteAttachment(ctx, a.ID); err != nil {
		if errors.Is(err, store.ErrHeld) {
			// A hold landed in the narrower window between the
			// re-check above and this call — the storage object's
			// bytes are already gone, but DeleteAttachment's guard
			// still refused to remove the metadata row, so at least the
			// Attachment row (and its retention deadline) survives as a
			// record of what existed. See this package's doc comment
			// for why this specific outcome is the one residual case
			// this design documents rather than eliminates.
			return true, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return false, fmt.Errorf("delete attachment metadata %q: %w", a.ID, err)
		}
	}

	return false, nil
}
