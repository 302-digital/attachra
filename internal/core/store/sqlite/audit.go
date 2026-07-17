package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store"
)

var _ audit.AuditSink = (*Store)(nil)
var _ audit.Reader = (*Store)(nil)
var _ audit.ReaderLister = (*Store)(nil)
var _ audit.Truncator = (*Store)(nil)

// defaultAuditPageSize and maxAuditPageSize mirror the API contract's
// shared Limit parameter default/maximum (api/openapi.yaml, parameter
// Limit: 1..200, default 50), the same bounds every other ListXxx
// method in this package (e.g. ListLinks) enforces.
const (
	defaultAuditPageSize = 50
	maxAuditPageSize     = 200
)

// Record implements audit.AuditSink (SR-128-1/SR-128-2, ATR-189).
//
// Seq and PrevHash (the tamper-evidence hook SR-128-1 requires) are
// computed here, inside the same write, by reading the previous row's
// seq and re-deriving its chain hash before inserting the new one:
// PrevHash on the returned Recorded, and the persisted prev_hash
// column, are the previous row's hash, while this row's own hash is
// never stored directly — a future verifier recomputes it on demand
// (via chainHash) from the row's own columns plus the prev_hash it
// read, exactly as lastAuditRecord does here for the row being
// inserted now. This is safe from a lost-update race because it runs
// against s.db.writer, which ADR-011 caps to a single connection
// (SetMaxOpenConns(1)): every Record call from this process is already
// serialized with every other write (audit or otherwise) issued
// through this Store, so two concurrent Record calls cannot compute
// the same next seq. A transaction is used regardless, for atomicity
// should a future refactor widen the writer pool.
//
// Every value that can originate from mail content or other untrusted
// input (Actor, MessageID, Recipient, Details) is bound as a
// parameterized query argument, never formatted into the SQL string
// (SR-128-2). Details is marshaled to a JSON blob before binding, so
// arbitrarily nested untrusted data never touches SQL syntax.
func (s *Store) Record(ctx context.Context, ev audit.Event) (audit.Recorded, error) {
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	detailsJSON, err := marshalDetails(ev.Details)
	if err != nil {
		return audit.Recorded{}, fmt.Errorf("sqlite: record audit event: marshal details: %w", err)
	}

	id, err := newAuditID()
	if err != nil {
		return audit.Recorded{}, fmt.Errorf("sqlite: record audit event: %w", err)
	}

	tx, err := s.db.writer.BeginTx(ctx, nil)
	if err != nil {
		return audit.Recorded{}, fmt.Errorf("sqlite: record audit event: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // best-effort; Commit below is the success path.

	prevSeq, prevHash, err := lastAuditRecord(ctx, tx)
	if err != nil {
		return audit.Recorded{}, fmt.Errorf("sqlite: record audit event: read previous record: %w", err)
	}
	seq := prevSeq + 1

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_events (id, seq, prev_hash, type, actor, message_id, recipient, details, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, seq, prevHash, string(ev.Type), ev.Actor, ev.MessageID, ev.Recipient, detailsJSON, ts.Format(timeLayout),
	); err != nil {
		return audit.Recorded{}, fmt.Errorf("sqlite: record audit event: insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return audit.Recorded{}, fmt.Errorf("sqlite: record audit event: commit: %w", err)
	}

	rec := audit.Recorded{
		Event: audit.Event{
			Timestamp: ts,
			Type:      ev.Type,
			Actor:     ev.Actor,
			MessageID: ev.MessageID,
			Recipient: ev.Recipient,
			Details:   ev.Details,
		},
		ID:       id,
		Seq:      seq,
		PrevHash: prevHash,
	}
	return rec, nil
}

// StreamEvents implements audit.Reader. It streams rows matching
// filter directly from the underlying *sql.Rows cursor, calling fn once
// per row without ever materializing the full result set in memory
// (the streaming invariant), so ExportJSONL (internal/core/audit) can
// export an arbitrarily large audit log with bounded memory use.
func (s *Store) StreamEvents(ctx context.Context, filter audit.Filter, fn func(audit.Recorded) error) error {
	query := `SELECT id, seq, prev_hash, type, actor, message_id, recipient, details, created_at
	          FROM audit_events WHERE 1=1`
	var args []any

	if !filter.From.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, filter.From.UTC().Format(timeLayout))
	}
	if !filter.To.IsZero() {
		query += " AND created_at < ?"
		args = append(args, filter.To.UTC().Format(timeLayout))
	}
	if filter.Type != "" {
		query += " AND type = ?"
		args = append(args, string(filter.Type))
	}
	query += " ORDER BY seq ASC"

	rows, err := s.db.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("sqlite: stream audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		rec, err := scanAuditRecord(rows)
		if err != nil {
			return fmt.Errorf("sqlite: stream audit events: scan: %w", err)
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite: stream audit events: %w", err)
	}
	return nil
}

// ListEvents implements audit.ReaderLister (US-8.1/T-8.1.6,
// api/openapi.yaml `GET /audit`): one page of rows matching p, ordered
// ascending by seq, paginated with a keyset cursor over seq itself
// (the audit log's own monotonic ordering, so no separate (created_at,
// id) tuple is needed the way ListLinks needs one). It fetches one
// extra row (limit+1) to detect whether a further page exists, the
// same technique ListLinks uses, so NextCursor is populated without a
// second COUNT/lookahead query.
func (s *Store) ListEvents(ctx context.Context, p audit.ListParams) (audit.Page, error) {
	limit := store.ClampLimit(p.Limit, defaultAuditPageSize, maxAuditPageSize)

	query := `SELECT id, seq, prev_hash, type, actor, message_id, recipient, details, created_at
	          FROM audit_events WHERE 1=1`
	var args []any

	if !p.From.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, p.From.UTC().Format(timeLayout))
	}
	if !p.To.IsZero() {
		query += " AND created_at < ?"
		args = append(args, p.To.UTC().Format(timeLayout))
	}
	if p.Type != "" {
		query += " AND type = ?"
		args = append(args, string(p.Type))
	}
	if p.MessageID != "" {
		query += " AND message_id = ?"
		args = append(args, p.MessageID)
	}
	// querier defaults to the plain reader pool for the common
	// no-cursor case (first page: nothing to guard, so no need to pay
	// for a transaction). When a cursor is present it is switched to a
	// single read-only transaction below, so the truncation guard and
	// the paged SELECT observe one consistent snapshot.
	var querier sqlQuerier = s.db.reader

	if p.Cursor != "" {
		afterSeq, derr := audit.DecodeSeqCursor(p.Cursor)
		if derr != nil {
			// derr already wraps audit.ErrInvalidCursor; propagate it
			// unwrapped so the caller's errors.Is check (see
			// internal/adapters/http's listAuditEvents) can tell a bad
			// client-supplied cursor apart from a genuine query failure.
			return audit.Page{}, fmt.Errorf("sqlite: list audit events: %w", derr)
		}

		// Retention truncation (ADR-017) may have removed the range this
		// cursor points into. If the cursor's continuation point precedes
		// the oldest surviving row, resuming here would silently skip the
		// removed events; refuse with ErrCursorTruncated instead (mapped
		// to 410 Gone by the HTTP layer). afterSeq+1 == minSeq (cursor
		// exactly at the anchor) resumes cleanly and is not an error.
		// With retention disabled, minSeq is 1 and this never fires.
		//
		// The guard's minAuditSeq read and the paged SELECT below MUST
		// run against the same WAL snapshot: s.db.reader is a
		// multi-connection pool (readers don't block the writer, ADR-011),
		// so two independent QueryContext calls can land on different
		// connections and straddle a truncation the sweeper commits
		// between them — the guard would see the pre-truncation minSeq
		// (pass), then the SELECT would see the post-truncation table and
		// silently skip the just-removed range: exactly the silent-gap
		// failure ErrCursorTruncated exists to prevent (security review,
		// ATR-308 B2). A single read-only transaction fixes the snapshot
		// at its first statement (SQLite WAL semantics), so both reads
		// below are guaranteed consistent with each other regardless of
		// what commits afterward.
		tx, err := s.db.reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return audit.Page{}, fmt.Errorf("sqlite: list audit events: begin read tx: %w", err)
		}
		// Read-only: there is nothing to Commit. Rollback is the correct
		// terminal call on every path (success or error) and is always
		// safe to call after the rows below have been read, mirroring
		// every other tx.Rollback() deferred in this package.
		defer tx.Rollback() //nolint:errcheck // read-only tx, no commit needed.

		minSeq, ok, merr := minAuditSeqTx(ctx, tx)
		if merr != nil {
			return audit.Page{}, fmt.Errorf("sqlite: list audit events: %w", merr)
		}
		if ok && afterSeq+1 < minSeq {
			return audit.Page{}, fmt.Errorf("sqlite: list audit events: %w", audit.ErrCursorTruncated)
		}
		query += " AND seq > ?"
		args = append(args, afterSeq)
		querier = tx
	}
	query += " ORDER BY seq ASC LIMIT ?"
	args = append(args, limit+1)

	rows, err := querier.QueryContext(ctx, query, args...)
	if err != nil {
		return audit.Page{}, fmt.Errorf("sqlite: list audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []audit.Recorded
	for rows.Next() {
		rec, serr := scanAuditRecord(rows)
		if serr != nil {
			return audit.Page{}, fmt.Errorf("sqlite: list audit events: scan: %w", serr)
		}
		events = append(events, rec)
	}
	if err := rows.Err(); err != nil {
		return audit.Page{}, fmt.Errorf("sqlite: list audit events: %w", err)
	}

	page := audit.Page{Events: events}
	if len(events) > limit {
		// The extra (limit+1'th) row proves there is another page; drop
		// it from the returned data and encode a cursor past the last
		// row we actually return.
		page.Events = events[:limit]
		page.NextCursor = audit.EncodeSeqCursor(page.Events[limit-1].Seq)
	}
	return page, nil
}

// TruncateAudit implements audit.Truncator (ATR-308, ADR-017): it
// removes the contiguous seq-prefix of audit_events whose every row is
// older than req.Cutoff — clamped down to spare any event tied to a
// message under legal hold — and appends a TypeRetentionCheckpoint
// anchoring the survivors, all in one writer transaction.
//
// The whole operation runs against s.db.writer, capped to a single
// connection by ADR-011: the boundary computation, the hold clamp, the
// checkpoint insert and the delete therefore see one consistent snapshot
// and cannot interleave with any other write (in particular, a
// concurrent SetHold either lands entirely before this transaction — and
// is seen by the clamp — or entirely after it).
//
// It writes no checkpoint and removes nothing when nothing is eligible
// (an empty/young log, or one fully pinned by legal hold), so an idle log
// never accretes empty checkpoints.
func (s *Store) TruncateAudit(ctx context.Context, req audit.TruncateRequest) (audit.TruncateResult, error) {
	cutoff := req.Cutoff.UTC().Format(timeLayout)

	tx, err := s.db.writer.BeginTx(ctx, nil)
	if err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // best-effort; Commit below is the success path.

	// Boundary: the largest N such that every row with seq <= N is
	// strictly older than the cutoff. Defined via the first row that is
	// NOT older (so it is correct even if seq order and created_at order
	// diverge, which only deterministic tests can arrange). If no row is
	// recent, every row is old and N is the max seq.
	boundary, ok, err := auditTruncationBoundary(ctx, tx, cutoff)
	if err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: compute boundary: %w", err)
	}
	if !ok {
		return audit.TruncateResult{}, tx.Commit()
	}

	// Legal-hold clamp: never truncate an event tied to a message that
	// currently has a link under hold (ATR-257/258). Lower the boundary
	// to just before the oldest such event rather than skip it mid-prefix
	// (which would fragment the chain and void the single anchor).
	res := audit.TruncateResult{}
	oldestHeld, held, err := oldestHeldAuditSeq(ctx, tx, boundary)
	if err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: hold clamp: %w", err)
	}
	if held {
		res.HeldClamped = true
		boundary = oldestHeld - 1
	}

	// After the clamp, is there still a present row at the boundary to
	// anchor on? If boundary fell below the oldest surviving seq (a prior
	// pass already truncated this far, or a hold pinned everything), there
	// is nothing to do.
	anchorHash, anchorFound, err := auditRowHash(ctx, tx, boundary)
	if err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: read anchor: %w", err)
	}
	if boundary <= 0 || !anchorFound {
		return res, tx.Commit()
	}

	var truncCount int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE seq <= ?`, boundary,
	).Scan(&truncCount); err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: count: %w", err)
	}
	if truncCount == 0 {
		return res, tx.Commit()
	}

	// Append the checkpoint at the current tail before deleting, so it
	// lands at seq = maxSeq+1 (> boundary) and the delete cannot touch it.
	prevSeq, prevHash, err := lastAuditRecord(ctx, tx)
	if err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: read tail: %w", err)
	}
	checkpointSeq := prevSeq + 1
	ts := time.Now().UTC()

	details := map[string]any{
		audit.DetailAnchorSeq:      boundary,
		audit.DetailAnchorHash:     anchorHash,
		audit.DetailTruncatedCount: truncCount,
		audit.DetailCutoff:         req.Cutoff.UTC().Format(time.RFC3339Nano),
		audit.DetailHeldClamped:    res.HeldClamped,
	}
	detailsJSON, err := marshalDetails(details)
	if err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: marshal checkpoint details: %w", err)
	}

	id, err := newAuditID()
	if err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_events (id, seq, prev_hash, type, actor, message_id, recipient, details, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, checkpointSeq, prevHash, string(audit.TypeRetentionCheckpoint), req.Actor, "", "", detailsJSON, ts.Format(timeLayout),
	); err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: insert checkpoint: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE seq <= ?`, boundary); err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: delete: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return audit.TruncateResult{}, fmt.Errorf("sqlite: truncate audit: commit: %w", err)
	}

	res.Truncated = true
	res.AnchorSeq = boundary
	res.AnchorHash = anchorHash
	res.TruncatedCount = truncCount
	res.Checkpoint = audit.Recorded{
		Event: audit.Event{
			Timestamp: ts,
			Type:      audit.TypeRetentionCheckpoint,
			Actor:     req.Actor,
			Details:   details,
		},
		ID:       id,
		Seq:      checkpointSeq,
		PrevHash: prevHash,
	}
	return res, nil
}

// auditTruncationBoundary returns the largest seq N such that every row
// with seq <= N has created_at strictly before cutoff, and ok=true when
// such an N (>= the oldest surviving seq) exists. It is defined as
// (min seq with created_at >= cutoff) - 1, falling back to the max seq
// when no row is that recent, so it never selects a row newer than the
// cutoff regardless of any seq/created_at ordering skew.
func auditTruncationBoundary(ctx context.Context, tx *sql.Tx, cutoff string) (int64, bool, error) {
	var firstRecent sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT MIN(seq) FROM audit_events WHERE created_at >= ?`, cutoff,
	).Scan(&firstRecent); err != nil {
		return 0, false, err
	}
	if firstRecent.Valid {
		return firstRecent.Int64 - 1, firstRecent.Int64-1 >= 1, nil
	}

	// No recent row: every row is older than the cutoff, so the boundary
	// is the whole table up to its max seq.
	var maxSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT MAX(seq) FROM audit_events`,
	).Scan(&maxSeq); err != nil {
		return 0, false, err
	}
	if !maxSeq.Valid {
		return 0, false, nil // empty table.
	}
	return maxSeq.Int64, true, nil
}

// oldestHeldAuditSeq returns the smallest seq (<= upTo) of an audit row
// tied to a message that currently has at least one link under legal
// hold, and held=true when such a row exists. Non-message events
// (message_id == ”) are never held.
func oldestHeldAuditSeq(ctx context.Context, tx *sql.Tx, upTo int64) (int64, bool, error) {
	var oldest sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT MIN(seq) FROM audit_events
		  WHERE seq <= ?
		    AND message_id != ''
		    AND message_id IN (SELECT message_id FROM links WHERE hold = 1)`,
		upTo,
	).Scan(&oldest); err != nil {
		return 0, false, err
	}
	if !oldest.Valid {
		return 0, false, nil
	}
	return oldest.Int64, true, nil
}

// auditRowHash recomputes the chain hash of the audit row at the given
// seq, returning found=false if no such row exists. This is the anchor
// hash a truncation records so the surviving chain can be resumed from
// it (ADR-017). It computes the hash via audit.HashRecord — the single
// canonical hash shared with the verifier (ATR-240) — so a truncation's
// anchor_hash is, by construction, exactly what `audit verify` will
// recompute for the boundary row.
func auditRowHash(ctx context.Context, tx *sql.Tx, seq int64) (string, bool, error) {
	row := tx.QueryRowContext(ctx,
		`SELECT id, seq, prev_hash, type, actor, message_id, recipient, details, created_at
		   FROM audit_events WHERE seq = ?`, seq)

	rec, err := scanAuditRecord(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}

	hash, err := audit.HashRecord(rec)
	if err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// sqlQuerier is satisfied by both *sql.DB and *sql.Tx, letting
// ListEvents run its paged SELECT against either the plain reader pool
// (no cursor: nothing to guard) or a single read-only transaction
// (cursor present: the guard and the SELECT must share one snapshot,
// see ListEvents' doc comment on the cursor-truncation guard).
type sqlQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// minAuditSeqTx returns the smallest seq currently in audit_events, with
// ok=false for an empty table. Used by ListEvents to detect a cursor
// that points into a range retention has since truncated (ADR-017). It
// takes an explicit *sql.Tx (never the bare reader pool) so its caller
// controls exactly which connection/snapshot it reads against — see
// ListEvents' doc comment for why this must not be a second,
// independent connection from the one the subsequent paged SELECT uses.
func minAuditSeqTx(ctx context.Context, tx *sql.Tx) (int64, bool, error) {
	var minSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT MIN(seq) FROM audit_events`,
	).Scan(&minSeq); err != nil {
		return 0, false, err
	}
	return minSeq.Int64, minSeq.Valid, nil
}

// lastAuditRecord returns the seq and computed hash of the
// highest-seq row currently in audit_events, or (0, "", nil) if the
// table is empty (the first record ever written has no predecessor).
// The hash is computed via audit.HashRecord — the single canonical hash
// shared with the verifier (ATR-240) — so the prev_hash a new row is
// written with is exactly what `audit verify` will recompute for its
// predecessor.
func lastAuditRecord(ctx context.Context, tx *sql.Tx) (seq int64, hash string, err error) {
	row := tx.QueryRowContext(ctx,
		`SELECT id, seq, prev_hash, type, actor, message_id, recipient, details, created_at
		   FROM audit_events ORDER BY seq DESC LIMIT 1`)

	rec, scanErr := scanAuditRecord(row)
	if scanErr != nil {
		if scanErr == sql.ErrNoRows {
			return 0, "", nil
		}
		return 0, "", scanErr
	}

	hash, err = audit.HashRecord(rec)
	if err != nil {
		return 0, "", err
	}
	return rec.Seq, hash, nil
}

// scanAuditRecord scans one audit_events row into an audit.Recorded,
// unmarshaling its JSON details blob back into a map.
func scanAuditRecord(row rowScanner) (audit.Recorded, error) {
	var (
		id, prevHash, typ, actor, messageID, recipient, details, createdAt string
		seq                                                                int64
	)
	if err := row.Scan(&id, &seq, &prevHash, &typ, &actor, &messageID, &recipient, &details, &createdAt); err != nil {
		return audit.Recorded{}, err
	}

	ts, err := parseTime(createdAt)
	if err != nil {
		return audit.Recorded{}, fmt.Errorf("parse created_at: %w", err)
	}

	var detailsMap map[string]any
	if err := json.Unmarshal([]byte(details), &detailsMap); err != nil {
		return audit.Recorded{}, fmt.Errorf("unmarshal details: %w", err)
	}

	return audit.Recorded{
		Event: audit.Event{
			Timestamp: ts,
			Type:      audit.Type(typ),
			Actor:     actor,
			MessageID: messageID,
			Recipient: recipient,
			Details:   detailsMap,
		},
		ID:       id,
		Seq:      seq,
		PrevHash: prevHash,
	}, nil
}

// marshalDetails encodes details as a JSON object, defaulting to "{}"
// for a nil/empty map so the stored column is always valid,
// unconditionally-unmarshalable JSON.
func marshalDetails(details map[string]any) (string, error) {
	if len(details) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(details)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// The per-row tamper-evidence hash (SR-128-1) is computed by
// audit.HashRecord in internal/core/audit — the single canonical hash
// used both here (at write time, via lastAuditRecord/auditRowHash) and by
// the `audit verify` chain walker (ATR-240). It was lifted out of this
// package so a verifier outside internal/core/store/sqlite can recompute
// it without importing store internals (ADR-002, ADR-017 note).

// auditIDRandomBytes mirrors internal/core/link's idRandomBytes scheme
// (128 bits of crypto/rand entropy for a store-internal row
// identifier, never exposed to recipients as a bearer token).
const auditIDRandomBytes = 16

// newAuditID generates a new opaque, hex-encoded audit_events.id.
func newAuditID() (string, error) {
	buf := make([]byte, auditIDRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate audit event id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
