package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
// (CLAUDE.md invariant #4), so ExportJSONL (internal/core/audit) can
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
	if p.Cursor != "" {
		afterSeq, derr := audit.DecodeSeqCursor(p.Cursor)
		if derr != nil {
			// derr already wraps audit.ErrInvalidCursor; propagate it
			// unwrapped so the caller's errors.Is check (see
			// internal/adapters/http's listAuditEvents) can tell a bad
			// client-supplied cursor apart from a genuine query failure.
			return audit.Page{}, fmt.Errorf("sqlite: list audit events: %w", derr)
		}
		query += " AND seq > ?"
		args = append(args, afterSeq)
	}
	query += " ORDER BY seq ASC LIMIT ?"
	args = append(args, limit+1)

	rows, err := s.db.reader.QueryContext(ctx, query, args...)
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

// lastAuditRecord returns the seq and computed hash of the
// highest-seq row currently in audit_events, or (0, "", nil) if the
// table is empty (the first record ever written has no predecessor).
func lastAuditRecord(ctx context.Context, tx *sql.Tx) (seq int64, hash string, err error) {
	row := tx.QueryRowContext(ctx,
		`SELECT id, seq, prev_hash, type, actor, message_id, recipient, details, created_at
		   FROM audit_events ORDER BY seq DESC LIMIT 1`)

	var (
		id, prevHash, typ, actor, messageID, recipient, details, createdAt string
	)
	scanErr := row.Scan(&id, &seq, &prevHash, &typ, &actor, &messageID, &recipient, &details, &createdAt)
	if scanErr != nil {
		if scanErr == sql.ErrNoRows {
			return 0, "", nil
		}
		return 0, "", scanErr
	}

	ts, err := parseTime(createdAt)
	if err != nil {
		return 0, "", err
	}

	hash = chainHash(prevHash, id, seq, ts, audit.Type(typ), actor, messageID, recipient, details)
	return seq, hash, nil
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

// chainHash computes the tamper-evidence hash for one audit_events row
// (SR-128-1): SHA-256 over the previous row's hash concatenated with
// every field of this row, so that changing or removing any previously
// written row (including the very first one, via prevHash) changes
// every subsequent row's hash. This is the structural hook only; a
// verifier that walks the table in seq order recomputing this same
// function is deliberately not implemented as part of this task (see
// internal/core/audit's package doc comment).
func chainHash(prevHash, id string, seq int64, ts time.Time, typ audit.Type, actor, messageID, recipient, detailsJSON string) string {
	h := sha256.New()
	msg := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s",
		prevHash, id, seq, ts.UTC().Format(timeLayout), typ, actor, messageID, recipient, detailsJSON)
	// hash.Hash.Write never returns an error (its doc comment
	// guarantees this); the error is still checked to satisfy errcheck
	// and to fail loudly rather than silently if that contract is ever
	// violated by a future Go version or a differently-typed h.
	if _, err := h.Write([]byte(msg)); err != nil {
		panic(fmt.Sprintf("sqlite: chainHash: hash.Hash.Write returned an error, violating its documented contract: %v", err))
	}
	return hex.EncodeToString(h.Sum(nil))
}

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
