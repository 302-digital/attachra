package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
)

// timeLayout is the exact text form every timestamp column is stored
// and compared in: strict UTC RFC3339 with nanosecond precision. Using
// a single fixed layout (rather than SQLite's own datetime() helpers)
// keeps the schema dialect-neutral (ADR-011): the same TEXT column and
// comparison-by-string-order semantics are valid on Postgres too,
// since RFC3339 timestamps sort lexicographically in time order.
const timeLayout = time.RFC3339Nano

// Store implements store.MetadataStore on top of a SQLite database
// opened per docs/architecture/adr-011-metadata-db.md (WAL,
// single-writer pool, separate read pool, foreign keys on).
type Store struct {
	db *sqlDB
}

// Open opens (creating if necessary) the SQLite database at path and
// runs every pending migration. The returned Store must be closed with
// Close when no longer needed.
func Open(path string) (*Store, error) {
	db, err := openSQLDB(path)
	if err != nil {
		return nil, err
	}

	if err := runMigrations(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// Close closes the underlying connection pools.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ping is a lightweight readiness probe (US-7.2/T-7.2.3, ATR-194): a
// successful PingContext against the read connection pool confirms the
// SQLite database file is reachable and the driver can execute a
// query, without touching application data or taking a write lock. It
// is not part of store.MetadataStore (that interface has no readiness
// concept); internal/adapters/http's readiness handler type-asserts
// for this method opportunistically (see its dbPinger interface).
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.reader.PingContext(ctx); err != nil {
		return fmt.Errorf("sqlite: ping: %w", err)
	}
	return nil
}

var _ store.MetadataStore = (*Store)(nil)

// CreateMessage implements store.MetadataStore.
func (s *Store) CreateMessage(ctx context.Context, p store.NewMessageParams) error {
	_, err := s.db.writer.ExecContext(ctx,
		`INSERT INTO messages (id, queue_id, sender, status, created_at) VALUES (?, ?, ?, ?, ?)`,
		p.ID, p.QueueID, p.Sender, string(p.Status), nowText(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: create message %q: %w", p.ID, err)
	}
	return nil
}

// CreateAttachment implements store.MetadataStore.
func (s *Store) CreateAttachment(ctx context.Context, p store.NewAttachmentParams) error {
	_, err := s.db.writer.ExecContext(ctx,
		`INSERT INTO attachments (id, message_id, part_ref, filename, declared_type, detected_type, size, storage_key, retain_until, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.MessageID, p.PartRef, p.Filename, p.DeclaredType, p.DetectedType, p.Size, p.StorageKey, p.RetainUntil, nowText(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: create attachment %q: %w", p.ID, err)
	}
	return nil
}

// CreateLink implements store.MetadataStore.
func (s *Store) CreateLink(ctx context.Context, p store.NewLinkParams) error {
	_, err := s.db.writer.ExecContext(ctx,
		`INSERT INTO links (id, message_id, attachment_id, recipient, token_hash, expires_at, max_downloads, downloads, status, hold, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 0, ?)`,
		p.ID, p.MessageID, p.AttachmentID, p.Recipient, p.TokenHash, p.ExpiresAt, p.MaxDownloads, string(store.LinkStatusActive), nowText(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: create link %q: %w", p.ID, err)
	}
	return nil
}

// CreateMessageLink implements store.MetadataStore.
func (s *Store) CreateMessageLink(ctx context.Context, p store.NewMessageLinkParams) error {
	_, err := s.db.writer.ExecContext(ctx,
		`INSERT INTO message_links (token_hash, message_id, recipient, expires_at, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		p.TokenHash, p.MessageID, p.Recipient, p.ExpiresAt, string(store.LinkStatusActive), nowText(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: create message_link: %w", err)
	}
	return nil
}

// messageColumns is the fixed column order used by every SELECT ...
// FROM messages query in this file, matching scanMessage.
const messageColumns = `id, queue_id, sender, status, created_at`

// scanMessage scans a full messages-table row (messageColumns' order)
// into a store.Message, returning its created_at text separately for
// the caller to parse (matching this file's other scan* helpers).
func scanMessage(row rowScanner) (store.Message, string, error) {
	var m store.Message
	var status, createdAt string
	if err := row.Scan(&m.ID, &m.QueueID, &m.Sender, &status, &createdAt); err != nil {
		return store.Message{}, "", err
	}
	m.Status = store.MessageStatus(status)
	return m, createdAt, nil
}

// GetMessage implements store.MetadataStore.
func (s *Store) GetMessage(ctx context.Context, id string) (store.Message, error) {
	row := s.db.reader.QueryRowContext(ctx,
		`SELECT `+messageColumns+` FROM messages WHERE id = ?`, id)

	m, createdAt, err := scanMessage(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.Message{}, fmt.Errorf("sqlite: get message %q: %w", id, store.ErrNotFound)
		}
		return store.Message{}, fmt.Errorf("sqlite: get message %q: %w", id, err)
	}

	t, err := parseTime(createdAt)
	if err != nil {
		return store.Message{}, fmt.Errorf("sqlite: get message %q: %w", id, err)
	}
	m.CreatedAt = t

	return m, nil
}

// attachmentColumns is the fixed column order used by every SELECT ...
// FROM attachments query in this file, matching scanAttachment.
const attachmentColumns = `id, message_id, part_ref, filename, declared_type, detected_type, size, storage_key, retain_until, created_at`

// GetAttachment implements store.MetadataStore.
func (s *Store) GetAttachment(ctx context.Context, id string) (store.Attachment, error) {
	row := s.db.reader.QueryRowContext(ctx,
		`SELECT `+attachmentColumns+` FROM attachments WHERE id = ?`, id)

	a, createdAt, err := scanAttachment(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.Attachment{}, fmt.Errorf("sqlite: get attachment %q: %w", id, store.ErrNotFound)
		}
		return store.Attachment{}, fmt.Errorf("sqlite: get attachment %q: %w", id, err)
	}

	t, err := parseTime(createdAt)
	if err != nil {
		return store.Attachment{}, fmt.Errorf("sqlite: get attachment %q: %w", id, err)
	}
	a.CreatedAt = t

	return a, nil
}

// ListMessagesBySender implements store.MetadataStore.
func (s *Store) ListMessagesBySender(ctx context.Context, sender string) ([]store.Message, error) {
	rows, err := s.db.reader.QueryContext(ctx,
		`SELECT `+messageColumns+` FROM messages WHERE sender = ? ORDER BY created_at ASC`, sender)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list messages by sender %q: %w", sender, err)
	}
	defer func() { _ = rows.Close() }()

	var messages []store.Message
	for rows.Next() {
		m, createdAt, serr := scanMessage(rows)
		if serr != nil {
			return nil, fmt.Errorf("sqlite: list messages by sender %q: %w", sender, serr)
		}
		t, err := parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("sqlite: list messages by sender %q: %w", sender, err)
		}
		m.CreatedAt = t
		messages = append(messages, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: list messages by sender %q: %w", sender, err)
	}

	return messages, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows, letting
// scanAttachment/scanLink be shared between single-row Get and
// multi-row List methods.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanAttachment scans a full attachments-table row (attachmentColumns'
// order) into a store.Attachment, returning its created_at text
// separately for the caller to parse (matching this file's other
// scan* helpers) and populating RetainUntil directly here since it is
// not otherwise post-processed by any caller: an empty retain_until
// (the legacy pre-ATR-178 sentinel, see store.Attachment.RetainUntil's
// doc comment) is left as the zero time.Time rather than parsed.
func scanAttachment(row rowScanner) (store.Attachment, string, error) {
	var a store.Attachment
	var createdAt, retainUntil string
	err := row.Scan(&a.ID, &a.MessageID, &a.PartRef, &a.Filename, &a.DeclaredType, &a.DetectedType, &a.Size, &a.StorageKey, &retainUntil, &createdAt)
	if err != nil {
		return store.Attachment{}, "", err
	}
	if retainUntil != "" {
		t, perr := parseTime(retainUntil)
		if perr != nil {
			return store.Attachment{}, "", fmt.Errorf("parse retain_until: %w", perr)
		}
		a.RetainUntil = t
	}
	return a, createdAt, nil
}

// scanLink scans a full links-table row (all columns, in the fixed
// order used by every SELECT ... FROM links query in this file) into
// a store.Link, parsing its two persisted timestamps and reconstructing
// the nullable hold_set_by/hold_set_at pair (hold_set_at only when
// non-NULL: an unheld link never had a hold set).
func scanLink(row rowScanner) (store.Link, error) {
	var l store.Link
	var expiresAt, createdAt string
	var hold int
	var holdSetBy sql.NullString
	var holdSetAt sql.NullString
	var status string

	err := row.Scan(
		&l.ID, &l.MessageID, &l.AttachmentID, &l.Recipient, &l.TokenHash,
		&expiresAt, &l.MaxDownloads, &l.Downloads, &status,
		&hold, &holdSetBy, &holdSetAt, &createdAt,
	)
	if err != nil {
		return store.Link{}, err
	}

	l.Status = store.LinkStatus(status)
	l.Hold = hold != 0
	if holdSetBy.Valid {
		l.HoldSetBy = holdSetBy.String
	}

	t, err := parseTime(expiresAt)
	if err != nil {
		return store.Link{}, fmt.Errorf("parse expires_at: %w", err)
	}
	l.ExpiresAt = t

	t, err = parseTime(createdAt)
	if err != nil {
		return store.Link{}, fmt.Errorf("parse created_at: %w", err)
	}
	l.CreatedAt = t

	if holdSetAt.Valid && holdSetAt.String != "" {
		t, err = parseTime(holdSetAt.String)
		if err != nil {
			return store.Link{}, fmt.Errorf("parse hold_set_at: %w", err)
		}
		l.HoldSetAt = t
	}

	return l, nil
}

const linkColumns = `id, message_id, attachment_id, recipient, token_hash, expires_at, max_downloads, downloads, status, hold, hold_set_by, hold_set_at, created_at`

// GetLinkByTokenHash implements store.MetadataStore.
func (s *Store) GetLinkByTokenHash(ctx context.Context, hash string) (store.Link, error) {
	row := s.db.reader.QueryRowContext(ctx,
		`SELECT `+linkColumns+` FROM links WHERE token_hash = ?`, hash)

	l, err := scanLink(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.Link{}, fmt.Errorf("sqlite: get link by token hash: %w", store.ErrNotFound)
		}
		return store.Link{}, fmt.Errorf("sqlite: get link by token hash: %w", err)
	}
	return l, nil
}

// GetLinkByID implements store.MetadataStore.
func (s *Store) GetLinkByID(ctx context.Context, id string) (store.Link, error) {
	row := s.db.reader.QueryRowContext(ctx,
		`SELECT `+linkColumns+` FROM links WHERE id = ?`, id)

	l, err := scanLink(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.Link{}, fmt.Errorf("sqlite: get link by id %q: %w", id, store.ErrNotFound)
		}
		return store.Link{}, fmt.Errorf("sqlite: get link by id %q: %w", id, err)
	}
	return l, nil
}

// ListLinksByMessage implements store.MetadataStore.
func (s *Store) ListLinksByMessage(ctx context.Context, messageID string) ([]store.Link, error) {
	rows, err := s.db.reader.QueryContext(ctx,
		`SELECT `+linkColumns+` FROM links WHERE message_id = ? ORDER BY created_at ASC`, messageID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list links by message %q: %w", messageID, err)
	}
	defer func() { _ = rows.Close() }()

	var links []store.Link
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: list links by message %q: %w", messageID, err)
		}
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: list links by message %q: %w", messageID, err)
	}

	return links, nil
}

// GetMessageLinkByTokenHash implements store.MetadataStore.
func (s *Store) GetMessageLinkByTokenHash(ctx context.Context, hash string) (store.MessageLink, error) {
	row := s.db.reader.QueryRowContext(ctx,
		`SELECT token_hash, message_id, recipient, expires_at, status, created_at
		 FROM message_links WHERE token_hash = ?`, hash)

	var ml store.MessageLink
	var expiresAt, createdAt, status string
	err := row.Scan(&ml.TokenHash, &ml.MessageID, &ml.Recipient, &expiresAt, &status, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.MessageLink{}, fmt.Errorf("sqlite: get message_link by token hash: %w", store.ErrNotFound)
		}
		return store.MessageLink{}, fmt.Errorf("sqlite: get message_link by token hash: %w", err)
	}
	ml.Status = store.LinkStatus(status)

	t, err := parseTime(expiresAt)
	if err != nil {
		return store.MessageLink{}, fmt.Errorf("sqlite: get message_link by token hash: %w", err)
	}
	ml.ExpiresAt = t

	t, err = parseTime(createdAt)
	if err != nil {
		return store.MessageLink{}, fmt.Errorf("sqlite: get message_link by token hash: %w", err)
	}
	ml.CreatedAt = t

	return ml, nil
}

// RegisterDownload implements store.MetadataStore using the single
// guarded atomic UPDATE mandated by ADR-011: the decision to grant a
// download is driven entirely by rows-affected, never by a preceding
// read. now is the caller-supplied current time (RFC3339Nano UTC),
// injected rather than read from time.Now() here so tests can exercise
// expiry deterministically.
func (s *Store) RegisterDownload(ctx context.Context, hash string, now string) (store.Link, error) {
	res, err := s.db.writer.ExecContext(ctx,
		`UPDATE links
		    SET downloads = downloads + 1
		  WHERE token_hash = ?
		    AND status = ?
		    AND expires_at > ?
		    AND (max_downloads = 0 OR downloads < max_downloads)`,
		hash, string(store.LinkStatusActive), now,
	)
	if err != nil {
		return store.Link{}, fmt.Errorf("sqlite: register download: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return store.Link{}, fmt.Errorf("sqlite: register download: read rows affected: %w", err)
	}
	if affected == 0 {
		return store.Link{}, fmt.Errorf("sqlite: register download: %w", store.ErrDownloadLimitReached)
	}

	// Read back the link as it exists after the increment (the
	// pre-increment Downloads value the interface doc promises is
	// reconstructed by the caller via Downloads-1 if ever needed; we
	// return the current row, which already reflects the granted
	// download, since callers need AttachmentID/MessageID, not the
	// exact pre-increment counter).
	link, err := s.GetLinkByTokenHash(ctx, hash)
	if err != nil {
		return store.Link{}, fmt.Errorf("sqlite: register download: reload link: %w", err)
	}
	return link, nil
}

// RegisterDownloadByID implements store.MetadataStore. It is
// RegisterDownload's identical guarded atomic UPDATE, keyed by the
// link's own row ID instead of its token hash (see the interface
// doc's package-page rationale).
func (s *Store) RegisterDownloadByID(ctx context.Context, id string, now string) (store.Link, error) {
	res, err := s.db.writer.ExecContext(ctx,
		`UPDATE links
		    SET downloads = downloads + 1
		  WHERE id = ?
		    AND status = ?
		    AND expires_at > ?
		    AND (max_downloads = 0 OR downloads < max_downloads)`,
		id, string(store.LinkStatusActive), now,
	)
	if err != nil {
		return store.Link{}, fmt.Errorf("sqlite: register download by id: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return store.Link{}, fmt.Errorf("sqlite: register download by id: read rows affected: %w", err)
	}
	if affected == 0 {
		return store.Link{}, fmt.Errorf("sqlite: register download by id: %w", store.ErrDownloadLimitReached)
	}

	link, err := s.GetLinkByID(ctx, id)
	if err != nil {
		return store.Link{}, fmt.Errorf("sqlite: register download by id: reload link: %w", err)
	}
	return link, nil
}

// RevokeLink implements store.MetadataStore.
func (s *Store) RevokeLink(ctx context.Context, id string) error {
	res, err := s.db.writer.ExecContext(ctx,
		`UPDATE links SET status = ? WHERE id = ?`, string(store.LinkStatusRevoked), id)
	if err != nil {
		return fmt.Errorf("sqlite: revoke link %q: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: revoke link %q: read rows affected: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("sqlite: revoke link %q: %w", id, store.ErrNotFound)
	}
	return nil
}

// RevokeLinksByMessage implements store.MetadataStore. It revokes
// every non-held Link and the MessageLink for messageID inside one
// transaction (docs/architecture/package-page-decision.md §4.1 item 4:
// "cascade over message_id"). Held links are left untouched: the
// caller (internal/core/link.Engine) decides whether a partial revoke
// due to hold is itself an error.
func (s *Store) RevokeLinksByMessage(ctx context.Context, messageID string) (int, error) {
	tx, err := s.db.writer.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("sqlite: revoke links by message %q: begin tx: %w", messageID, err)
	}
	defer tx.Rollback() //nolint:errcheck // best-effort; Commit below is the success path.

	res, err := tx.ExecContext(ctx,
		`UPDATE links SET status = ? WHERE message_id = ? AND hold = 0`,
		string(store.LinkStatusRevoked), messageID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: revoke links by message %q: %w", messageID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: revoke links by message %q: read rows affected: %w", messageID, err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE message_links SET status = ? WHERE message_id = ?`,
		string(store.LinkStatusRevoked), messageID); err != nil {
		return 0, fmt.Errorf("sqlite: revoke links by message %q: revoke message_link: %w", messageID, err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("sqlite: revoke links by message %q: commit: %w", messageID, err)
	}

	return int(affected), nil
}

// SetHold implements store.MetadataStore.
func (s *Store) SetHold(ctx context.Context, id string, hold bool, setBy string, setAt string) error {
	holdInt := 0
	if hold {
		holdInt = 1
	}
	res, err := s.db.writer.ExecContext(ctx,
		`UPDATE links SET hold = ?, hold_set_by = ?, hold_set_at = ? WHERE id = ?`,
		holdInt, setBy, setAt, id)
	if err != nil {
		return fmt.Errorf("sqlite: set hold on link %q: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: set hold on link %q: read rows affected: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("sqlite: set hold on link %q: %w", id, store.ErrNotFound)
	}
	return nil
}

// defaultExpiredAttachmentsLimit bounds ListExpiredAttachments when the
// caller passes a non-positive limit, so a programming mistake in a
// future caller cannot accidentally turn into an unbounded query
// (CLAUDE.md invariant #4).
const defaultExpiredAttachmentsLimit = 100

// ListExpiredAttachments implements store.MetadataStore. The NOT EXISTS
// anti-join against links is the SQL-level hold exclusion ATR-259
// requires: an attachment with at least one held link is never a
// candidate row in the first place, regardless of what the caller does
// with the result.
func (s *Store) ListExpiredAttachments(ctx context.Context, now string, limit int) ([]store.Attachment, error) {
	if limit <= 0 {
		limit = defaultExpiredAttachmentsLimit
	}

	rows, err := s.db.reader.QueryContext(ctx,
		`SELECT `+attachmentColumns+`
		   FROM attachments a
		  WHERE a.retain_until != ''
		    AND a.retain_until < ?
		    AND NOT EXISTS (SELECT 1 FROM links l WHERE l.attachment_id = a.id AND l.hold = 1)
		  ORDER BY a.retain_until ASC
		  LIMIT ?`,
		now, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list expired attachments: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []store.Attachment
	for rows.Next() {
		a, createdAt, err := scanAttachment(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: list expired attachments: %w", err)
		}
		t, err := parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("sqlite: list expired attachments: %w", err)
		}
		a.CreatedAt = t
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: list expired attachments: %w", err)
	}

	return out, nil
}

// CountHeldExpiredAttachments implements store.MetadataStore. Its WHERE
// clause is the exact complement of ListExpiredAttachments' anti-join
// (EXISTS instead of NOT EXISTS), so the two methods together account
// for every expired attachment: either returned for deletion, or
// counted here as skipped for hold.
func (s *Store) CountHeldExpiredAttachments(ctx context.Context, now string) (int, error) {
	var count int
	err := s.db.reader.QueryRowContext(ctx,
		`SELECT COUNT(*)
		   FROM attachments a
		  WHERE a.retain_until != ''
		    AND a.retain_until < ?
		    AND EXISTS (SELECT 1 FROM links l WHERE l.attachment_id = a.id AND l.hold = 1)`,
		now,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("sqlite: count held expired attachments: %w", err)
	}
	return count, nil
}

// DeleteAttachment implements store.MetadataStore.
//
// The links.attachment_id foreign key (no ON DELETE behavior) forces
// child rows to be removed before the parent attachments row, so the
// guard cannot be expressed as a single "DELETE FROM attachments ...
// AND NOT EXISTS (held link)" statement the way RegisterDownload's
// atomic counter UPDATE is a single statement — deleting the parent
// first would violate the foreign key while a held link still
// references it, and deleting all links first (including held ones)
// would destroy the very evidence Hold exists to protect before the
// guard even runs. Instead: only non-held links are deleted first
// (`hold = 0`); a followup existence check for any link still
// referencing this attachment_id (i.e. a held one) decides whether the
// attachment row is safe to remove. Both statements run inside one
// transaction — and therefore against one consistent view, since this
// Store's writer pool is a single serialized connection (ADR-011): no
// other write (in particular, no concurrent SetHold) can land between
// the two statements below. If a held link is found, DeleteAttachment
// returns immediately without committing, so the deferred Rollback
// restores the non-held links this call itself just deleted — the
// net, externally-observable effect of a refused call is therefore
// exactly "nothing changed", never "some links pruned, held ones and
// the attachment left behind" (ATR-259 fix, added after security
// review flagged the original, unconditional version as a TOCTOU race:
// see store.MetadataStore.DeleteAttachment's doc comment for the exact
// window this closes and the residual one it cannot).
func (s *Store) DeleteAttachment(ctx context.Context, id string) error {
	tx, err := s.db.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: delete attachment %q: begin tx: %w", id, err)
	}
	defer tx.Rollback() //nolint:errcheck // best-effort; Commit below is the success path.

	if _, err := tx.ExecContext(ctx, `DELETE FROM links WHERE attachment_id = ? AND hold = 0`, id); err != nil {
		return fmt.Errorf("sqlite: delete attachment %q: delete non-held links: %w", id, err)
	}

	var heldLinkRemains bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM links WHERE attachment_id = ?)`, id,
	).Scan(&heldLinkRemains); err != nil {
		return fmt.Errorf("sqlite: delete attachment %q: check for held links: %w", id, err)
	}
	if heldLinkRemains {
		// A held link still references this attachment: refuse
		// entirely. Returning now (without Commit) rolls back the
		// non-held-links delete above too, so this call's net effect
		// is a no-op, not a partial prune.
		return fmt.Errorf("sqlite: delete attachment %q: %w", id, store.ErrHeld)
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM attachments WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete attachment %q: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: delete attachment %q: read rows affected: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("sqlite: delete attachment %q: %w", id, store.ErrNotFound)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: delete attachment %q: commit: %w", id, err)
	}
	return nil
}

// IsAttachmentHeld implements store.MetadataStore. It is a plain read
// against the reader pool — no transaction, no write-lock — used by
// callers (internal/core/retention.Sweeper) to narrow, immediately
// before an out-of-band destructive call (storage.Driver.Delete), the
// TOCTOU window DeleteAttachment's doc comment describes.
func (s *Store) IsAttachmentHeld(ctx context.Context, id string) (bool, error) {
	var held bool
	err := s.db.reader.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM links WHERE attachment_id = ? AND hold = 1)`, id,
	).Scan(&held)
	if err != nil {
		return false, fmt.Errorf("sqlite: is attachment held %q: %w", id, err)
	}
	return held, nil
}

// ExpireStaleLinks implements store.MetadataStore as a single bulk
// UPDATE, driven entirely by the database (no rows are ever read into
// Go memory), matching CLAUDE.md invariant #4.
func (s *Store) ExpireStaleLinks(ctx context.Context, now string) (int, error) {
	res, err := s.db.writer.ExecContext(ctx,
		`UPDATE links SET status = ? WHERE status = ? AND expires_at < ?`,
		string(store.LinkStatusExpired), string(store.LinkStatusActive), now,
	)
	if err != nil {
		return 0, fmt.Errorf("sqlite: expire stale links: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: expire stale links: read rows affected: %w", err)
	}
	return int(affected), nil
}

// nowText returns the current UTC time formatted with timeLayout, for
// created_at columns written internally by Store (as opposed to
// caller-supplied expires_at/now values, which callers control so
// tests can exercise expiry deterministically).
func nowText() string {
	return time.Now().UTC().Format(timeLayout)
}

// parseTime parses a timestamp column value written with timeLayout.
func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("sqlite: parse timestamp %q: %w", s, err)
	}
	return t, nil
}
