package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/302-digital/attachra/internal/core/mail"
	"github.com/302-digital/attachra/internal/core/store"
)

// defaultMessagePageSize and maxMessagePageSize mirror the API
// contract's Limit parameter (api/openapi.yaml: default 50, max 200),
// matching defaultLinkPageSize/maxLinkPageSize.
const (
	defaultMessagePageSize = 50
	maxMessagePageSize     = 200
)

// ListMessages implements store.MetadataStore using the same keyset
// pagination over (created_at, id) as ListLinks: it fetches limit+1
// rows so it can tell whether a further page exists without a second
// COUNT query, then trims the extra row and issues a NextCursor
// pointing just past the last returned row. The recipient filter is
// an EXISTS subquery against links rather than a JOIN, so it narrows
// which messages match without duplicating a message row per matching
// link or disturbing the enrichMessages aggregation below (which must
// see every link/attachment belonging to a matched message, not just
// the ones satisfying the filter).
//
// Every filter in p is combined with AND into a single parameterized
// query — sender and recipient are exact matches against the
// mail.NormalizeAddress canonical form (each argument is normalized
// in Go before binding, matching how every write path already stores
// it — see ListMessagesBySender's doc comment, ATR-293), status is an
// exact match, from/to bound created_at — with every value bound as a
// placeholder argument, never interpolated into the SQL text.
func (s *Store) ListMessages(ctx context.Context, p store.MessageListParams) (store.MessagePage, error) {
	limit := store.ClampLimit(p.Limit, defaultMessagePageSize, maxMessagePageSize)

	var conds []string
	var args []any

	if p.Sender != "" {
		conds = append(conds, "sender = ?")
		args = append(args, mail.NormalizeAddress(p.Sender))
	}
	if p.Status != "" {
		conds = append(conds, "status = ?")
		args = append(args, string(p.Status))
	}
	if p.Recipient != "" {
		conds = append(conds, "EXISTS (SELECT 1 FROM links l WHERE l.message_id = messages.id AND l.recipient = ?)")
		args = append(args, mail.NormalizeAddress(p.Recipient))
	}
	if !p.From.IsZero() {
		conds = append(conds, "created_at >= ?")
		args = append(args, p.From.UTC().Format(timeLayout))
	}
	if !p.To.IsZero() {
		conds = append(conds, "created_at < ?")
		args = append(args, p.To.UTC().Format(timeLayout))
	}

	if p.Cursor != "" {
		afterCreatedAt, afterID, derr := store.DecodeCursor(p.Cursor)
		if derr != nil {
			// derr already wraps store.ErrInvalidCursor; propagate it
			// unwrapped so the caller's errors.Is check (see
			// internal/adapters/http's listMessages) can tell a bad
			// client-supplied cursor apart from a genuine query failure.
			return store.MessagePage{}, fmt.Errorf("sqlite: list messages: %w", derr)
		}
		conds = append(conds, "(created_at > ? OR (created_at = ? AND id > ?))")
		args = append(args, afterCreatedAt, afterCreatedAt, afterID)
	}

	query := `SELECT ` + messageColumns + ` FROM messages`
	if len(conds) > 0 {
		// nolint:gosec // G202 false positive: conds only ever holds the
		// fixed "column = ?"/EXISTS fragments chosen by this function
		// above, never a caller-supplied string; every actual filter
		// value is bound as a placeholder argument in args, never
		// interpolated into the query text. Same discipline as
		// sqlite.ListLinks.
		query += ` WHERE ` + strings.Join(conds, " AND ")
	}
	query += ` ORDER BY created_at ASC, id ASC LIMIT ?`
	args = append(args, limit+1)

	rows, err := s.db.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return store.MessagePage{}, fmt.Errorf("sqlite: list messages: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var messages []store.Message
	for rows.Next() {
		m, createdAt, serr := scanMessage(rows)
		if serr != nil {
			return store.MessagePage{}, fmt.Errorf("sqlite: list messages: %w", serr)
		}
		t, perr := parseTime(createdAt)
		if perr != nil {
			return store.MessagePage{}, fmt.Errorf("sqlite: list messages: %w", perr)
		}
		m.CreatedAt = t
		messages = append(messages, m)
	}
	if err := rows.Err(); err != nil {
		return store.MessagePage{}, fmt.Errorf("sqlite: list messages: %w", err)
	}

	var nextCursor string
	if len(messages) > limit {
		// The extra (limit+1'th) row proves there is another page; drop
		// it from the returned data and encode a cursor past the last
		// row we actually return.
		last := messages[limit-1]
		messages = messages[:limit]
		nextCursor = store.EncodeCursor(last.CreatedAt.Format(timeLayout), last.ID)
	}

	summaries, err := s.enrichMessages(ctx, messages)
	if err != nil {
		return store.MessagePage{}, fmt.Errorf("sqlite: list messages: %w", err)
	}

	return store.MessagePage{Messages: summaries, NextCursor: nextCursor}, nil
}

// GetMessageSummary implements store.MetadataStore.
func (s *Store) GetMessageSummary(ctx context.Context, id string) (store.MessageSummary, error) {
	row := s.db.reader.QueryRowContext(ctx, `SELECT `+messageColumns+` FROM messages WHERE id = ?`, id)

	m, createdAt, err := scanMessage(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.MessageSummary{}, fmt.Errorf("sqlite: get message summary %q: %w", id, store.ErrNotFound)
		}
		return store.MessageSummary{}, fmt.Errorf("sqlite: get message summary %q: %w", id, err)
	}

	t, err := parseTime(createdAt)
	if err != nil {
		return store.MessageSummary{}, fmt.Errorf("sqlite: get message summary %q: %w", id, err)
	}
	m.CreatedAt = t

	summaries, err := s.enrichMessages(ctx, []store.Message{m})
	if err != nil {
		return store.MessageSummary{}, fmt.Errorf("sqlite: get message summary %q: %w", id, err)
	}
	return summaries[0], nil
}

// enrichMessages computes the two aggregates api/openapi.yaml's
// Message schema documents as derived rather than stored
// (attachment_count, recipients) for every message in messages,
// batched into exactly two queries total regardless of len(messages)
// (a `WHERE message_id IN (...)` per aggregate) rather than a
// per-message round trip, so a full page of up to
// maxMessagePageSize messages never costs more than a small, fixed
// number of queries.
func (s *Store) enrichMessages(ctx context.Context, messages []store.Message) ([]store.MessageSummary, error) {
	summaries := make([]store.MessageSummary, len(messages))
	if len(messages) == 0 {
		return summaries, nil
	}

	ids := make([]any, len(messages))
	index := make(map[string]int, len(messages))
	for i, m := range messages {
		summaries[i] = store.MessageSummary{Message: m, Recipients: []string{}}
		ids[i] = m.ID
		index[m.ID] = i
	}
	placeholders := sqlPlaceholders(len(ids))

	// nolint:gosec // G202 false positive: placeholders is built purely
	// from the literal "?"/"," characters by sqlPlaceholders (see its
	// own doc comment) — never from caller-supplied data — and every
	// actual message ID is bound as a placeholder argument in ids,
	// never interpolated into the query text.
	countRows, err := s.db.reader.QueryContext(ctx,
		`SELECT message_id, COUNT(*) FROM attachments WHERE message_id IN (`+placeholders+`) GROUP BY message_id`, ids...)
	if err != nil {
		return nil, fmt.Errorf("enrich messages: count attachments: %w", err)
	}
	defer func() { _ = countRows.Close() }()
	for countRows.Next() {
		var messageID string
		var count int
		if err := countRows.Scan(&messageID, &count); err != nil {
			return nil, fmt.Errorf("enrich messages: scan attachment count: %w", err)
		}
		if i, ok := index[messageID]; ok {
			summaries[i].AttachmentCount = count
		}
	}
	if err := countRows.Err(); err != nil {
		return nil, fmt.Errorf("enrich messages: count attachments: %w", err)
	}

	// nolint:gosec // G202 false positive: same discipline as the count
	// query above — placeholders is a fixed "?"/"," string, every value
	// is bound via ids.
	recipientRows, err := s.db.reader.QueryContext(ctx,
		`SELECT DISTINCT message_id, recipient FROM links WHERE message_id IN (`+placeholders+`) ORDER BY message_id, recipient`, ids...)
	if err != nil {
		return nil, fmt.Errorf("enrich messages: list recipients: %w", err)
	}
	defer func() { _ = recipientRows.Close() }()
	for recipientRows.Next() {
		var messageID, recipient string
		if err := recipientRows.Scan(&messageID, &recipient); err != nil {
			return nil, fmt.Errorf("enrich messages: scan recipient: %w", err)
		}
		if i, ok := index[messageID]; ok {
			summaries[i].Recipients = append(summaries[i].Recipients, recipient)
		}
	}
	if err := recipientRows.Err(); err != nil {
		return nil, fmt.Errorf("enrich messages: list recipients: %w", err)
	}

	return summaries, nil
}

// sqlPlaceholders returns a comma-joined string of n "?" placeholders
// (e.g. "?,?,?" for n=3), for building a fixed-shape "IN (...)" clause
// whose argument count is only known at runtime (the number of
// messages on one page). The returned string is built purely from the
// literal "?" and "," characters — never from caller-supplied data —
// so it carries no injection risk despite being concatenated into a
// query; every actual value is still bound as a placeholder argument
// by the caller.
func sqlPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
