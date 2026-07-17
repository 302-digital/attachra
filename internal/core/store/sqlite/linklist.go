package sqlite

import (
	"context"
	"fmt"
	"strings"

	"github.com/302-digital/attachra/internal/core/mail"
	"github.com/302-digital/attachra/internal/core/store"
)

// defaultLinkPageSize and maxLinkPageSize mirror the API contract's
// Limit parameter (api/openapi.yaml: default 50, max 200), matching
// defaultAPITokenPageSize/maxAPITokenPageSize.
const (
	defaultLinkPageSize = 50
	maxLinkPageSize     = 200
)

// ListLinks implements store.MetadataStore using the same keyset
// pagination over (created_at, id) as ListAPITokens: it fetches
// limit+1 rows so it can tell whether a further page exists without a
// second COUNT query, then trims the extra row and issues a
// NextCursor pointing just past the last returned row.
//
// Every filter in p is combined with AND into a single parameterized
// query — message_id and status are exact matches, recipient is an
// exact match against the mail.NormalizeAddress canonical form (the
// argument is normalized in Go before binding, matching how every
// write path already stores it, ATR-293), from/to bound created_at —
// with every value bound as a placeholder argument, never interpolated
// into the SQL text.
func (s *Store) ListLinks(ctx context.Context, p store.LinkListParams) (store.LinkPage, error) {
	limit := store.ClampLimit(p.Limit, defaultLinkPageSize, maxLinkPageSize)

	var conds []string
	var args []any

	if p.MessageID != "" {
		conds = append(conds, "message_id = ?")
		args = append(args, p.MessageID)
	}
	if p.Recipient != "" {
		conds = append(conds, "recipient = ?")
		args = append(args, mail.NormalizeAddress(p.Recipient))
	}
	if p.Status != "" {
		conds = append(conds, "status = ?")
		args = append(args, string(p.Status))
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
			// internal/adapters/http's listLinks) can tell a bad
			// client-supplied cursor apart from a genuine query failure.
			return store.LinkPage{}, fmt.Errorf("sqlite: list links: %w", derr)
		}
		conds = append(conds, "(created_at > ? OR (created_at = ? AND id > ?))")
		args = append(args, afterCreatedAt, afterCreatedAt, afterID)
	}

	query := `SELECT ` + linkColumns + ` FROM links`
	if len(conds) > 0 {
		// nolint:gosec // G202 false positive: conds only ever holds the
		// fixed "column = ?" fragments chosen by this function above,
		// never a caller-supplied string; every actual filter value is
		// bound as a placeholder argument in args, never interpolated
		// into the query text.
		query += ` WHERE ` + strings.Join(conds, " AND ")
	}
	query += ` ORDER BY created_at ASC, id ASC LIMIT ?`
	args = append(args, limit+1)

	rows, err := s.db.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return store.LinkPage{}, fmt.Errorf("sqlite: list links: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var links []store.Link
	for rows.Next() {
		l, serr := scanLink(rows)
		if serr != nil {
			return store.LinkPage{}, fmt.Errorf("sqlite: list links: %w", serr)
		}
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		return store.LinkPage{}, fmt.Errorf("sqlite: list links: %w", err)
	}

	page := store.LinkPage{Links: links}
	if len(links) > limit {
		// The extra (limit+1'th) row proves there is another page; drop it
		// from the returned data and encode a cursor past the last row we
		// actually return.
		last := links[limit-1]
		page.Links = links[:limit]
		page.NextCursor = store.EncodeCursor(last.CreatedAt.Format(timeLayout), last.ID)
	}
	return page, nil
}
