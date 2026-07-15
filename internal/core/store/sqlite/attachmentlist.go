package sqlite

import (
	"context"
	"fmt"
	"strings"

	"github.com/302-digital/attachra/internal/core/store"
)

// defaultAttachmentPageSize and maxAttachmentPageSize mirror the API
// contract's Limit parameter (api/openapi.yaml: default 50, max 200),
// matching defaultLinkPageSize/maxLinkPageSize.
const (
	defaultAttachmentPageSize = 50
	maxAttachmentPageSize     = 200
)

// likeEscape is the ESCAPE character globToLike uses to neutralize any
// literal LIKE metacharacter (`%`, `_`) that appears in a caller's
// filter string, so it is matched literally rather than as a wildcard.
const likeEscape = `\`

// globToLike translates the LIKE-expressible subset of
// internal/core/policy's glob dialect (`*` any run of characters, `?`
// exactly one character — see policy.compileGlob, backed by
// path.Match) into a standard SQL LIKE pattern: both SQLite and
// Postgres support LIKE ... ESCAPE (ADR-011 portability), whereas
// SQLite's GLOB operator is SQLite-only and Postgres's own glob
// support differs. Any literal `%`, `_` or backslash in pattern is
// escaped first so it is matched as a literal character rather than a
// LIKE metacharacter.
//
// This is a deliberately narrower grammar than policy's own glob
// dialect: path.Match's character classes (`[abc]`, `[a-z]`) have no
// LIKE equivalent and are NOT translated specially here — a `[` or `]`
// in a filter value is matched as a literal character, never as a
// class. Filtering with the full path.Match grammar would require
// pulling every candidate row into Go memory before matching, which
// would break this method's cursor-pagination correctness (a filtered
// page could return fewer than `limit` rows even though more matching
// rows exist further down the table, per api/openapi.yaml SR-130-5);
// staying on portable, index-friendly SQL LIKE is the deliberate
// trade-off (documented here and in the API's known-discrepancies
// list, see this task's final report).
func globToLike(pattern string) string {
	var b strings.Builder
	for _, r := range pattern {
		switch r {
		case '%', '_', '\\':
			b.WriteString(likeEscape)
			b.WriteRune(r)
		case '*':
			b.WriteByte('%')
		case '?':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ListAttachments implements store.MetadataStore using the same
// keyset pagination over (created_at, id) as ListLinks/ListMessages:
// it fetches limit+1 rows so it can tell whether a further page exists
// without a second COUNT query, then trims the extra row and issues a
// NextCursor pointing just past the last returned row.
//
// Every filter in p is combined with AND into a single parameterized
// query — message_id is an exact match, filename/mime_type are
// case-insensitive LIKE patterns translated by globToLike, min_size/
// max_size/from/to are inclusive/exclusive range bounds — with every
// value bound as a placeholder argument, never interpolated into the
// SQL text.
func (s *Store) ListAttachments(ctx context.Context, p store.AttachmentListParams) (store.AttachmentPage, error) {
	limit := store.ClampLimit(p.Limit, defaultAttachmentPageSize, maxAttachmentPageSize)

	var conds []string
	var args []any

	if p.MessageID != "" {
		conds = append(conds, "message_id = ?")
		args = append(args, p.MessageID)
	}
	if p.Filename != "" {
		conds = append(conds, `LOWER(filename) LIKE LOWER(?) ESCAPE '\'`)
		args = append(args, globToLike(p.Filename))
	}
	if p.MimeType != "" {
		conds = append(conds, `LOWER(detected_type) LIKE LOWER(?) ESCAPE '\'`)
		args = append(args, globToLike(p.MimeType))
	}
	if p.MinSize != nil {
		conds = append(conds, "size >= ?")
		args = append(args, *p.MinSize)
	}
	if p.MaxSize != nil {
		conds = append(conds, "size <= ?")
		args = append(args, *p.MaxSize)
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
			// internal/adapters/http's listAttachments) can tell a bad
			// client-supplied cursor apart from a genuine query failure.
			return store.AttachmentPage{}, fmt.Errorf("sqlite: list attachments: %w", derr)
		}
		conds = append(conds, "(created_at > ? OR (created_at = ? AND id > ?))")
		args = append(args, afterCreatedAt, afterCreatedAt, afterID)
	}

	query := `SELECT ` + attachmentColumns + ` FROM attachments`
	if len(conds) > 0 {
		// nolint:gosec // G202 false positive: conds only ever holds the
		// fixed "column op ?" fragments chosen by this function above,
		// never a caller-supplied string; every actual filter value
		// (including the LIKE pattern globToLike builds) is bound as a
		// placeholder argument in args, never interpolated into the
		// query text. Same discipline as sqlite.ListLinks.
		query += ` WHERE ` + strings.Join(conds, " AND ")
	}
	query += ` ORDER BY created_at ASC, id ASC LIMIT ?`
	args = append(args, limit+1)

	rows, err := s.db.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return store.AttachmentPage{}, fmt.Errorf("sqlite: list attachments: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var attachments []store.Attachment
	for rows.Next() {
		a, createdAt, serr := scanAttachment(rows)
		if serr != nil {
			return store.AttachmentPage{}, fmt.Errorf("sqlite: list attachments: %w", serr)
		}
		t, perr := parseTime(createdAt)
		if perr != nil {
			return store.AttachmentPage{}, fmt.Errorf("sqlite: list attachments: %w", perr)
		}
		a.CreatedAt = t
		attachments = append(attachments, a)
	}
	if err := rows.Err(); err != nil {
		return store.AttachmentPage{}, fmt.Errorf("sqlite: list attachments: %w", err)
	}

	page := store.AttachmentPage{Attachments: attachments}
	if len(attachments) > limit {
		// The extra (limit+1'th) row proves there is another page; drop
		// it from the returned data and encode a cursor past the last
		// row we actually return.
		last := attachments[limit-1]
		page.Attachments = attachments[:limit]
		page.NextCursor = store.EncodeCursor(last.CreatedAt.Format(timeLayout), last.ID)
	}
	return page, nil
}
