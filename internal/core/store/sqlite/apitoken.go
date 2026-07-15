package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/302-digital/attachra/internal/core/store"
)

var _ store.APITokenStore = (*Store)(nil)

// apiTokenColumns is the fixed column order used by every SELECT ... FROM
// api_tokens query in this file, matching scanAPIToken.
//
//nolint:gosec // G101 false positive: this is a SQL column list, not a credential.
const apiTokenColumns = `id, name, role, token_hash, created_at, last_used_at, revoked_at`

// CreateAPIToken implements store.APITokenStore.
func (s *Store) CreateAPIToken(ctx context.Context, p store.NewAPITokenParams) error {
	_, err := s.db.writer.ExecContext(ctx,
		`INSERT INTO api_tokens (id, name, role, token_hash, created_at, last_used_at, revoked_at)
		 VALUES (?, ?, ?, ?, ?, NULL, NULL)`,
		p.ID, p.Name, string(p.Role), p.TokenHash, nowText(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: create api token %q: %w", p.ID, err)
	}
	return nil
}

// scanAPIToken scans a full api_tokens row (apiTokenColumns' order) into
// a store.APIToken, parsing its timestamps and reconstructing the
// nullable last_used_at/revoked_at pair (each left as the zero time.Time
// when NULL).
func scanAPIToken(row rowScanner) (store.APIToken, error) {
	var t store.APIToken
	var role, createdAt string
	var lastUsedAt, revokedAt sql.NullString

	if err := row.Scan(&t.ID, &t.Name, &role, &t.TokenHash, &createdAt, &lastUsedAt, &revokedAt); err != nil {
		return store.APIToken{}, err
	}
	t.Role = store.Role(role)

	parsed, err := parseTime(createdAt)
	if err != nil {
		return store.APIToken{}, fmt.Errorf("parse created_at: %w", err)
	}
	t.CreatedAt = parsed

	if lastUsedAt.Valid && lastUsedAt.String != "" {
		parsed, err = parseTime(lastUsedAt.String)
		if err != nil {
			return store.APIToken{}, fmt.Errorf("parse last_used_at: %w", err)
		}
		t.LastUsedAt = parsed
	}
	if revokedAt.Valid && revokedAt.String != "" {
		parsed, err = parseTime(revokedAt.String)
		if err != nil {
			return store.APIToken{}, fmt.Errorf("parse revoked_at: %w", err)
		}
		t.RevokedAt = parsed
	}

	return t, nil
}

// GetAPIToken implements store.APITokenStore.
func (s *Store) GetAPIToken(ctx context.Context, id string) (store.APIToken, error) {
	row := s.db.reader.QueryRowContext(ctx,
		`SELECT `+apiTokenColumns+` FROM api_tokens WHERE id = ?`, id)

	t, err := scanAPIToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.APIToken{}, fmt.Errorf("sqlite: get api token %q: %w", id, store.ErrNotFound)
		}
		return store.APIToken{}, fmt.Errorf("sqlite: get api token %q: %w", id, err)
	}
	return t, nil
}

// LookupActiveAPIToken implements store.APITokenStore. The
// `revoked_at IS NULL` predicate is what makes revocation immediate
// (SR-130-2): a revoked token is filtered out by the query itself, so it
// can never authenticate again regardless of any caller logic, and is
// reported as ErrNotFound identically to a never-existed hash.
func (s *Store) LookupActiveAPIToken(ctx context.Context, tokenHash string) (store.APIToken, error) {
	row := s.db.reader.QueryRowContext(ctx,
		`SELECT `+apiTokenColumns+` FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL`, tokenHash)

	t, err := scanAPIToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.APIToken{}, fmt.Errorf("sqlite: lookup active api token: %w", store.ErrNotFound)
		}
		return store.APIToken{}, fmt.Errorf("sqlite: lookup active api token: %w", err)
	}
	return t, nil
}

// ListAPITokens implements store.APITokenStore using keyset pagination
// over (created_at, id): it fetches limit+1 rows so it can tell whether a
// further page exists without a second COUNT query, then trims the extra
// row and issues a NextCursor pointing just past the last returned row.
func (s *Store) ListAPITokens(ctx context.Context, p store.APITokenListParams) (store.APITokenPage, error) {
	limit := store.ClampLimit(p.Limit, defaultAPITokenPageSize, maxAPITokenPageSize)

	var (
		rows *sql.Rows
		err  error
	)
	if p.Cursor == "" {
		rows, err = s.db.reader.QueryContext(ctx,
			`SELECT `+apiTokenColumns+`
			   FROM api_tokens
			  ORDER BY created_at ASC, id ASC
			  LIMIT ?`,
			limit+1,
		)
	} else {
		afterCreatedAt, afterID, derr := store.DecodeCursor(p.Cursor)
		if derr != nil {
			// derr already wraps store.ErrInvalidCursor; propagate it
			// unwrapped so the caller's errors.Is check (see
			// internal/adapters/http's listAPITokens) can tell a bad
			// client-supplied cursor apart from a genuine query failure.
			return store.APITokenPage{}, fmt.Errorf("sqlite: list api tokens: %w", derr)
		}
		rows, err = s.db.reader.QueryContext(ctx,
			`SELECT `+apiTokenColumns+`
			   FROM api_tokens
			  WHERE created_at > ? OR (created_at = ? AND id > ?)
			  ORDER BY created_at ASC, id ASC
			  LIMIT ?`,
			afterCreatedAt, afterCreatedAt, afterID, limit+1,
		)
	}
	if err != nil {
		return store.APITokenPage{}, fmt.Errorf("sqlite: list api tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []store.APIToken
	for rows.Next() {
		t, serr := scanAPIToken(rows)
		if serr != nil {
			return store.APITokenPage{}, fmt.Errorf("sqlite: list api tokens: %w", serr)
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return store.APITokenPage{}, fmt.Errorf("sqlite: list api tokens: %w", err)
	}

	page := store.APITokenPage{Tokens: tokens}
	if len(tokens) > limit {
		// The extra (limit+1'th) row proves there is another page; drop it
		// from the returned data and encode a cursor past the last row we
		// actually return.
		last := tokens[limit-1]
		page.Tokens = tokens[:limit]
		page.NextCursor = store.EncodeCursor(last.CreatedAt.Format(timeLayout), last.ID)
	}
	return page, nil
}

// RevokeAPIToken implements store.APITokenStore. The `revoked_at IS NULL`
// guard makes it idempotent: revoking an already-revoked token matches
// zero rows to update but is not an error (the token is already in the
// desired state), while a genuinely missing id is distinguished by a
// separate existence check so it can surface ErrNotFound.
func (s *Store) RevokeAPIToken(ctx context.Context, id string, revokedAt string) error {
	res, err := s.db.writer.ExecContext(ctx,
		`UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		revokedAt, id)
	if err != nil {
		return fmt.Errorf("sqlite: revoke api token %q: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: revoke api token %q: read rows affected: %w", id, err)
	}
	if affected == 1 {
		return nil
	}

	// Zero rows updated: either the token does not exist, or it was
	// already revoked. Disambiguate so a missing token surfaces
	// ErrNotFound while a repeat revoke is reported as success.
	var exists bool
	if err := s.db.reader.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM api_tokens WHERE id = ?)`, id,
	).Scan(&exists); err != nil {
		return fmt.Errorf("sqlite: revoke api token %q: existence check: %w", id, err)
	}
	if !exists {
		return fmt.Errorf("sqlite: revoke api token %q: %w", id, store.ErrNotFound)
	}
	return nil
}

// TouchAPIToken implements store.APITokenStore. It is a plain
// best-effort UPDATE: a missing id updates zero rows and returns nil
// (see the interface doc comment), since this write exists only for the
// last_used_at observability column and must never fail a request.
func (s *Store) TouchAPIToken(ctx context.Context, id string, usedAt string) error {
	if _, err := s.db.writer.ExecContext(ctx,
		`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, usedAt, id); err != nil {
		return fmt.Errorf("sqlite: touch api token %q: %w", id, err)
	}
	return nil
}

// defaultAPITokenPageSize and maxAPITokenPageSize mirror the API
// contract's Limit parameter (api/openapi.yaml: default 50, max 200).
const (
	defaultAPITokenPageSize = 50
	maxAPITokenPageSize     = 200
)
