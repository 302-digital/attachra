package store

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// cursorSeparator joins the two components of a keyset cursor. It is a
// NUL byte, which cannot appear in an RFC3339Nano timestamp or in any
// hex/base64-encoded row identifier this package generates, so splitting
// on it is unambiguous.
const cursorSeparator = "\x00"

// EncodeCursor builds the opaque, server-issued pagination cursor the
// API contract requires (SR-130-5): clients treat it as an unstructured
// token and never parse or construct one. It encodes the keyset position
// of the last row on a page — the (created_at, id) pair every list
// endpoint here orders by — so the next page can resume with a strict
// "row after this one" comparison rather than an offset (offset
// pagination silently skips or repeats rows when concurrent writes land
// between two page requests, a real hazard for these append-mostly
// tables; see api/openapi.yaml's Pagination section).
//
// createdAt must be the row's created_at column value in the exact
// RFC3339Nano text form it is stored in, so the decoded cursor compares
// byte-for-byte against the stored column.
func EncodeCursor(createdAt, id string) string {
	raw := createdAt + cursorSeparator + id
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor reverses EncodeCursor. It returns an error wrapping
// ErrInvalidCursor (never a panic) for any malformed cursor — a client
// that tampers with or invents a cursor value gets a clean 400, not a
// 500 (SR-130-5) — so every ListXxx driver method and the HTTP layer
// above it can distinguish "bad client input" from a genuine store
// failure with a single errors.Is(err, ErrInvalidCursor) check. An empty
// cursor is a caller error here (callers must check for the first-page
// case before decoding); it is reported as such rather than silently
// treated as the beginning.
func DecodeCursor(cursor string) (createdAt, id string, err error) {
	if cursor == "" {
		return "", "", fmt.Errorf("store: empty pagination cursor: %w", ErrInvalidCursor)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", "", fmt.Errorf("store: malformed pagination cursor: %w", ErrInvalidCursor)
	}
	createdAt, id, found := strings.Cut(string(raw), cursorSeparator)
	if !found || createdAt == "" || id == "" {
		return "", "", fmt.Errorf("store: malformed pagination cursor: missing component: %w", ErrInvalidCursor)
	}
	return createdAt, id, nil
}

// ClampLimit normalizes a caller-supplied page size to the API
// contract's bounds (SR-130-5's mandatory response-size cap): a
// non-positive limit falls back to def, and any value above max is
// capped at max. It centralizes the limit policy so every list endpoint
// enforces the same ceiling rather than trusting a client-supplied
// count.
func ClampLimit(limit, def, max int) int {
	if limit <= 0 {
		return def
	}
	if limit > max {
		return max
	}
	return limit
}
