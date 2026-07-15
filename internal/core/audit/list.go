package audit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// ErrInvalidCursor is returned (wrapped) by DecodeSeqCursor when a
// caller-supplied pagination cursor is empty or malformed: a client
// that tampers with or invents a cursor value must get a clean 400 at
// the API layer, never a 500 (SR-130-5), mirroring
// internal/core/store.ErrInvalidCursor's contract for this package's
// own cursor scheme.
var ErrInvalidCursor = errors.New("audit: invalid pagination cursor")

// ListParams bounds and filters one page of a GET /audit-style query
// (US-8.1/T-8.1.6, api/openapi.yaml `GET /audit`). From/To/Type mirror
// Filter's own semantics (inclusive-from, exclusive-to, empty Type
// matches every type); MessageID, when non-empty, restricts the result
// to events with an exact MessageID match. Limit/Cursor page the
// result the same opaque, server-issued way every other list endpoint
// in this codebase does (SR-130-5): an empty Cursor requests the first
// page.
type ListParams struct {
	From      time.Time
	To        time.Time
	Type      Type
	MessageID string

	Limit  int
	Cursor string
}

// Page is one page of ListEvents output, in ascending Seq order.
// NextCursor is empty when the returned page is the last one (no
// further rows).
type Page struct {
	Events     []Recorded
	NextCursor string
}

// EncodeSeqCursor builds the opaque pagination cursor ListEvents
// implementations issue: the Seq of the last row on a page, so the
// next page can resume with a strict "seq greater than this" keyset
// comparison rather than an offset (the same reasoning
// api/openapi.yaml's Pagination section gives for every other list
// endpoint applies here: the audit log is append-only and
// concurrently written, so an offset would silently skip or repeat
// rows).
func EncodeSeqCursor(seq int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(seq, 10)))
}

// DecodeSeqCursor reverses EncodeSeqCursor, returning an error wrapping
// ErrInvalidCursor (never a panic) for any malformed cursor so the
// HTTP layer can answer 400, not 500. An empty cursor is a caller
// error here (callers must check for the first-page case before
// decoding).
func DecodeSeqCursor(cursor string) (int64, error) {
	if cursor == "" {
		return 0, fmt.Errorf("audit: empty pagination cursor: %w", ErrInvalidCursor)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, fmt.Errorf("audit: malformed pagination cursor: %w", ErrInvalidCursor)
	}
	seq, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("audit: malformed pagination cursor: %w", ErrInvalidCursor)
	}
	return seq, nil
}
