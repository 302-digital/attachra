package message

import "fmt"

// LimitKind identifies which configured Limits field was exceeded.
type LimitKind string

// Recognized LimitKind values, one per Limits field.
const (
	LimitDepth     LimitKind = "depth"
	LimitParts     LimitKind = "parts"
	LimitHeaders   LimitKind = "headers"
	LimitPartSize  LimitKind = "part_size"
	LimitTotalSize LimitKind = "total_size"
)

// LimitError is returned by Parse when the message exceeds one of the
// configured Limits. It is a distinct, typed error (SR-117-1) so
// callers can distinguish "message too complex/large" from a
// malformed-message parse error and route it to their configured
// fail-open/fail-closed policy (the mail-must-never-be-lost invariant).
type LimitError struct {
	// Kind identifies which limit was exceeded.
	Kind LimitKind
	// PartPath identifies the part being processed when the limit
	// was hit, using the same dotted-index notation as
	// Attachment.PartPath (empty for message-wide limits such as
	// LimitParts and LimitTotalSize).
	PartPath string
	// Limit is the configured limit value that was exceeded.
	Limit int64
}

func (e *LimitError) Error() string {
	if e.PartPath == "" {
		return fmt.Sprintf("message: %s limit exceeded (limit=%d)", e.Kind, e.Limit)
	}
	return fmt.Sprintf("message: %s limit exceeded at part %q (limit=%d)", e.Kind, e.PartPath, e.Limit)
}

// newLimitError builds a *LimitError for the given kind, part path
// and limit value.
func newLimitError(kind LimitKind, partPath string, limit int64) *LimitError {
	return &LimitError{Kind: kind, PartPath: partPath, Limit: limit}
}
