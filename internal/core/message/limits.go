package message

// Limits bounds the resources the parser is willing to spend on a
// single message. All limits are configurable by the caller (see
// SR-117-1 and SR-117-2) so that the adapter layer can wire them to
// operator-facing configuration; Parse itself carries no defaults
// baked in beyond what DefaultLimits returns.
//
// Exceeding any limit aborts parsing with a *LimitError, which callers
// resolve into their configured fail-open/fail-closed policy (see
// the mail-must-never-be-lost invariant and ADR-116 SR-116-1) rather
// than the parser deciding that policy itself.
type Limits struct {
	// MaxDepth is the maximum nesting depth of multipart and
	// message/rfc822 parts. The top-level message body is depth 0;
	// each multipart or rfc822 envelope entered increases the depth
	// by one. Zero means "unset"; DefaultLimits provides a sane value.
	MaxDepth int

	// MaxParts is the maximum total number of MIME parts (leaf and
	// container) visited while walking the tree, across the whole
	// message including nested message/rfc822 parts.
	MaxParts int

	// MaxHeaders is the maximum number of header fields allowed on
	// any single part (including the top-level message).
	MaxHeaders int

	// MaxPartSize is the maximum number of bytes read from any single
	// part's body. A part whose body exceeds this size aborts
	// parsing; it is not silently truncated, since silent truncation
	// would let an oversized attachment pass policy checks on partial
	// data.
	MaxPartSize int64

	// MaxTotalSize is the maximum cumulative number of body bytes
	// read across all parts in the message.
	MaxTotalSize int64
}

// DefaultLimits returns conservative, production-safe limits suitable
// as a starting point. Callers should generally source these values
// from operator configuration rather than relying on the defaults in
// production.
func DefaultLimits() Limits {
	return Limits{
		MaxDepth:     10,
		MaxParts:     1000,
		MaxHeaders:   256,
		MaxPartSize:  512 << 20,  // 512 MiB per part
		MaxTotalSize: 1024 << 20, // 1 GiB per message
	}
}

// normalized returns a copy of l with any zero-valued field replaced
// by the corresponding DefaultLimits value, so a caller-provided
// partial Limits behaves predictably instead of degrading to "no
// limit" for whichever field they forgot to set.
func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxParts <= 0 {
		l.MaxParts = d.MaxParts
	}
	if l.MaxHeaders <= 0 {
		l.MaxHeaders = d.MaxHeaders
	}
	if l.MaxPartSize <= 0 {
		l.MaxPartSize = d.MaxPartSize
	}
	if l.MaxTotalSize <= 0 {
		l.MaxTotalSize = d.MaxTotalSize
	}
	return l
}
