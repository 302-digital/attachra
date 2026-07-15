package link

import "errors"

// ErrNotFound is returned by Resolve when no active, matching link or
// package exists for a given token, including for a token that once
// existed but has since expired or been revoked (SR-125-5): Resolve
// deliberately does not distinguish "never existed" from "gone" so
// callers render one generic response and cannot be used to enumerate
// valid tokens.
var ErrNotFound = errors.New("link: not found")

// ErrHeld is returned by Revoke when the requested link (or, for a
// cascading revoke, at least one link belonging to the message/sender)
// is under legal hold (Hold == true). Per
// docs/compliance/journaling-position.md §4, a link under hold must
// not be revoked until the hold is explicitly lifted by an authorized
// human; ErrHeld signals that refusal so callers can surface it
// distinctly from a not-found or already-revoked outcome (this is an
// internal/operator-facing error, not exposed to the anonymous
// download path, so it does not need the generic-response treatment
// ErrNotFound gets).
var ErrHeld = errors.New("link: held, revoke refused")
