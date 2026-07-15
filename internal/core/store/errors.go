package store

import "errors"

// ErrNotFound is returned by any single-row lookup (GetLink,
// GetLinkByTokenHash, GetMessageLinkByTokenHash, GetMessage,
// GetAttachment) when no matching row exists. Callers on the
// resolve/download path must map this to the same generic
// not-found response as an expired or revoked link (SR-125-5): the
// caller, not the store, is responsible for not leaking which case
// occurred.
var ErrNotFound = errors.New("store: not found")

// ErrDownloadLimitReached is returned by RegisterDownload when the
// guarded atomic UPDATE affects zero rows because the link's download
// budget is already exhausted (or the link no longer exists / is not
// active). It intentionally does not distinguish these cases at the
// store layer: the guarded UPDATE is a single indivisible operation
// (docs/architecture/adr-011-metadata-db.md "atomic download counter
// increment"), and finer diagnosis (expired vs revoked vs exhausted)
// is done by a separate read the caller may perform for error
// reporting, not by the counter operation itself.
var ErrDownloadLimitReached = errors.New("store: download limit reached")

// ErrHeld is returned by DeleteAttachment when its guarded DELETE
// refuses to remove the Attachment row because at least one of its
// Link rows currently has Hold set (US-5.3/ATR-179, ATR-259: legal
// hold must block retention deletion, not just revoke). This is the
// store-layer authoritative backstop against the TOCTOU window between
// ListExpiredAttachments (which excludes held attachments at the time
// it runs) and a later DeleteAttachment call for one of the attachments
// it returned: a hold set in that window is caught here, atomically,
// by the same guarded-DELETE mechanism RegisterDownload/
// RegisterDownloadByID already use for their own atomic counter
// checks — never by a preceding read followed by a separate write.
var ErrHeld = errors.New("store: attachment held, delete refused")

// ErrInvalidCursor is returned (wrapped) by DecodeCursor when a
// caller-supplied pagination cursor is empty or malformed: a client
// that tampers with or invents a cursor value must get a clean 400 at
// the API layer, never a 500 (SR-130-5). Every ListXxx implementation
// that decodes a cursor propagates this sentinel unchanged so the HTTP
// layer can distinguish "bad client input" from a genuine store
// failure with a single errors.Is check, regardless of which list
// resource (API tokens, links, ...) is being paginated.
var ErrInvalidCursor = errors.New("store: invalid pagination cursor")
