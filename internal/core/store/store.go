package store

import (
	"context"
	"time"
)

// NewMessageParams are the fields needed to create a Message row.
type NewMessageParams struct {
	ID      string
	QueueID string
	Sender  string

	// Status is the aggregated policy.MessageDecision.Action for this
	// message (ATR-198/T-8.1.4, see Message.Status's own doc comment).
	// An empty value persists the legacy/unknown sentinel rather than
	// failing the call, so existing direct callers that predate this
	// field (test fixtures) keep compiling unchanged.
	Status MessageStatus
}

// NewAttachmentParams are the fields needed to create an Attachment
// row.
type NewAttachmentParams struct {
	ID           string
	MessageID    string
	PartRef      string
	Filename     string
	DeclaredType string
	DetectedType string
	Size         int64
	StorageKey   string

	// RetainUntil is the storage retention deadline, RFC3339Nano UTC,
	// matching Attachment.RetainUntil (US-5.3/ATR-178, SR-123-1). It
	// must not be empty for attachments created via the normal
	// link.Engine.CreateLinks path (only pre-migration legacy rows use
	// the empty-string sentinel, and only because they predate this
	// field existing at all).
	RetainUntil string
}

// NewLinkParams are the fields needed to create a Link row.
type NewLinkParams struct {
	ID           string
	MessageID    string
	AttachmentID string
	Recipient    string
	TokenHash    string
	ExpiresAt    string // RFC3339Nano UTC, matching Link.ExpiresAt.
	MaxDownloads int
}

// NewMessageLinkParams are the fields needed to create a MessageLink
// row.
type NewMessageLinkParams struct {
	TokenHash string
	MessageID string
	Recipient string
	ExpiresAt string // RFC3339Nano UTC.
}

// LinkListParams bounds and filters a ListLinks page (US-8.1/T-8.1.3,
// api/openapi.yaml `GET /links`). Every filter field is optional: its
// zero value (empty string / zero time.Time) means "no constraint on
// this dimension". Cursor is the opaque string returned as a previous
// page's LinkPage.NextCursor; an empty Cursor requests the first page
// (SR-130-5's mandatory pagination, same keyset-over-(created_at, id)
// scheme as APITokenListParams).
type LinkListParams struct {
	Limit  int
	Cursor string

	// MessageID, when non-empty, restricts the result to links
	// belonging to this exact message.
	MessageID string

	// Recipient, when non-empty, restricts the result to links whose
	// Recipient matches exactly, case-insensitively.
	Recipient string

	// Status, when non-empty, restricts the result to links currently
	// in this exact LinkStatus.
	Status LinkStatus

	// From is an inclusive lower bound on CreatedAt; the zero
	// time.Time means no lower bound.
	From time.Time

	// To is an exclusive upper bound on CreatedAt; the zero time.Time
	// means no upper bound.
	To time.Time
}

// LinkPage is one page of ListLinks output. NextCursor is empty when
// the returned page is the last one (no further rows).
type LinkPage struct {
	Links      []Link
	NextCursor string
}

// MessageListParams bounds and filters a ListMessages page (US-8.1/
// T-8.1.4, api/openapi.yaml `GET /messages`). Every filter field is
// optional: its zero value means "no constraint on this dimension",
// mirroring LinkListParams. Cursor is the opaque string returned as a
// previous page's MessagePage.NextCursor; an empty Cursor requests the
// first page (SR-130-5's mandatory pagination, same keyset-over-
// (created_at, id) scheme as ListLinks/ListAPITokens).
type MessageListParams struct {
	Limit  int
	Cursor string

	// Sender, when non-empty, restricts the result to messages whose
	// Sender matches exactly, case-insensitively.
	Sender string

	// Recipient, when non-empty, restricts the result to messages that
	// have at least one Link row for this exact, case-insensitive
	// recipient — a Message row itself carries no recipient column
	// (api/openapi.yaml: "implemented as a join against this message's
	// links").
	Recipient string

	// Status, when non-empty, restricts the result to messages with
	// this exact MessageStatus.
	Status MessageStatus

	// From is an inclusive lower bound on CreatedAt; the zero
	// time.Time means no lower bound.
	From time.Time

	// To is an exclusive upper bound on CreatedAt; the zero time.Time
	// means no upper bound.
	To time.Time
}

// MessageSummary augments Message with fields derived from its
// Attachment/Link rows rather than stored directly on the messages
// table (api/openapi.yaml schema Message: "recipients" and
// "attachment_count" are both explicitly documented as derived, not
// stored columns). ListMessages/GetMessageSummary are the only
// MetadataStore methods that compute these; GetMessage (used by
// callers that only need existence/Sender, e.g. the revoke-by-message
// API) intentionally still returns a plain Message.
type MessageSummary struct {
	Message

	// Recipients lists the distinct recipients derived from this
	// message's Link rows. Never nil: an empty slice, not a nil one,
	// when the message has no links (e.g. a legacy row).
	Recipients []string

	// AttachmentCount is the number of Attachment rows belonging to
	// this message.
	AttachmentCount int
}

// MessagePage is one page of ListMessages output. NextCursor is empty
// when the returned page is the last one (no further rows).
type MessagePage struct {
	Messages   []MessageSummary
	NextCursor string
}

// AttachmentListParams bounds and filters a ListAttachments page
// (US-8.1/T-8.1.4, api/openapi.yaml `GET /attachments`). Every filter
// field is optional: its zero value means "no constraint on this
// dimension", mirroring LinkListParams/MessageListParams.
type AttachmentListParams struct {
	Limit  int
	Cursor string

	// MessageID, when non-empty, restricts the result to attachments
	// belonging to this exact message.
	MessageID string

	// Filename, when non-empty, restricts the result to attachments
	// whose Filename matches this case-insensitive glob pattern (`*`
	// any run of characters, `?` exactly one character — the
	// LIKE-translatable subset of the `when.attachment.filename`
	// grammar internal/core/policy implements via path.Match; unlike
	// that full grammar, character classes such as `[abc]` are matched
	// literally here rather than as a class, a deliberate narrowing
	// documented on the sqlite driver's ListAttachments so filtering
	// stays a single indexed/portable SQL LIKE rather than requiring
	// every row to be pulled into Go memory to filter with path.Match,
	// which would break cursor-pagination correctness).
	Filename string

	// MimeType, when non-empty, restricts the result to attachments
	// whose DetectedType (the real, magic-byte-sniffed type) matches
	// this case-insensitive glob pattern, same grammar/limitation as
	// Filename.
	MimeType string

	// MinSize, when non-nil, is an inclusive lower bound on Size, in
	// bytes.
	MinSize *int64

	// MaxSize, when non-nil, is an inclusive upper bound on Size, in
	// bytes.
	MaxSize *int64

	// From is an inclusive lower bound on CreatedAt; the zero
	// time.Time means no lower bound.
	From time.Time

	// To is an exclusive upper bound on CreatedAt; the zero time.Time
	// means no upper bound.
	To time.Time
}

// AttachmentPage is one page of ListAttachments output. NextCursor is
// empty when the returned page is the last one (no further rows).
type AttachmentPage struct {
	Attachments []Attachment
	NextCursor  string
}

// MetadataStore is the repository interface for Attachra's relational
// metadata (ADR-011). It is defined in internal/core so domain code
// (internal/core/link) depends only on this interface, never on a
// driver package or *sql.DB directly (ADR-002). Implementations live
// under internal/core/store/<driver> (MVP: sqlite).
//
// All methods must be safe for concurrent use by multiple goroutines.
// Implementations must never receive or return a bearer token: only
// pre-hashed TokenHash values cross this boundary (CLAUDE.md invariant
// #5, SR-124-2).
type MetadataStore interface {
	// CreateMessage inserts a new Message row.
	CreateMessage(ctx context.Context, p NewMessageParams) error

	// CreateAttachment inserts a new Attachment row.
	CreateAttachment(ctx context.Context, p NewAttachmentParams) error

	// CreateLink inserts a new Link row with Status LinkStatusActive,
	// Downloads 0 and Hold false.
	CreateLink(ctx context.Context, p NewLinkParams) error

	// CreateMessageLink inserts a new MessageLink row with Status
	// LinkStatusActive.
	CreateMessageLink(ctx context.Context, p NewMessageLinkParams) error

	// GetMessage returns the Message with the given ID, or an error
	// wrapping ErrNotFound.
	GetMessage(ctx context.Context, id string) (Message, error)

	// ListMessagesBySender returns every Message with the given exact
	// Sender, in creation order (oldest first). Used by the
	// revoke-by-sender operation (US-6.3, ATR-258): the caller resolves
	// the set of message IDs belonging to sender via this method, then
	// drives link.Engine.RevokeSender/RevokeMessage per message, since
	// that fan-out is an API/CLI-layer concern rather than link.Engine's
	// own (see link.Engine.RevokeSender's doc comment). An unknown
	// sender returns an empty slice and a nil error, not ErrNotFound:
	// "no messages from this sender" is a normal, expected outcome, not
	// a lookup failure.
	ListMessagesBySender(ctx context.Context, sender string) ([]Message, error)

	// ListMessages returns one page of Message rows, enriched into
	// MessageSummary, ordered by (created_at, id) ascending and
	// filtered by any non-zero field on p, using the same opaque,
	// server-issued cursor scheme ListLinks uses (SR-130-5). Used by
	// GET /api/v1/messages (US-8.1/T-8.1.4). An invalid p.Cursor
	// returns an error wrapping ErrInvalidCursor so the HTTP layer can
	// answer 400, not 500.
	ListMessages(ctx context.Context, p MessageListParams) (MessagePage, error)

	// GetMessageSummary returns the MessageSummary for the Message
	// with the given ID, or an error wrapping ErrNotFound. Used by GET
	// /api/v1/messages/{messageId} (US-8.1/T-8.1.4).
	GetMessageSummary(ctx context.Context, id string) (MessageSummary, error)

	// GetAttachment returns the Attachment with the given ID, or an
	// error wrapping ErrNotFound.
	GetAttachment(ctx context.Context, id string) (Attachment, error)

	// ListAttachments returns one page of Attachment rows ordered by
	// (created_at, id) ascending and filtered by any non-zero field on
	// p, using the same opaque, server-issued cursor scheme ListLinks
	// uses (SR-130-5). Used by GET /api/v1/attachments (US-8.1/
	// T-8.1.4). An invalid p.Cursor returns an error wrapping
	// ErrInvalidCursor so the HTTP layer can answer 400, not 500.
	ListAttachments(ctx context.Context, p AttachmentListParams) (AttachmentPage, error)

	// GetLinkByTokenHash returns the Link whose TokenHash matches
	// hash, or an error wrapping ErrNotFound. Lookup is by unique
	// index on token_hash (SR-124-2): implementations must not scan
	// or otherwise take a time proportional to the number of stored
	// links.
	GetLinkByTokenHash(ctx context.Context, hash string) (Link, error)

	// GetLinkByID returns the Link with the given store-assigned ID
	// (as opposed to GetLinkByTokenHash's lookup by bearer-token hash),
	// or an error wrapping ErrNotFound. Used by operator/API-facing
	// paths (single-link revoke, hold checks) that address a link by
	// its own identifier rather than by the recipient's token.
	GetLinkByID(ctx context.Context, id string) (Link, error)

	// GetMessageLinkByTokenHash returns the MessageLink whose
	// TokenHash matches hash, or an error wrapping ErrNotFound.
	GetMessageLinkByTokenHash(ctx context.Context, hash string) (MessageLink, error)

	// ListLinksByMessage returns every Link belonging to messageID,
	// in creation order. Used to render the package page (all
	// replace-attachments of one message) per
	// docs/architecture/package-page-decision.md §4.1 item 4.
	ListLinksByMessage(ctx context.Context, messageID string) ([]Link, error)

	// ListLinks returns one page of Link rows ordered by (created_at,
	// id) ascending, filtered by any non-zero field on p and paginated
	// with the same opaque, server-issued cursor scheme ListAPITokens
	// uses (SR-130-5). Used by GET /api/v1/links (US-8.1/T-8.1.3). An
	// invalid p.Cursor returns an error wrapping ErrInvalidCursor so the
	// HTTP layer can answer 400, not 500.
	ListLinks(ctx context.Context, p LinkListParams) (LinkPage, error)

	// RegisterDownload atomically increments the Downloads counter of
	// the link identified by hash, but only if the link is currently
	// LinkStatusActive, not expired (ExpiresAt > now), and MaxDownloads
	// is 0 (unlimited) or Downloads < MaxDownloads. Hold does not gate
	// downloads: it only blocks revoke and retention deletion (see
	// Link.Hold and internal/core/link.Revoke), so it is intentionally
	// not part of this guard.
	//
	// This must be implemented as the single guarded atomic UPDATE
	// described in docs/architecture/adr-011-metadata-db.md ("atomic
	// download counter increment"), driven by rows-affected, never by
	// a read-then-write sequence: that is the only way two concurrent
	// callers cannot both slip past the limit.
	//
	// On success, returns the Link as it existed immediately before
	// the increment (so the caller can stream the file described by
	// its AttachmentID without a second read). If the guarded UPDATE
	// affects zero rows, RegisterDownload returns an error wrapping
	// ErrDownloadLimitReached (link exhausted, expired, revoked, or
	// gone).
	RegisterDownload(ctx context.Context, hash string, now string) (Link, error)

	// RegisterDownloadByID is RegisterDownload keyed by the
	// store-assigned Link.ID instead of the bearer-token hash, for the
	// package-page step-2 download path
	// (docs/architecture/package-page-decision.md §4.1 items 3-4): a
	// recipient reaches the download form by presenting the
	// package-page token, never a per-attachment bearer token (the raw
	// per-attachment token is never persisted anywhere, CLAUDE.md
	// invariant #5, so it cannot be presented again here). id is a
	// non-secret row identifier, never a bearer token; the caller
	// (internal/core/link.Engine) is responsible for verifying id
	// belongs to the message the presented package token resolves to
	// before relying on this method's result as authorization — this
	// method itself performs no such membership check.
	//
	// Same single guarded atomic UPDATE contract as RegisterDownload:
	// increments only if the link is currently LinkStatusActive, not
	// expired, and under MaxDownloads, driven by rows-affected, never a
	// read-then-write. Returns the Link as it exists after the
	// increment, or an error wrapping ErrDownloadLimitReached (folds
	// not-found/expired/revoked/exhausted into one outcome, same as
	// RegisterDownload) if the guarded UPDATE affects zero rows.
	RegisterDownloadByID(ctx context.Context, id string, now string) (Link, error)

	// RevokeLink marks a single Link as LinkStatusRevoked. Returns
	// ErrHeld-wrapping error (via the caller, see internal/core/link)
	// is not this method's job: RevokeLink is a low-level, unguarded
	// status write. Hold enforcement is the responsibility of the
	// link.Engine, which must check Hold before calling this method.
	RevokeLink(ctx context.Context, id string) error

	// RevokeLinksByMessage marks every Link and the MessageLink
	// belonging to messageID as LinkStatusRevoked, in a single
	// transaction, skipping (leaving untouched) any Link row that has
	// Hold set. It returns the number of Link rows actually revoked.
	// Whether the caller treats a partial revoke (some links held) as
	// an error is a link.Engine-level decision (ErrHeld), not this
	// method's.
	RevokeLinksByMessage(ctx context.Context, messageID string) (revoked int, err error)

	// SetHold sets or clears the Hold flag (and HoldSetBy/HoldSetAt)
	// on the Link identified by id.
	SetHold(ctx context.Context, id string, hold bool, setBy string, setAt string) error

	// ListExpiredAttachments returns up to limit Attachment rows whose
	// RetainUntil has elapsed (a non-empty retain_until strictly before
	// now), ordered by RetainUntil ascending so a chunked sweep
	// (internal/core/retention, T-5.3.2/ATR-179, ADR-011's "chunked
	// DELETE" guidance) makes steady progress across repeated calls
	// instead of always the same rows. limit must be positive.
	//
	// An attachment with at least one Link row that has Hold set is
	// excluded from the result entirely, evaluated by the query itself
	// (a SQL-level NOT EXISTS / anti-join in the sqlite driver), never
	// by the caller filtering results in memory: this is a hard
	// requirement (ATR-259, docs/compliance/journaling-position.md §4)
	// because the caller's only use for this method's result is to
	// physically delete the returned attachments, and a hold must never
	// be bypassable by a caller that forgets to re-check it after the
	// fact.
	//
	// Legacy attachment rows created before RetainUntil existed (the
	// empty-string sentinel, see Attachment.RetainUntil's doc comment)
	// are never returned by this method.
	ListExpiredAttachments(ctx context.Context, now string, limit int) ([]Attachment, error)

	// CountHeldExpiredAttachments reports how many attachments currently
	// match ListExpiredAttachments' expiry condition but are excluded
	// from it solely because at least one of their Link rows has Hold
	// set. It exists purely for observability (ATR-259: "cleanup audit
	// event reflects hold-skips separately") — the retention
	// sweeper calls it once per pass to report a held-skip count
	// distinct from its deletion count, without ever materializing the
	// held rows themselves.
	CountHeldExpiredAttachments(ctx context.Context, now string) (int, error)

	// DeleteAttachment permanently removes the Attachment row identified
	// by id together with every Link row referencing it, in a single
	// transaction (US-5.3/ATR-179, SR-123-2: "consistent" metadata
	// deletion). Callers (internal/core/retention) are responsible for
	// having already deleted (or confirmed already-gone) the
	// corresponding storage.Driver object before calling this method, so
	// that a crash between the two steps never leaves a storage object
	// with no metadata row pointing to it — the reverse (this method
	// succeeding, then a crash before the storage delete) is the safe
	// direction: a subsequent retry re-attempts storage.Driver.Delete
	// only, which storage drivers must treat an already-missing key as
	// success (storage.ErrNotFound), making the overall two-step
	// deletion idempotent no matter where a crash lands.
	//
	// DeleteAttachment is itself a guarded delete (ATR-259 fix, added
	// after security review flagged the original unguarded version as a
	// TOCTOU race): the attachment row is removed only if none of its
	// Link rows currently has Hold set, checked and acted on by a single
	// conditional statement whose rows-affected result is authoritative
	// — never by a preceding read followed by a separate write (the same
	// discipline RegisterDownload/RegisterDownloadByID already use for
	// their own atomic guarded UPDATEs). If the attachment is held,
	// DeleteAttachment returns an error wrapping ErrHeld and leaves both
	// the attachment row and every one of its links completely untouched
	// (all-or-nothing: it never removes only the non-held links of a
	// held attachment).
	//
	// This guard is the store layer's authoritative defense against a
	// hold being set in the window between ListExpiredAttachments (T0,
	// which already excludes held attachments as of that moment) and
	// this call for one of the attachments it returned — a real window
	// in a chunked sweep, since deleting a chunk's storage objects one
	// by one over the network can take seconds to tens of seconds. It
	// does NOT, by itself, protect against a hold being set after the
	// caller's storage.Driver.Delete call has already removed the
	// object's bytes but before this method runs: in that ordering, this
	// guard still refuses to delete the metadata (the Attachment row
	// survives, recording what existed and its retention deadline), but
	// the object's bytes are already gone and cannot be restored by this
	// method. Closing that residual sub-operation window would require a
	// single transaction spanning both the object store and this
	// metadata store, which this interface does not provide. Callers
	// wanting the smallest practical exposure should call
	// IsAttachmentHeld immediately before invoking
	// storage.Driver.Delete, narrowing (not eliminating) the unprotected
	// interval to the gap between that check and the storage delete
	// itself — see internal/core/retention.Sweeper's doc comment for how
	// it combines both mitigations, and for why "never bypassable" is
	// deliberately not claimed as an absolute for the full
	// storage-plus-metadata deletion.
	//
	// If no Attachment exists for id, DeleteAttachment returns an error
	// wrapping ErrNotFound; callers performing a retry after a partial
	// prior run should treat that specifically as "already deleted",
	// not as a failure.
	DeleteAttachment(ctx context.Context, id string) error

	// IsAttachmentHeld reports whether the attachment identified by id
	// currently has at least one Link row with Hold set. It exists so a
	// caller about to perform a destructive action against a *different*
	// system that cannot share a transaction with this store
	// (storage.Driver.Delete) can re-check hold status immediately
	// beforehand, narrowing the TOCTOU window documented on
	// DeleteAttachment's doc comment to the smallest practical interval.
	// This method is a plain read with no side effect and no atomicity
	// guarantee of its own beyond the instant it runs —
	// DeleteAttachment's guarded DELETE, not this method, is the
	// authoritative check for the metadata half of a deletion.
	IsAttachmentHeld(ctx context.Context, id string) (bool, error)

	// ExpireStaleLinks marks every Link currently LinkStatusActive whose
	// ExpiresAt is strictly before now as LinkStatusExpired, in a single
	// bulk update, and returns the number of rows affected. This is a
	// non-destructive bookkeeping operation only (US-5.3 acceptance
	// criterion "marks links as expired"): Resolve/isUsable already
	// treat a past-ExpiresAt link as unusable regardless of its stored
	// Status (see store.Link's LinkStatusExpired doc comment), so
	// ExpireStaleLinks changes no caller-visible behavior — it only
	// makes the stored Status reflect reality for audit/reporting
	// purposes. Unlike ListExpiredAttachments/DeleteAttachment, this
	// method is intentionally not gated by Hold: marking a status field
	// destroys nothing and does not affect resolvability, so it carries
	// none of the legal-hold risk ATR-259 is concerned with.
	ExpireStaleLinks(ctx context.Context, now string) (int, error)
}
