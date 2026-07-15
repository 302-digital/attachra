package store

import "time"

// LinkStatus is the lifecycle state of a Link or MessageLink.
type LinkStatus string

// Recognized LinkStatus values.
const (
	// LinkStatusActive means the link may still be resolved and, if
	// under its download/expiry limits, used to fetch bytes.
	LinkStatusActive LinkStatus = "active"
	// LinkStatusRevoked means the link was explicitly revoked (US-6.3)
	// and must never resolve to bytes again, regardless of remaining
	// TTL or download budget.
	LinkStatusRevoked LinkStatus = "revoked"
	// LinkStatusExpired means the link's TTL has elapsed. Attachra
	// treats an active link past ExpiresAt as expired even before a
	// background sweep sets this status explicitly (belt-and-braces:
	// Resolve always re-checks ExpiresAt regardless of the stored
	// status).
	LinkStatusExpired LinkStatus = "expired"
)

// Valid reports whether s is one of the three recognized LinkStatus
// values (api/openapi.yaml schema LinkStatus). Used to validate the
// `status` query filter on GET /links (US-8.1/T-8.1.3) before it
// reaches a query, mirroring Role.Valid()'s role of guarding a
// caller-supplied enum value at the API boundary.
func (s LinkStatus) Valid() bool {
	switch s {
	case LinkStatusActive, LinkStatusRevoked, LinkStatusExpired:
		return true
	default:
		return false
	}
}

// MessageStatus mirrors policy.Action (pass/replace/block) as
// persisted on a Message row (ATR-198/T-8.1.4, api/openapi.yaml
// Message.status: "aggregated worst-case policy action for the whole
// message"). It intentionally duplicates policy.Action's three string
// values rather than importing internal/core/policy, keeping this
// package free of a policy dependency (mirroring LinkStatus's own
// self-contained enum above); internal/core/link, which already
// depends on policy, converts with a plain string cast at the one call
// site that constructs a NewMessageParams (link.Engine.CreateLinks).
//
// The empty string is the legacy/unknown sentinel, used by Message
// rows created before this field existed and by any caller that does
// not supply one, mirroring Attachment.RetainUntil's own empty-string
// convention: it renders as JSON null (api/openapi.yaml: "nullable:
// true"), never as an empty string, at the HTTP layer.
type MessageStatus string

// Recognized MessageStatus values, mirroring policy.Action.
const (
	MessageStatusPass    MessageStatus = "pass"
	MessageStatusReplace MessageStatus = "replace"
	MessageStatusBlock   MessageStatus = "block"
)

// Valid reports whether s is one of the three recognized MessageStatus
// values (api/openapi.yaml schema Action) or the empty
// legacy/unknown sentinel. Used to validate the `status` query filter
// on GET /messages (US-8.1/T-8.1.4) before it reaches a query.
func (s MessageStatus) Valid() bool {
	switch s {
	case MessageStatusPass, MessageStatusReplace, MessageStatusBlock:
		return true
	default:
		return false
	}
}

// Message is a single processed email, identified by the milter
// queue ID. It is the root of the message -> attachment -> link graph
// (ADR-011).
//
// Status is the aggregated policy.MessageDecision.Action for this
// message (ATR-198/T-8.1.4). In practice every Message row that exists
// at all was created via internal/core/link.Engine.CreateLinks, which
// pipeline.AttachmentProcessor only calls once its policy decision has
// already resolved to "replace" (see hasReplace's guard in
// internal/core/pipeline/processor.go): a "pass" message is delivered
// untouched with no Message row at all, and a "block" message is
// rejected before one is ever created. Status is nonetheless carried
// as a genuine, policy-decision-derived column (not hardcoded to
// "replace") so it stays correct if that pipeline invariant ever
// changes, and legacy rows predating this column use the empty-string
// sentinel described on MessageStatus's own doc comment.
type Message struct {
	ID        string
	QueueID   string
	Sender    string
	Status    MessageStatus
	CreatedAt time.Time
}

// Attachment is a single replaced MIME part belonging to a Message.
// Filename/DeclaredType/DetectedType/Size are metadata only (SR-121-3,
// SR-124-3): the object payload itself lives in the storage.Driver
// backend, addressed by StorageKey, which is an opaque key produced by
// storage.NewObjectKey and carries no identifying information.
//
// RetainUntil is the storage retention deadline (US-5.3/ATR-178,
// SR-123-1): the point in time after which the background retention
// job (internal/core/retention, T-5.3.2/ATR-179) is free to delete
// both this attachment's storage object and this row. It is set once,
// at creation time, from the matched policy's `then.retention` or the
// configured global default (internal/core/link.Engine.CreateLinks),
// and is guaranteed to be at least the link TTL applied to the same
// message (link.resolveParams), so a link never outlives the object it
// points to. The zero time.Time is a legacy sentinel for attachment
// rows created before this field existed (pre-ATR-178 migration): such
// rows are deliberately excluded from retention cleanup rather than
// treated as already expired (see the sqlite driver's
// ListExpiredAttachments/CountHeldExpiredAttachments).
type Attachment struct {
	ID           string
	MessageID    string
	PartRef      string
	Filename     string
	DeclaredType string
	DetectedType string
	Size         int64
	StorageKey   string
	RetainUntil  time.Time
	CreatedAt    time.Time
}

// Link is the sole granularity for download, revoke and audit
// (docs/architecture/package-page-decision.md §4.1 item 4): one row
// per (message, attachment, recipient). TokenHash is the SHA-256 hash
// of the bearer token handed to the recipient; the token itself is
// never persisted (CLAUDE.md invariant #5, SR-124-2).
//
// Hold, HoldSetBy and HoldSetAt implement the legal-hold mechanism
// required by docs/compliance/journaling-position.md §4: while Hold is
// true, Revoke and retention deletion for this link must refuse with
// ErrHeld, regardless of caller. Hold can only be lifted by an
// explicit, audited action (out of scope for this task beyond the
// field itself and the guard in link.Revoke).
type Link struct {
	ID           string
	MessageID    string
	AttachmentID string
	Recipient    string
	TokenHash    string
	ExpiresAt    time.Time
	MaxDownloads int // 0 means unlimited.
	Downloads    int
	Status       LinkStatus
	Hold         bool
	HoldSetBy    string
	HoldSetAt    time.Time
	CreatedAt    time.Time
}

// MessageLink is the thin per-message token backing the "package
// page" landing view (docs/architecture/package-page-decision.md §4.1
// item 4): it identifies the message + recipient for the `/p/<token>`
// landing page. The file listing itself is not stored here — it is
// derived by selecting Links WHERE MessageID = ?. TokenHash is a
// SHA-256 hash; the raw token is never persisted.
type MessageLink struct {
	TokenHash string
	MessageID string
	Recipient string
	ExpiresAt time.Time
	Status    LinkStatus
	CreatedAt time.Time
}
