package audit

import "time"

// Type identifies what kind of occurrence an Event records. The set is
// intentionally small and stable: new event kinds should be added here
// deliberately, not inferred from free-form strings, so consumers
// (export, future SIEM integrations) can rely on an enum rather than
// parsing prose (SR-128-2).
type Type string

// Recognized Event Type values (docs/security/requirements-for-backlog.md
// ATR-128, SR-128-2: "events at every point — policy decision, download,
// revoke, errors, token/policy changes").
const (
	// TypeMessageProcessed records the terminal outcome of processing
	// one message through the pipeline (accept/rewrite/reject),
	// independent of the more granular TypePolicyDecision event for the
	// same message.
	TypeMessageProcessed Type = "message_processed"
	// TypePolicyDecision records the policy engine's decision for one
	// attachment or message (action taken, matched rule, dry-run
	// status).
	TypePolicyDecision Type = "policy_decision"
	// TypeAttachmentStored records a successful upload of one
	// attachment's payload to the storage backend.
	TypeAttachmentStored Type = "attachment_stored"
	// TypeLinksCreated records the minting of one or more download
	// links (and the package-page link) for a message.
	TypeLinksCreated Type = "links_created"
	// TypeDownload records a single successful or denied download
	// attempt against a link.
	TypeDownload Type = "download"
	// TypeRevoke records an explicit revoke action against a single
	// link or every link belonging to a message.
	TypeRevoke Type = "revoke"
	// TypeHold records an explicit legal-hold action (set or clear)
	// against a single link (ATR-257,
	// docs/compliance/journaling-position.md §4). Both directions
	// (setting and clearing the hold) share this Type; Details
	// distinguishes them via the "hold" boolean field, mirroring how
	// TypeRevoke folds success/failure into Details rather than
	// introducing a new Type per outcome.
	TypeHold Type = "hold"
	// TypeRetentionCleanup records the background retention sweep's
	// (internal/core/retention, US-5.3/ATR-179, SR-123-2) activity: one
	// event per attachment it actually deletes (Details carries the
	// attachment/storage key so the deletion is individually
	// traceable), plus one additional summary event per sweep pass
	// whenever it skipped at least one expired attachment because a
	// link on it is under legal hold (Details' "scope" field
	// distinguishes the two shapes: "deletion" vs "held_summary") — the
	// distinct-from-normal-deletion accounting ATR-259 requires
	// (docs/compliance/journaling-position.md §4).
	TypeRetentionCleanup Type = "retention_cleanup"
	// TypeTokenChange records the creation or revocation of an API
	// token (ATR-296, SR-128-2: a compromised admin token must leave a
	// tamper-evident trail if it mints a backdoor token or revokes
	// another one — the mutable slog line alone is not enough). Both
	// directions share this single Type, mirroring how TypeHold folds
	// "set" and "clear" together rather than introducing a Type per
	// outcome; Details' "action" field ("create" or "revoke")
	// distinguishes them. Details carries only non-secret token
	// metadata (token_id, name, role) — the secret and its hash never
	// enter an Event (invariant #5). Unlike TypeHold/TypeRevoke, a
	// failed create/revoke attempt is not separately recorded here:
	// those requests are rejected before any store change happens (bad
	// input, unknown role, unknown token id), so there is no state
	// change to make tamper-evident beyond what the API's own access
	// log already captures.
	TypeTokenChange Type = "token_change"
	// TypeError records a processing failure at any stage (parse,
	// policy, storage, link creation, rewrite) that could not be
	// classified under a more specific Type above.
	TypeError Type = "error"
)

// Valid reports whether t is one of the recognized Type values above
// (api/openapi.yaml schema AuditType). Used to validate a caller (API
// query parameter, CLI flag) supplied type filter before it reaches a
// query, so an unrecognized value is rejected explicitly (400 at the
// HTTP layer) rather than silently matching zero rows.
func (t Type) Valid() bool {
	switch t {
	case TypeMessageProcessed, TypePolicyDecision, TypeAttachmentStored, TypeLinksCreated,
		TypeDownload, TypeRevoke, TypeHold, TypeRetentionCleanup, TypeTokenChange, TypeError:
		return true
	default:
		return false
	}
}

// Event is a single append-only audit record (SR-128-1). Fields that
// originate from untrusted input (Recipient, and anything
// message/attachment-derived such as filenames or error text) must be
// carried only inside Details, and Details must always be persisted as
// a JSON-encoded blob via parameterized values — never through string
// concatenation into a query or into another field (SR-128-2).
//
// Event does not itself expose an ID/Seq/PrevHash before it is
// recorded: those are assigned by the AuditSink implementation at
// write time (see Record's doc comment and Recorded below), mirroring
// how store.NewMessageParams/store.Message are split into "fields the
// caller supplies" vs. "fields the store assigns".
type Event struct {
	// Timestamp is when the event occurred, always stored and compared
	// in UTC (matching internal/core/store's own timestamp discipline).
	// Callers should leave this zero to let the AuditSink stamp the
	// current time, or set it explicitly for deterministic tests.
	Timestamp time.Time

	// Type is the kind of occurrence this Event records.
	Type Type

	// Actor identifies who or what caused the event: an API
	// principal's identifier, "milter" for the automated mail path, or
	// "system" for background/internal actions. Never a bearer
	// token or secret.
	Actor string

	// MessageID is the store.Message.ID this event relates to, if any.
	// Empty for events not tied to a single message (e.g. a policy
	// reload).
	MessageID string

	// Recipient is the mail recipient this event relates to, if any.
	// This is untrusted, mail-derived input: implementations must
	// bind it as a parameterized value, never concatenate it into SQL
	// or log text (SR-128-2).
	Recipient string

	// Details carries every event-specific, potentially untrusted
	// field (filenames, error messages, rule names, IPs, etc.) as a
	// JSON object. Using a single structured map/JSON payload rather
	// than ad hoc typed columns keeps the schema stable as new event
	// producers are added, while still keeping untrusted values out of
	// any concatenated string (SR-128-2).
	Details map[string]any
}

// Recorded is an Event as it exists after being durably appended by an
// AuditSink: it carries the store-assigned identity and
// tamper-evidence fields alongside the original Event content.
type Recorded struct {
	Event

	// ID is the store-assigned identifier of this audit row.
	ID string

	// Seq is the monotonically increasing sequence number of this
	// event within the append-only log, assigned by the AuditSink in
	// insertion order. Seq (together with PrevHash) is the hook
	// SR-128-1 requires for tamper-evidence: a verifier can walk the
	// log in Seq order and confirm each row's PrevHash matches the
	// previous row's hash. Full chain verification is not implemented
	// by this task (see package doc comment); Seq/PrevHash are laid
	// down now so that verification can be added later without a
	// schema migration.
	Seq int64

	// PrevHash is the hash of the previous record in the chain (the
	// record with Seq-1), or empty for the very first record. Computing
	// and storing this value is the tamper-evidence hook mandated by
	// SR-128-1; verifying the chain end-to-end is intentionally out of
	// scope for this task (see package doc comment).
	PrevHash string
}
