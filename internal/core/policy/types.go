package policy

// Action selects what Attachra does with an attachment (or, once
// aggregated, with the whole message — see §3.1 of the policy format
// spec) once a rule or the default branch is chosen.
type Action string

// Recognized Action values, per docs/architecture/policy-format-v1.md
// §2.4. Strength/severity increases in the order they are listed:
// Pass is weakest, Block is strongest (used for worst-case
// aggregation across recipients, §3.4, and across attachments, §3.1).
const (
	// ActionPass forwards the attachment unmodified.
	ActionPass Action = "pass"
	// ActionReplace uploads the attachment to storage and substitutes
	// it with a personal download link.
	ActionReplace Action = "replace"
	// ActionBlock rejects the whole message.
	ActionBlock Action = "block"
)

// actionStrength ranks Action by severity so worst-case aggregation
// (§3.1, §3.4) can pick the strongest of several candidate actions.
// Unknown actions are treated as weaker than Pass so a validated
// Policy (which rejects unknown actions) never relies on this
// fallback in practice.
func actionStrength(a Action) int {
	switch a {
	case ActionPass:
		return 1
	case ActionReplace:
		return 2
	case ActionBlock:
		return 3
	default:
		return 0
	}
}

// strongestAction returns whichever of a and b is more severe
// (Block > Replace > Pass), per the worst-case aggregation rule in
// §3.1/§3.4 of the policy format spec.
func strongestAction(a, b Action) Action {
	if actionStrength(b) > actionStrength(a) {
		return b
	}
	return a
}

// Policy is the root of a parsed and validated policy document
// (docs/architecture/policy-format-v1.md §2.1). A zero-value Policy is
// not valid; obtain one via Parse or Load.
type Policy struct {
	// Version is the major policy format version. This build supports
	// version 1 only (§7.1).
	Version int `yaml:"version"`

	// Name is a human-readable policy name used in logs, audit
	// records and UI.
	Name string `yaml:"name"`

	// Description is free-form documentation for the policy.
	Description string `yaml:"description,omitempty"`

	// Rules is the ordered list of rules, evaluated top to bottom
	// (first-match-wins, §3.2). May be empty.
	Rules []Rule `yaml:"rules"`

	// Default is the action applied when no rule matches (§3.2). It
	// is required: SR-119-1 forbids a policy that silently passes
	// attachments by omission.
	Default ActionSpec `yaml:"default"`

	// Metadata holds arbitrary author/tooling key-value pairs. It is
	// reserved (§7.2): parsed but ignored by the engine.
	Metadata map[string]string `yaml:"metadata,omitempty"`

	// Defaults holds default action parameters inherited by rules
	// that omit them (e.g. a shared ttl). It is reserved (§7.2):
	// parsed but does not affect evaluation in v1.
	Defaults *ActionParams `yaml:"defaults,omitempty"`
}

// Rule is a single `when -> then` entry in Policy.Rules
// (docs/architecture/policy-format-v1.md §2.2).
type Rule struct {
	// Name identifies the rule for audit, dry-run and error messages.
	// Required.
	Name string `yaml:"name"`

	// Description is free-form documentation for the rule.
	Description string `yaml:"description,omitempty"`

	// When is the match condition. A nil When (the field was omitted
	// entirely) matches every attachment/recipient (catch-all, §3.3).
	When *When `yaml:"when,omitempty"`

	// Then is the action taken when When matches. Required.
	Then ActionSpec `yaml:"then"`

	// Disabled skips the rule during evaluation without deleting it
	// from the file. Defaults to false.
	Disabled bool `yaml:"disabled,omitempty"`
}

// When is the condition block of a Rule (§2.3). Its sections are
// combined with AND: a rule matches only if every section present in
// When matches (an absent section does not narrow the match).
type When struct {
	// Sender constrains the envelope-from address.
	Sender *AddressMatch `yaml:"sender,omitempty"`

	// Recipient constrains one envelope-to address at a time (see
	// §3.4 for how multiple recipients are aggregated).
	Recipient *AddressMatch `yaml:"recipient,omitempty"`

	// Attachment constrains the attachment under evaluation. A
	// non-nil, all-zero Attachment{} matches any attachment (§5,
	// scenario e) — it is semantically equivalent to omitting the
	// section, but documents intent.
	Attachment *AttachmentMatch `yaml:"attachment,omitempty"`
}

// AddressMatch is the shared address-matching grammar used by both
// `when.sender` and `when.recipient` (§2.3.1). Fields within
// AddressMatch are combined with OR (an address matches the section
// if it satisfies Address, OR Domain, OR Pattern); this differs
// deliberately from AttachmentMatch, where fields are AND'd — see
// §2.3.2 for the rationale.
type AddressMatch struct {
	// Address lists exact, case-insensitive full address matches,
	// e.g. "ceo@example.com".
	Address []string `yaml:"address,omitempty"`

	// Domain lists case-insensitive exact domain matches (the part of
	// the address after '@'). Subdomains are not included implicitly;
	// use Pattern for subtree matches.
	Domain []string `yaml:"domain,omitempty"`

	// Pattern lists case-insensitive glob masks (`*`, `?`) matched
	// against the full address, e.g. "*@*.example.com".
	Pattern []string `yaml:"pattern,omitempty"`
}

// AttachmentMatch is the `when.attachment` condition grammar (§2.3.2).
// Fields present within AttachmentMatch are combined with AND (e.g.
// MimeType AND Size both must match); a list value within a single
// field is OR'd.
type AttachmentMatch struct {
	// Size constrains the attachment's byte size range.
	Size *SizeRange `yaml:"size,omitempty"`

	// MimeType lists case-insensitive glob patterns matched against
	// the attachment's real, detected content type (magic bytes),
	// e.g. "application/pdf", "image/*".
	MimeType []string `yaml:"mime_type,omitempty"`

	// ClaimedMimeType lists case-insensitive glob patterns matched
	// against the Content-Type the message declared for the part,
	// independent of the real detected type (useful for spotting
	// spoofed declarations).
	ClaimedMimeType []string `yaml:"claimed_mime_type,omitempty"`

	// Extension lists case-insensitive file extensions, without the
	// leading dot, e.g. "exe", "js".
	Extension []string `yaml:"extension,omitempty"`

	// Filename lists case-insensitive glob patterns (`*`, `?`)
	// matched against the full attachment file name.
	Filename []string `yaml:"filename,omitempty"`

	// Disposition constrains the attachment's EFFECTIVE presentation
	// classification (ADR-016), not its raw Content-Disposition
	// header: "inline" matches a part whose message.Attachment.
	// InlineAsset is true (a presentation-inline asset — e.g. a logo
	// referenced from the HTML body via `cid:`, RFC 2387/2392),
	// "attachment" matches every other part. Matching the raw header
	// instead would be a policy bypass: some MUAs (Apple Mail) mark
	// genuine downloadable attachments Content-Disposition: inline.
	// Values within the list are OR'd, matching every other
	// AttachmentMatch field; validate() rejects any value other than
	// "inline"/"attachment". Absent (the common case) imposes no
	// constraint, matching every part — this is a backward-compatible
	// optional addition to §2.3.2 (§7.1: no version bump required).
	Disposition []string `yaml:"disposition,omitempty"`
}

// SizeRange bounds an attachment's byte size (§2.3.2). Bound is a
// custom scalar type accepting either a plain integer (bytes) or a
// unit-suffixed string ("10MB", "512KiB") — see size.go.
type SizeRange struct {
	// Min is the inclusive lower bound in bytes. Nil means unbounded.
	Min *Bound `yaml:"min,omitempty"`
	// Max is the inclusive upper bound in bytes. Nil means unbounded.
	Max *Bound `yaml:"max,omitempty"`
}

// ActionSpec is the `then` (and `default`) block (§2.4): what to do
// when a rule matches, or when no rule matched.
type ActionSpec struct {
	// Action selects the action taken. Required, must be one of
	// ActionPass, ActionReplace, ActionBlock.
	Action Action `yaml:"action"`

	ActionParams `yaml:",inline"`

	// Reason is a human-readable rejection reason, valid only for
	// Action == ActionBlock.
	Reason string `yaml:"reason,omitempty"`

	// Link is reserved (§7.2) for future link parameters (password,
	// watermark). Unknown subfields are a validation error in v1
	// since the type has no fields yet.
	Link *struct{} `yaml:"link,omitempty"`

	// DryRun overrides the global policy.dry_run config setting
	// (US-4.2/T-4.2.2) for this specific rule (or the `default`
	// branch) when non-nil: true forces dry-run behavior for matches
	// of this rule regardless of the global setting, false forces the
	// rule to apply for real even while the global setting is dry-run.
	// Nil (the field omitted) means "defer to the global setting" —
	// the common case. This is a minor, backward-compatible addition
	// to the §2.4 `then`/`default` schema (new optional field, §7.1:
	// does not require a `version` bump).
	//
	// See ApplyMode (mode.go), which is the single place this field
	// and the global dry-run setting are reconciled into the
	// mode-adjusted decision a Processor should act on.
	DryRun *bool `yaml:"dry_run,omitempty"`
}

// ActionParams holds the ActionReplace-only parameters shared by
// ActionSpec and Policy.Defaults.
type ActionParams struct {
	// TTL is the link lifetime, valid only for Action == ActionReplace.
	TTL *Duration `yaml:"ttl,omitempty"`

	// MaxDownloads caps the number of downloads permitted for the
	// generated link, valid only for Action == ActionReplace. Nil
	// means unlimited.
	MaxDownloads *int `yaml:"max_downloads,omitempty"`

	// Retention is how long the uploaded object is kept in storage,
	// valid only for Action == ActionReplace. May outlive TTL so the
	// object remains available for audit/recovery after the link
	// itself has expired.
	Retention *Duration `yaml:"retention,omitempty"`
}
