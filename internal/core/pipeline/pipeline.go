// Package pipeline defines the Core-side contract between mail
// transport adapters (e.g. the Postfix milter adapter, see ADR-008)
// and Attachra's attachment policy engine. It must not depend on any
// adapter-specific code (e.g. github.com/d--j/go-milter) — see
// ADR-002.
package pipeline

import (
	"context"
	"io"
)

// Envelope carries the transport-agnostic view of a single email
// message that an adapter has collected and hands to the Core for
// processing. Body is a streamed reader over the message so a
// Processor can inspect and forward the message without requiring
// the whole message to be buffered in memory (the streaming invariant —
// no full-message buffering); adapters are responsible for choosing
// how Body is backed (memory, temp file, etc.) on their side of the
// interface.
type Envelope struct {
	// Sender is the envelope-from address (SMTP MAIL FROM), in the
	// canonical form internal/core/mail.NormalizeAddress produces
	// (trimmed, angle-bracket-free, lower-cased). Adapters are
	// responsible for normalizing the raw transport value before
	// constructing an Envelope (see the milter adapter's MailFrom,
	// ATR-293) so every Core consumer of this field — policy matching,
	// the audit trail, and the messages table a revoke-by-sender query
	// later reads back — agrees on one form.
	Sender string

	// Recipients lists the envelope-to addresses (SMTP RCPT TO), each
	// already normalized the same way as Sender (see its doc comment).
	// A message may have more than one recipient.
	Recipients []string

	// QueueID is the mail transport's identifier for this message
	// (e.g. the Postfix queue ID), used to correlate log and audit
	// entries across the processing pipeline. It may be empty if the
	// transport does not assign one until after the Envelope was
	// constructed.
	QueueID string

	// Body is a stream over the complete message (headers + body) as
	// received from the sending client. Processor implementations
	// must read Body at most once and must not assume it is
	// seekable.
	Body io.Reader
}

// VerdictAction identifies what the adapter should do with the
// message after Processor.Process returns.
type VerdictAction int

// Recognized VerdictAction values.
const (
	// VerdictAccept instructs the adapter to accept the message
	// without any modification.
	VerdictAccept VerdictAction = iota

	// VerdictRewrite instructs the adapter to replace the message
	// body and/or add headers before accepting it.
	VerdictRewrite

	// VerdictReject instructs the adapter to permanently reject the
	// message (SMTP 5xx).
	VerdictReject

	// VerdictTempFail instructs the adapter to temporarily reject
	// the message (SMTP 4xx), signaling the sending MTA to retry
	// later.
	VerdictTempFail
)

// String returns a human-readable name for the action, for logging.
func (a VerdictAction) String() string {
	switch a {
	case VerdictAccept:
		return "accept"
	case VerdictRewrite:
		return "rewrite"
	case VerdictReject:
		return "reject"
	case VerdictTempFail:
		return "tempfail"
	default:
		return "unknown"
	}
}

// Header is a single email header field to be added to the message by
// an adapter carrying out a VerdictRewrite.
type Header struct {
	Name  string
	Value string
}

// Verdict is the Core's decision for how a single message should be
// handled, returned by Processor.Process.
type Verdict struct {
	// Action selects which of the fields below are meaningful.
	Action VerdictAction

	// NewBody is the complete rewritten RFC 5322 message (headers +
	// body), used only when Action is VerdictRewrite. It is a
	// self-contained message a transport adapter delivers in place of
	// the original; the Core does not encode any particular transport's
	// content-replacement model here (ADR-002). The Core always emits
	// every header change it makes (e.g. X-Attachra-Processed) inside
	// NewBody's own header block — never via AddHeaders. Adapters whose
	// wire protocol replaces only the body (e.g. the milter adapter's
	// ReplaceBody / SMFIR_REPLBODY, which leaves the MTA's headers in
	// place) are responsible for splitting NewBody into its header block
	// and body and reconciling the message headers accordingly. It is a
	// stream so the adapter can forward it without buffering the whole
	// message in memory.
	NewBody io.Reader

	// AddHeaders lists extra headers an adapter should add, used only
	// when Action is VerdictRewrite and independent of NewBody's own
	// header block. The AttachmentProcessor leaves this empty (it emits
	// all header changes inside NewBody instead); it exists for
	// processors/adapters that want to request a header addition without
	// re-serializing the message body. Order is preserved.
	AddHeaders []Header

	// Reason is a human-readable explanation for VerdictReject and
	// VerdictTempFail, suitable for inclusion in the SMTP response
	// text sent back to the sending MTA. It must not be derived from
	// unsanitized message content (no embedded CR/LF).
	Reason string

	// Attachments summarizes how policy evaluation disposed of the
	// message's attachments, for adapter-side observability (e.g. the
	// milter adapter's per-message summary log, ATR-304). It carries
	// no mail-handling meaning of its own — Action/NewBody/AddHeaders/
	// Reason above fully determine what an adapter does with the
	// message; Attachments is purely descriptive.
	Attachments AttachmentSummary
}

// AttachmentSummary counts how a Processor disposed of a message's
// attachments. A Processor implementation that does not track
// attachment counts (e.g. PassthroughProcessor) leaves every field at
// its zero value, which callers should read as "no attachments
// observed" — accurate for a processor that never looks at
// attachments in the first place.
type AttachmentSummary struct {
	// Total is how many attachment/body parts were discovered in the
	// message, regardless of what the policy engine decided for each.
	Total int

	// Replaced is how many attachments were durably uploaded and
	// replaced with a personal download link. Only non-zero when
	// Action is VerdictRewrite.
	Replaced int

	// InlineProtected is how many attachments the ADR-016 inline
	// (CID) protection downgraded from replace to pass.
	InlineProtected int

	// BodyProtected is how many structural body parts (the message's
	// own text/plain or text/html content) the ADR-016 structural-body
	// protection downgraded from replace to pass.
	BodyProtected int
}

// Processor applies Attachra's attachment policies to a message and
// decides how the adapter should proceed. Implementations must be
// safe for concurrent use: an adapter may call Process for multiple
// simultaneous sessions.
//
// Process must not retain Envelope.Body past its return: adapters may
// discard or reuse the backing storage as soon as Process returns.
type Processor interface {
	Process(ctx context.Context, env *Envelope) (*Verdict, error)
}
