// Package pipeline's AttachmentProcessor wires together every Core
// component (message parsing, policy evaluation, storage upload, link
// generation and MIME rewrite) into the first end-to-end mail path
// (ATR-167). See doc comments below for the exact sequencing and how
// each step resolves into CLAUDE.md invariant #3 (a message can never
// be silently lost).
package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/rewrite"
	"github.com/302-digital/attachra/internal/core/storage"
)

// AttachmentProcessorParams bundles the dependencies AttachmentProcessor
// needs, all sourced from cmd/attachra's wiring of internal/config and
// the Core services it constructs.
type AttachmentProcessorParams struct {
	// PolicyStore supplies the currently active policy
	// (US-4.2/T-4.2.1). It must not be nil; callers that want
	// passthrough (community-edition, no-policy-configured) behavior
	// should use PassthroughProcessor instead of constructing an
	// AttachmentProcessor at all — see cmd/attachra.
	PolicyStore *policy.Store

	// Storage stores the payload of every ActionReplace attachment.
	Storage storage.Driver

	// LinkEngine mints and persists the personal download tokens for
	// every ActionReplace attachment (US-6.1).
	LinkEngine *link.Engine

	// Templates renders the replacement block inserted into a
	// rewritten message (T-3.2.2).
	Templates *rewrite.Templates

	// Limits bounds message.Parse's MIME walk (SR-117-1/2).
	Limits message.Limits

	// MaxAttachmentSize is the maximum number of bytes any single
	// attachment may occupy once decoded, enforced while buffering an
	// attachment for storage upload. It is expected to be
	// config.LimitsConfig.MaxAttachmentSize; a zero value disables
	// this specific check (message.Limits.MaxPartSize, applied by
	// message.Parse itself, still bounds part size regardless).
	MaxAttachmentSize int64

	// InlineMaxSize is the maximum size, in bytes, of a
	// presentation-inline asset (ADR-016) eligible for the protective
	// downgrade applied by protectInlineAssets: an InlineAsset part
	// decided ActionReplace is downgraded to ActionPass (unless the
	// winning rule opted in via when.attachment.disposition) only when
	// it is image/* by detected type AND its size is within this
	// bound. It is expected to be config.LimitsConfig.InlineMaxSize; a
	// zero/negative value falls back to defaultInlineMaxSize, matching
	// message.Limits's own zero-fallback convention (Limits.normalized).
	InlineMaxSize int64

	// PublicBaseURL is the externally reachable base URL of the
	// download adapter (internal/adapters/http), used to build the
	// package-page link embedded in a rewritten message
	// (docs/architecture/package-page-decision.md §4.1 item 1), e.g.
	// "https://links.example.com".
	PublicBaseURL string

	// DryRun mirrors config.PolicyConfig.DryRun (US-4.2/T-4.2.2): when
	// true, the policy engine logs what it would have done but always
	// delivers the message unmodified (policy.ApplyModeToMessage).
	DryRun bool

	// Logger receives structured logs for policy dry-run decisions and
	// processing diagnostics. May be nil.
	Logger *slog.Logger

	// AuditSink receives audit events for policy decisions, storage
	// uploads, link creation and terminal message outcomes (US-7.1,
	// ATR-190). A nil AuditSink is replaced with audit.NopSink{} — see
	// the Process doc comment's "audit does not affect delivery"
	// section for why a failure to record an audit event never itself
	// changes the Verdict or aborts an in-flight message.
	AuditSink audit.AuditSink

	// Metrics receives Prometheus observations for messages processed,
	// attachment/policy decisions and processing duration (US-7.2/
	// T-7.2.1, ATR-192). A nil Metrics is valid: every metrics.Metrics
	// method is nil-safe, matching Logger/AuditSink's optional-by-design
	// posture, so recording metrics never affects delivery (CLAUDE.md
	// invariant #3).
	Metrics *metrics.Metrics
}

// AttachmentProcessor is the real pipeline.Processor implementation
// (ATR-167): it parses a message, evaluates the active policy against
// its attachments, uploads any ActionReplace attachment to storage,
// mints personal download links, rewrites the message body to embed
// the resulting package-page link, and returns the corresponding
// Verdict.
//
// AttachmentProcessor is safe for concurrent use: it holds no
// per-message state itself (all per-message state lives in local
// variables of Process), matching Processor's documented concurrency
// contract.
type AttachmentProcessor struct {
	params AttachmentProcessorParams
}

var _ Processor = (*AttachmentProcessor)(nil)

// NewAttachmentProcessor constructs an AttachmentProcessor from p. It
// returns an error if a required dependency is missing.
func NewAttachmentProcessor(p AttachmentProcessorParams) (*AttachmentProcessor, error) {
	if p.PolicyStore == nil {
		return nil, fmt.Errorf("pipeline: new attachment processor: PolicyStore must not be nil")
	}
	if p.Storage == nil {
		return nil, fmt.Errorf("pipeline: new attachment processor: Storage must not be nil")
	}
	if p.LinkEngine == nil {
		return nil, fmt.Errorf("pipeline: new attachment processor: LinkEngine must not be nil")
	}
	if p.Templates == nil {
		return nil, fmt.Errorf("pipeline: new attachment processor: Templates must not be nil")
	}
	return &AttachmentProcessor{params: p}, nil
}

func (p *AttachmentProcessor) logger() *slog.Logger {
	if p.params.Logger != nil {
		return p.params.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (p *AttachmentProcessor) auditSink() audit.AuditSink {
	if p.params.AuditSink != nil {
		return p.params.AuditSink
	}
	return audit.NopSink{}
}

// metrics returns the configured Metrics instrumentation, which may be
// nil: every metrics.Metrics method is nil-safe, so call sites need no
// separate nil check (mirrors auditSink's own nil-defaulting pattern,
// though here the zero value itself — a nil pointer — is already
// safe to call methods on).
func (p *AttachmentProcessor) metrics() *metrics.Metrics {
	return p.params.Metrics
}

// defaultInlineMaxSize is the fallback used when
// AttachmentProcessorParams.InlineMaxSize is zero/negative (not
// configured), matching config.LimitsConfig's own default and
// message.Limits.normalized's zero-fallback convention.
const defaultInlineMaxSize = 256 * 1024

// inlineMaxSize returns the configured InlineMaxSize, or
// defaultInlineMaxSize if it was left unset.
func (p *AttachmentProcessor) inlineMaxSize() int64 {
	if p.params.InlineMaxSize > 0 {
		return p.params.InlineMaxSize
	}
	return defaultInlineMaxSize
}

// pipelineActor identifies the milter/mail-processing path as the
// Actor for every audit event Process records, distinguishing it from
// API-originated events (e.g. an operator revoking a link) that other
// packages record with their own actor identity.
const pipelineActor = "milter"

// recordAudit appends ev via the configured AuditSink, logging (never
// returning) any failure. Audit recording is deliberately
// best-effort and out of Process's own success/failure path: a message
// must never be lost, rejected, or delayed because the audit log
// could not be written (CLAUDE.md invariant #3) — the audit trail is a
// secondary, observability concern layered onto an already-decided
// mail-delivery outcome, not a precondition for it. Every call site
// below therefore ignores this method's (absent) return value.
func (p *AttachmentProcessor) recordAudit(ctx context.Context, ev audit.Event) {
	ev.Actor = pipelineActor
	if _, err := p.auditSink().Record(ctx, ev); err != nil {
		p.logger().Warn("pipeline: failed to record audit event", "type", string(ev.Type), "error", err.Error())
	}
}

// Process implements Processor. See the package doc comment and the
// step-by-step comments below for the full sequencing.
//
// Error handling (CLAUDE.md invariant #3): every error returned by
// Process — from message parsing, storage, the metadata store, or
// rewrite — is returned as a plain error, never as a Verdict and never
// via panic. The milter adapter (internal/adapters/milter's backend)
// resolves any non-nil error into the configured fail-open (accept
// the original message unmodified) or fail-closed (temp-fail)
// behavior. Process never partially applies a rewrite: the message
// body is only replaced once every replace-attachment has been
// durably uploaded and every link created, so a recipient can never
// receive a message with a dead or missing package link because of a
// partial upload failure part-way through — such a failure surfaces
// as an error and the whole message is handled by the configured
// failure policy instead.
//
// Storage-vs-metadata rollback asymmetry: if link.Engine.CreateLinks
// succeeds but a later step (packageURLFor, rewrite.Rewrite) fails,
// the storage objects already uploaded for this message are rolled
// back (deleted, see the defer around uploadReplaced below), but the
// message/attachment/link rows CreateLinks already wrote to the
// metadata store are not — store.MetadataStore exposes no delete
// operation for them (only RevokeLink/RevokeLinksByMessage, which mark
// a row revoked rather than remove it). Such a failure therefore
// leaves behind active-status rows that reference storage keys which
// no longer exist. This is safe with respect to CLAUDE.md invariant #3
// and the recipient-facing contract: no token for those rows was ever
// generated into a delivered message (Process returns an error before
// any Verdict reaches the adapter, so fail-open delivers the original,
// untouched message and fail-closed temp-fails it), so nothing
// resolvable was ever exposed. It is, however, discoverable metadata
// debris an operator/future cleanup job should be aware of; a
// metadata-side rollback is not implemented here because
// store.MetadataStore has no delete-by-id operations to perform it
// with (a gap to close alongside a broader retention/cleanup story,
// not something to grow ad hoc in this Processor).
//
// Audit coverage (US-7.1, ATR-190): Process records a TypeError event
// for every early error return, a TypePolicyDecision event once the
// policy engine has decided, a TypeAttachmentStored event per
// successfully uploaded attachment, a TypeLinksCreated event once
// links are minted, and a single TypeMessageProcessed event on every
// exit path (accept/reject/rewrite/error) via the deferred recorder
// below. Recording is always best-effort: see recordAudit's doc
// comment for why an audit-sink failure never changes Process's
// returned Verdict/error.
func (p *AttachmentProcessor) Process(ctx context.Context, env *Envelope) (verdict *Verdict, procErr error) {
	// finalOutcome records exactly one TypeMessageProcessed event
	// covering however Process actually returns, regardless of which
	// of the many return statements below is taken. Placed first so it
	// observes every return path, including the ones before a
	// messageID even exists.
	var messageID string
	start := time.Now()
	defer func() {
		dur := time.Since(start)
		details := map[string]any{"queue_id": env.QueueID, "sender": env.Sender}
		if procErr != nil {
			details["error"] = procErr.Error()
			p.recordAudit(ctx, audit.Event{Type: audit.TypeError, MessageID: messageID, Details: details})
			p.metrics().ObserveError("pipeline")
			p.metrics().ObserveMessage("error", dur)
			return
		}
		result := VerdictAccept.String()
		if verdict != nil {
			result = verdict.Action.String()
			details["action"] = result
			if verdict.Reason != "" {
				details["reason"] = verdict.Reason
			}
		}
		p.metrics().ObserveMessage(result, dur)
		p.recordAudit(ctx, audit.Event{Type: audit.TypeMessageProcessed, MessageID: messageID, Details: details})
	}()

	if env.Body == nil {
		return &Verdict{Action: VerdictAccept}, nil
	}

	// Capture the full message once so it can be read independently by
	// message.Parse (step a) and, later, rewrite.Rewrite (step f):
	// Envelope.Body is documented as a single-read stream, but this
	// pipeline needs to walk it twice.
	body, err := spoolReader(env.Body)
	if err != nil {
		return nil, fmt.Errorf("pipeline: spool message body: %w", err)
	}
	defer func() {
		if cerr := body.Close(); cerr != nil {
			p.logger().Warn("pipeline: failed to clean up message body spool", "queue_id", env.QueueID, "error", cerr)
		}
	}()

	parseReader, err := body.Reader()
	if err != nil {
		return nil, fmt.Errorf("pipeline: open message body for parsing: %w", err)
	}

	// Step a: parse the message, discovering every leaf MIME part
	// (attachment) and buffering each one's decoded content into its
	// own bounded spool so it can be uploaded later without a second
	// read of the original message (which, for a base64-encoded part,
	// would require redoing the decode).
	atts, bodies, err := p.parseMessage(parseReader)
	if err != nil {
		return nil, fmt.Errorf("pipeline: parse message: %w", err)
	}
	defer closeAttachmentBodies(bodies, p.logger())

	// Step b: no policy configured. cmd/attachra only constructs an
	// AttachmentProcessor when a policy is loaded (see
	// AttachmentProcessorParams.PolicyStore's doc comment), but this
	// guard keeps Process itself total/safe if ever called without
	// one, matching PassthroughProcessor's behavior.
	if p.params.PolicyStore == nil {
		return &Verdict{Action: VerdictAccept, Attachments: AttachmentSummary{Total: len(atts)}}, nil
	}

	// Step c: evaluate the active policy against every discovered
	// attachment, then reconcile the result with dry-run mode
	// (US-4.2/T-4.2.2) in exactly the one place this is meant to
	// happen (policy.ApplyModeToMessage's own doc comment).
	activePolicy := p.params.PolicyStore.Current()
	meta := policy.EnvelopeMeta{Sender: env.Sender, Recipients: env.Recipients}
	decision := policy.Evaluate(activePolicy, meta, atts)

	// Step c.1 (ADR-016, refined by the security review of ATR-305/306):
	// protect presentation-inline assets AND structural body parts from
	// a blanket replace decision before dry-run reconciliation, so a
	// dry-run log for a protected part correctly reads "would-pass"
	// rather than a misleading "would-replace" a real run would never
	// have performed anyway. Both protections downgrade replace->pass
	// only; a block decision on either kind of part (e.g. a rule
	// matching a structural body's DETECTED type) is left untouched —
	// see protectInlineAssets/protectStructuralBodies doc comments for
	// why these must never silently skip evaluation (that would itself
	// be an enforcement bypass, not a protection).
	decision, inlineProtectedPaths := protectInlineAssets(atts, decision, p.inlineMaxSize())
	decision, bodyProtectedPaths := protectStructuralBodies(atts, decision)
	for range inlineProtectedPaths {
		p.metrics().ObserveAttachmentAction("inline_protected")
	}
	for range bodyProtectedPaths {
		p.metrics().ObserveAttachmentAction("body_protected")
	}

	names := attachmentNames(atts)
	decision = policy.ApplyModeToMessage(decision, p.params.DryRun, names, p.logger())

	policyDecisionDetails := map[string]any{
		"queue_id":    env.QueueID,
		"policy_name": activePolicy.Name,
		"action":      string(decision.Action),
		"dry_run":     p.params.DryRun,
		"attachments": len(atts),
		"reason":      decision.Reason,
	}
	if len(inlineProtectedPaths) > 0 {
		policyDecisionDetails["inline_protected"] = inlineProtectedPaths
	}
	if len(bodyProtectedPaths) > 0 {
		policyDecisionDetails["body_protected"] = bodyProtectedPaths
	}
	p.recordAudit(ctx, audit.Event{
		Type:    audit.TypePolicyDecision,
		Details: policyDecisionDetails,
	})
	p.metrics().ObservePolicyDecision(string(decision.Action), p.params.DryRun)
	for _, d := range decision.Attachments {
		p.metrics().ObserveAttachmentAction(string(d.Action))
	}

	attachmentSummary := AttachmentSummary{
		Total:           len(atts),
		InlineProtected: len(inlineProtectedPaths),
		BodyProtected:   len(bodyProtectedPaths),
	}

	if decision.Action == policy.ActionBlock {
		return &Verdict{Action: VerdictReject, Reason: decision.Reason, Attachments: attachmentSummary}, nil
	}

	// Step d: nothing to replace (every attachment decided pass, or
	// dry-run suppressed every replace/block down to pass) — accept
	// the message completely untouched, avoiding any unnecessary
	// storage/link/rewrite work.
	if !hasReplace(decision) {
		return &Verdict{Action: VerdictAccept, Attachments: attachmentSummary}, nil
	}

	if len(env.Recipients) == 0 {
		return nil, fmt.Errorf("pipeline: message decided replace but has no envelope recipients to create links for")
	}

	// messageID is generated here, before upload, purely so every audit
	// event from this point on (including per-attachment
	// TypeAttachmentStored below) can already carry it; it is the same
	// ID later passed to LinkEngine.CreateLinks as link.MessageInput.ID.
	messageID, err = newRandomID()
	if err != nil {
		return nil, fmt.Errorf("pipeline: generate message id: %w", err)
	}

	// Step e: upload every replace-decided attachment to storage and
	// mint personal download links for it. uploaded accumulates
	// whatever succeeded even if uploadReplaced itself returns early
	// on a later attachment's failure, so the rollback deferred right
	// below covers a partial upload failure too, not just failures in
	// the steps after uploadReplaced returns. This rollback only
	// covers storage objects, not metadata rows written later by
	// CreateLinks — see the storage-vs-metadata rollback asymmetry
	// note on Process's own doc comment above.
	uploaded, err := p.uploadReplaced(ctx, atts, bodies, decision)
	uploadedOK := false
	defer func() {
		if uploadedOK {
			return
		}
		for _, u := range uploaded {
			if derr := p.params.Storage.Delete(context.Background(), u.storageKey); derr != nil {
				p.logger().Warn("pipeline: failed to roll back uploaded attachment after later failure",
					"queue_id", env.QueueID, "storage_key", u.storageKey, "error", derr)
			}
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("pipeline: upload replaced attachments: %w", err)
	}

	for _, u := range uploaded {
		p.recordAudit(ctx, audit.Event{
			Type:      audit.TypeAttachmentStored,
			MessageID: messageID,
			Details: map[string]any{
				"queue_id":    env.QueueID,
				"filename":    u.att.Filename,
				"size":        u.att.Size,
				"storage_key": u.storageKey,
			},
		})
	}

	created, err := p.params.LinkEngine.CreateLinks(ctx, link.CreateLinksParams{
		Message: link.MessageInput{
			ID:      messageID,
			QueueID: env.QueueID,
			Sender:  env.Sender,
			Status:  decision.Action,
		},
		Attachments: uploadedAttachmentInputs(uploaded),
		Recipients:  env.Recipients,
		Params:      worstCaseReplaceParams(decision),
	})
	if err != nil {
		return nil, fmt.Errorf("pipeline: create links: %w", err)
	}

	for _, recipient := range env.Recipients {
		p.recordAudit(ctx, audit.Event{
			Type:      audit.TypeLinksCreated,
			MessageID: messageID,
			Recipient: recipient,
			Details:   map[string]any{"queue_id": env.QueueID, "attachments": len(uploaded)},
		})
	}

	packageURL, expiresAt, err := packageURLFor(created, env.Recipients[0], p.params.PublicBaseURL)
	if err != nil {
		return nil, fmt.Errorf("pipeline: resolve package url: %w", err)
	}

	// Step f: rewrite the original message, removing replace-decided
	// attachments and inserting the replacement block that links to
	// the package page.
	rewriteReader, err := body.Reader()
	if err != nil {
		return nil, fmt.Errorf("pipeline: open message body for rewrite: %w", err)
	}

	// Structural body parts are excluded from what rewrite.Rewrite sees
	// (rewriteAtts/rewriteDecision), even though they were full
	// participants in policy.Evaluate/protectStructuralBodies above.
	// See rewriteInput's doc comment for why: internal/core/rewrite's
	// "append the replacement block to the primary body" logic keys off
	// a part having NO decision of its own, a contract predating this
	// change that is safer to preserve here than to alter in that
	// separately-reviewed critical zone.
	rewriteAtts, rewriteDecision := rewriteInput(atts, decision)

	result, err := rewrite.Rewrite(rewrite.Input{
		Message:     rewriteReader,
		Attachments: rewriteAtts,
		Decision:    rewriteDecision,
		PackageURL:  packageURL,
		ExpiresAt:   expiresAt,
		SenderName:  env.Sender,
	}, p.params.Templates)
	if err != nil {
		return nil, fmt.Errorf("pipeline: rewrite message: %w", err)
	}

	uploadedOK = true

	attachmentSummary.Replaced = len(uploaded)

	// Step g: everything succeeded — the rewritten body is durable and
	// safe to hand to the adapter.
	return &Verdict{Action: VerdictRewrite, NewBody: result.Body, Attachments: attachmentSummary}, nil
}

// uploadedAttachment pairs a message.Attachment (and its
// freshly-generated store row id) with the storage key its content
// was written to, for building both the Link Engine's
// AttachmentInput and the rollback path if a later step fails.
type uploadedAttachment struct {
	att        message.Attachment
	id         string
	storageKey string
}

// isStructuralBodyPart reports whether att is a structural body part
// of the message — its primary text/plain or text/html content —
// rather than a genuine attachment or a presentation-inline asset
// (ATR-306). message.Parse classifies such a part DispositionInline
// by default precisely because it carries no filename and no explicit
// Content-Disposition header (message.classifyDisposition); a part
// that does have an explicit "inline" disposition AND a filename
// (e.g. some MUAs' inline text attachments) is deliberately NOT
// matched here, so it is still handled like any other attachment
// (never protected).
//
// isStructuralBodyPart identifies parts that are never REPLACE
// CANDIDATES, not parts exempt from evaluation (a security review of
// ATR-305/306 flagged an earlier version of this fix that skipped
// evaluation entirely for these parts — see parseMessage/
// protectStructuralBodies doc comments for why that was itself an
// enforcement bypass: a part declaring `Content-Type: text/plain` but
// containing e.g. real ZIP bytes must still be sniffed and matched
// against operator rules, including `block`). ADR-016's Consequences
// section documents this in "never replace candidates" terms.
func isStructuralBodyPart(att message.Attachment) bool {
	return att.Disposition == message.DispositionInline &&
		att.Filename == "" &&
		(att.DeclaredType == "text/plain" || att.DeclaredType == "text/html")
}

// parseMessage walks r via message.Parse, returning the flat list of
// discovered attachments (in document order, matching PartPath values
// message.Parse assigns) alongside a same-indexed slice of *spool
// captures of each attachment's decoded content — buffered once here
// so a later storage upload does not need to re-parse/re-decode the
// original message.
//
// Every leaf part, including structural body parts
// (isStructuralBodyPart), is spooled, sniffed (DetectedType) and
// included in the returned slices: they must go through
// policy.Evaluate like any other part so an operator's `block` rule
// (matched on the part's real, detected type) still fires even when
// the part is disguised as the message body (e.g. ZIP bytes declared
// `Content-Type: text/plain`). protectStructuralBodies is the layer
// that keeps a structural body part from actually being removed on a
// `replace` verdict; skipping evaluation here instead would silently
// defeat detected-type/block enforcement for anything shaped like a
// message body — exactly the bypass a security review of ATR-305/306
// flagged in an earlier version of this function.
//
// Buffering is bounded per attachment (message.Limits.MaxPartSize,
// already enforced by message.Parse itself, and, in addition,
// AttachmentProcessorParams.MaxAttachmentSize if configured), so this
// does not violate CLAUDE.md invariant #4: each attachment's content
// is captured through the same bounded spool used for the whole
// message body, never an unbounded single allocation.
func (p *AttachmentProcessor) parseMessage(r io.Reader) ([]message.Attachment, []*spool, error) {
	var (
		atts   []message.Attachment
		bodies []*spool
	)

	err := message.Parse(r, p.params.Limits, func(att *message.Attachment, partBody io.Reader) error {
		limited := partBody
		if p.params.MaxAttachmentSize > 0 {
			limited = &limitedReader{r: partBody, remaining: p.params.MaxAttachmentSize}
		}

		s, err := spoolReader(limited)
		if err != nil {
			return fmt.Errorf("buffer attachment part %q: %w", att.PartPath, err)
		}

		sniffPrefix, err := readSniffPrefix(s)
		if err != nil {
			_ = s.Close()
			return fmt.Errorf("sniff attachment part %q: %w", att.PartPath, err)
		}
		att.DetectedType = message.DetectType(sniffPrefix)
		att.Size = s.Len()

		atts = append(atts, *att)
		bodies = append(bodies, s)
		return nil
	})
	if err != nil {
		closeSpools(bodies)
		return nil, nil, err
	}

	return atts, bodies, nil
}

// rewriteInput builds the subset of atts/decision.Attachments that
// rewrite.Rewrite should see: structural body parts (isStructuralBodyPart)
// are excluded entirely. By the time Process reaches this call, a
// structural body part's decision can only be ActionPass (a Block
// decision on any part aggregates to a message-level Block, which
// Process already rejected before ever calling rewrite.Rewrite; a
// Replace decision was downgraded by protectStructuralBodies above) —
// so omitting it from rewrite.Input.Attachments/Decision is exactly
// equivalent to it carrying an ActionPass entry, but keeps
// internal/core/rewrite/walk.go's rewriteLeaf "no policy decision of
// its own" gate for its append-the-replacement-block-into-the-primary-body
// logic (wantsPlain/wantsHTML) working unmodified. Changing that gate
// instead (to treat "decided pass" the same as "no decision") would
// risk mis-triggering on a genuine, non-structural text/plain or
// text/html ATTACHMENT that a rule separately decided pass for — a
// real "notes.txt" should stay a byte-for-byte pass-through, never
// have the replacement block appended into it. Keeping this filter in
// pipeline (rather than editing internal/core/rewrite, a separately
// reviewed critical zone) avoids that risk entirely.
func rewriteInput(atts []message.Attachment, decision policy.MessageDecision) ([]message.Attachment, policy.MessageDecision) {
	filteredAtts := make([]message.Attachment, 0, len(atts))
	filteredDecisions := make([]policy.AttachmentDecision, 0, len(decision.Attachments))

	for i, att := range atts {
		if isStructuralBodyPart(att) {
			continue
		}
		filteredAtts = append(filteredAtts, att)
		filteredDecisions = append(filteredDecisions, decision.Attachments[i])
	}

	return filteredAtts, policy.MessageDecision{
		Action:      decision.Action,
		Attachments: filteredDecisions,
		Reason:      decision.Reason,
	}
}

// sniffLen mirrors internal/core/message's own unexported sniffLen
// constant (the WHATWG MIME Sniffing window DetectType considers);
// duplicated here since message does not export it, but the value
// itself is a documented, stable contract of DetectType's doc comment
// ("callers should pass at least sniffLen bytes when available").
const sniffLen = 512

// readSniffPrefix returns up to sniffLen bytes from the start of s's
// captured content, for message.DetectType, without consuming s's
// reusable Reader for later callers (a fresh io.Reader is opened and
// discarded here).
func readSniffPrefix(s *spool) ([]byte, error) {
	r, err := s.Reader()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, sniffLen)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

// closeSpools closes every spool in bodies, ignoring errors: it is
// used on parseMessage's error path where the caller is already
// returning a different error and best-effort cleanup is all that
// matters.
func closeSpools(bodies []*spool) {
	for _, s := range bodies {
		_ = s.Close()
	}
}

// closeAttachmentBodies closes every spool in bodies, logging (rather
// than ignoring) any failure, for use on Process's success path via
// defer.
func closeAttachmentBodies(bodies []*spool, logger *slog.Logger) {
	for _, s := range bodies {
		if err := s.Close(); err != nil {
			logger.Warn("pipeline: failed to clean up attachment body spool", "error", err)
		}
	}
}

// inlineImageTypePrefix is the detected-type prefix protectInlineAssets
// requires for the protective downgrade (ADR-016 decision 2): "image/*"
// by real, magic-byte-detected type (message.Attachment.DetectedType),
// never the declared/claimed type, since the whole point of the
// protection is to survive an attachment whose real bytes might be
// disguised as something else — matchDisposition-style glob matching
// is unnecessary here since this is a single fixed prefix, not an
// operator-authored pattern.
const inlineImageTypePrefix = "image/"

// protectInlineAssets applies ADR-016 decision 2, the pipeline's
// protective downgrade: an attachment classified InlineAsset
// (message.Attachment.InlineAsset — a `cid:`-referenced asset inside
// multipart/related) whose resolved decision is ActionReplace is
// downgraded to ActionPass, UNLESS the winning rule explicitly opted
// the disposition in (policy.AttachmentDecision.InlineOptIn). The
// downgrade only fires when the part's DETECTED type (magic bytes) is
// image/* AND its size is within inlineMaxSize — a small, verified
// image is exactly the shape of a logo/signature asset the protection
// is meant to preserve, while anything else (including a file merely
// masquerading as an image by extension/declared type) still replaces
// normally. ActionBlock is never downgraded: blocking is a stronger,
// deliberate policy outcome ADR-016 does not soften.
//
// atts and m.Attachments must be the same length and index-aligned
// (policy.Evaluate's own documented contract, which parseMessage/
// Process already preserve). protectInlineAssets returns the
// (possibly modified) decision, with the message-level Action
// re-aggregated to reflect any downgrades, and the PartPath of every
// downgraded attachment (nil if none), for the caller's audit/metrics
// reporting.
func protectInlineAssets(atts []message.Attachment, m policy.MessageDecision, inlineMaxSize int64) (policy.MessageDecision, []string) {
	var protectedPaths []string

	out := policy.MessageDecision{Attachments: make([]policy.AttachmentDecision, len(m.Attachments))}
	copy(out.Attachments, m.Attachments)

	for i, d := range out.Attachments {
		if d.Action != policy.ActionReplace || d.InlineOptIn {
			continue
		}
		att := atts[i]
		if !att.InlineAsset {
			continue
		}
		if !strings.HasPrefix(att.DetectedType, inlineImageTypePrefix) {
			continue
		}
		if att.Size > inlineMaxSize {
			continue
		}

		out.Attachments[i].Action = policy.ActionPass
		protectedPaths = append(protectedPaths, att.PartPath)
	}

	out.Action, out.Reason = aggregateMessageAction(out.Attachments)
	return out, protectedPaths
}

// protectStructuralBodies applies the ATR-306 fix's protective layer:
// a structural body part (isStructuralBodyPart — the message's own
// text/plain or text/html content) whose resolved decision is
// ActionReplace is downgraded to ActionPass unconditionally (no
// InlineOptIn-style opt-out — the message body must never actually be
// removed, that is what "structural" means here). ActionBlock is
// never downgraded: an operator rule matching the part's real,
// sniffed content (e.g. `mime_type: ["application/zip"]` against a
// part masquerading as `Content-Type: text/plain`) still rejects the
// whole message, exactly as it would for any other attachment — see
// parseMessage's doc comment for why these parts are fully evaluated
// rather than excluded before this step.
//
// atts and m.Attachments must be the same length and index-aligned,
// matching protectInlineAssets' contract. Returns the (possibly
// modified) decision, re-aggregated, and the PartPath of every
// downgraded attachment (nil if none) for the caller's audit/metrics
// reporting (the "body_protected" detail/label, mirroring
// protectInlineAssets' "inline_protected").
func protectStructuralBodies(atts []message.Attachment, m policy.MessageDecision) (policy.MessageDecision, []string) {
	var protectedPaths []string

	out := policy.MessageDecision{Attachments: make([]policy.AttachmentDecision, len(m.Attachments))}
	copy(out.Attachments, m.Attachments)

	for i, d := range out.Attachments {
		if d.Action != policy.ActionReplace {
			continue
		}
		if !isStructuralBodyPart(atts[i]) {
			continue
		}

		out.Attachments[i].Action = policy.ActionPass
		protectedPaths = append(protectedPaths, atts[i].PartPath)
	}

	out.Action, out.Reason = aggregateMessageAction(out.Attachments)
	return out, protectedPaths
}

// aggregateMessageAction re-derives the message-level Action/Reason
// from per-attachment decisions, mirroring policy.Evaluate's own
// worst-case aggregation rule (§3.1: the strongest action across
// attachments wins). It is duplicated (in miniature) here rather than
// calling into policy directly because the ranking helper
// (actionStrength) policy.Evaluate itself uses is unexported; the
// three-value ranking (pass < replace < block) is stable and simple
// enough that this small duplication is preferable to exporting an
// internal ranking function purely for this one call site.
func aggregateMessageAction(decisions []policy.AttachmentDecision) (policy.Action, string) {
	action := policy.ActionPass
	reason := ""
	rank := map[policy.Action]int{policy.ActionPass: 1, policy.ActionReplace: 2, policy.ActionBlock: 3}

	for _, d := range decisions {
		if rank[d.Action] > rank[action] {
			action = d.Action
			reason = d.Reason
		}
	}
	return action, reason
}

// hasReplace reports whether m has at least one ActionReplace
// attachment decision.
func hasReplace(m policy.MessageDecision) bool {
	for _, d := range m.Attachments {
		if d.Action == policy.ActionReplace {
			return true
		}
	}
	return false
}

// attachmentNames extracts each attachment's display file name, in
// the same order as atts, for policy.ApplyModeToMessage's dry-run log
// records.
func attachmentNames(atts []message.Attachment) []string {
	names := make([]string, len(atts))
	for i, a := range atts {
		names[i] = a.Filename
	}
	return names
}

// uploadReplaced uploads every attachment decided ActionReplace to
// storage under a freshly generated object key, returning one
// uploadedAttachment per upload in the same relative order as they
// appear in atts/decision.
//
// If any upload fails partway through, uploadReplaced itself does not
// attempt a rollback (the caller, Process, owns that via its own
// deferred cleanup keyed on the uploaded slice this function already
// returned for everything that did succeed) — this keeps the
// upload-then-rollback responsibility in exactly one place.
func (p *AttachmentProcessor) uploadReplaced(ctx context.Context, atts []message.Attachment, bodies []*spool, decision policy.MessageDecision) ([]uploadedAttachment, error) {
	var uploaded []uploadedAttachment

	for i, d := range decision.Attachments {
		if d.Action != policy.ActionReplace {
			continue
		}

		key, err := storage.NewObjectKey()
		if err != nil {
			return uploaded, fmt.Errorf("generate object key for attachment %q: %w", atts[i].PartPath, err)
		}

		r, err := bodies[i].Reader()
		if err != nil {
			return uploaded, fmt.Errorf("read buffered attachment %q: %w", atts[i].PartPath, err)
		}

		if err := p.params.Storage.Put(ctx, key, r, atts[i].Size); err != nil {
			return uploaded, fmt.Errorf("upload attachment %q: %w", atts[i].PartPath, err)
		}

		id, err := newRandomID()
		if err != nil {
			return uploaded, fmt.Errorf("generate attachment id for %q: %w", atts[i].PartPath, err)
		}

		uploaded = append(uploaded, uploadedAttachment{att: atts[i], id: id, storageKey: key})
	}

	return uploaded, nil
}

// uploadedAttachmentInputs converts uploaded to the link.AttachmentInput
// slice link.Engine.CreateLinks expects, preserving order.
func uploadedAttachmentInputs(uploaded []uploadedAttachment) []link.AttachmentInput {
	out := make([]link.AttachmentInput, len(uploaded))
	for i, u := range uploaded {
		out[i] = link.AttachmentInput{
			ID:           u.id,
			PartRef:      u.att.PartPath,
			Filename:     u.att.Filename,
			DeclaredType: u.att.DeclaredType,
			DetectedType: u.att.DetectedType,
			Size:         u.att.Size,
			StorageKey:   u.storageKey,
		}
	}
	return out
}

// worstCaseReplaceParams collects the ActionParams from every
// ActionReplace attachment decision in m and merges them to the most
// restrictive value per field (mirroring policy's own worst-case
// merge across recipients, §4/§8.2 item 3), since
// link.CreateLinksParams.Params applies a single set of parameters to
// every link created for the message
// (docs/architecture/package-page-decision.md §7 item 3).
func worstCaseReplaceParams(m policy.MessageDecision) policy.ActionParams {
	var (
		out   policy.ActionParams
		first = true
	)
	for _, d := range m.Attachments {
		if d.Action != policy.ActionReplace {
			continue
		}
		if first {
			out = d.Params
			first = false
			continue
		}
		out = policy.MostRestrictiveParams(out, d.Params)
	}
	return out
}

// packageURLFor locates the package-page CreatedLink for recipient
// among created (link.Engine.CreateLinks marks it with an empty
// AttachmentID, see CreatedLink's own doc comment) and builds the full
// URL to embed in the rewritten message body.
//
// Per docs/architecture/package-page-decision.md §4.1 item 2, the MVP
// milter path embeds a single, non-personalized package URL in the
// one body shared by every envelope recipient; recipient is expected
// to be the first envelope recipient (Process's caller), an explicit,
// documented MVP limitation rather than an oversight — see this
// package's doc comment and this task's final report for the
// rationale.
func packageURLFor(created []link.CreatedLink, recipient, baseURL string) (packageURL string, expiresAt time.Time, err error) {
	for _, c := range created {
		if c.AttachmentID == "" && c.Recipient == recipient {
			return baseURL + "/p/" + c.Token, c.ExpiresAt, nil
		}
	}
	return "", time.Time{}, fmt.Errorf("no package link found for recipient %q", recipient)
}

// limitedReader wraps r, returning an error once more than remaining
// bytes have been read, enforcing
// AttachmentProcessorParams.MaxAttachmentSize independent of
// message.Limits.MaxPartSize (which message.Parse already enforces on
// its own, tighter or looser terms depending on configuration).
type limitedReader struct {
	r         io.Reader
	remaining int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		// The budget is exhausted: read one more byte from the
		// underlying reader to distinguish "exactly at the limit,
		// nothing left to read" (io.EOF, not an error — a part whose
		// size equals the configured maximum is not oversized) from
		// "there is still more data beyond the limit" (the actual
		// over-limit condition).
		var one [1]byte
		if _, err := l.r.Read(one[:]); err == io.EOF {
			return 0, io.EOF
		}
		return 0, fmt.Errorf("pipeline: attachment exceeds configured max attachment size")
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

// newRandomID generates a new opaque, hex-encoded identifier for a
// store.Message/store.Attachment row, using the same 128-bit
// crypto/rand scheme as internal/core/link's own unexported newID
// (duplicated rather than imported since it is a private helper of
// that package). It never derives from message content (SR-121-3).
func newRandomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
