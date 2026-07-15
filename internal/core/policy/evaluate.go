package policy

import (
	"github.com/302-digital/attachra/internal/core/message"
)

// AttachmentDecision is the policy verdict computed for a single
// attachment (§3.1: policy is evaluated independently per
// attachment), already aggregated across every envelope recipient
// per the worst-case rule in §3.4.
type AttachmentDecision struct {
	// Action is the worst-case (strongest) action across all
	// recipients for this attachment.
	Action Action

	// RuleName is the name of the rule that produced Action for the
	// recipient that drove the worst-case result, or "" if Action
	// came from the policy's Default branch.
	RuleName string

	// Params carries the ActionReplace-only parameters (ttl,
	// max_downloads, retention) associated with Action. When several
	// recipients independently produced a `replace` verdict with
	// differing parameters, Params holds the most restrictive value
	// per field (smallest ttl, smallest max_downloads, smallest
	// retention) — §4/§8.2 item 3. Zero value (all nil) when Action
	// is not ActionReplace.
	Params ActionParams

	// Reason is the human-readable rejection reason (§2.4
	// `then.reason`), populated only when Action is ActionBlock.
	Reason string

	// DryRun is the winning rule's (or Default's) §2.4 `then.dry_run`
	// override, or nil if it left the field unset (defer to the
	// global policy.dry_run config setting). See ApplyMode (mode.go)
	// for how this is reconciled with the global setting.
	DryRun *bool

	// InlineOptIn is true when the winning rule explicitly constrained
	// `when.attachment.disposition` (ADR-016): the policy author
	// deliberately wrote a rule that only matches inline or only
	// matches attachment parts, rather than relying on the field's
	// default "matches everything" behavior. pipeline's protective
	// inline-asset downgrade (ADR-016 decision 2) only applies to
	// InlineAsset parts whose InlineOptIn is false — an explicit
	// disposition constraint is treated as the policy author's
	// deliberate choice to replace inline assets too, overriding the
	// engine's protective default. Always false for a decision that
	// came from Policy.Default, since ActionSpec/Policy.Default has no
	// `when` block to constrain disposition with.
	InlineOptIn bool
}

// MessageDecision is the policy verdict for a whole message, obtained
// by aggregating every attachment's AttachmentDecision (§3.1).
type MessageDecision struct {
	// Action is the strongest action across all attachments in the
	// message: if any attachment decision is ActionBlock, the whole
	// message is blocked (§3.1); otherwise the message is delivered
	// and each attachment is handled per its own decision
	// (Attachments).
	Action Action

	// Attachments holds each attachment's individual decision, in the
	// same order as the attachments slice passed to Evaluate. Callers
	// consult this even when Action is ActionBlock, e.g. to find
	// which attachment(s) caused the block and their Reason/RuleName
	// for the audit log.
	Attachments []AttachmentDecision

	// Reason is the Reason of the first attachment decision that
	// caused Action to become ActionBlock. Empty when Action is not
	// ActionBlock, or the winning rule/default set no reason.
	Reason string
}

// Evaluate computes the policy decision for every attachment in atts
// against p, given the envelope's sender and recipients, and
// aggregates the per-attachment decisions into a MessageDecision
// following the model in §4 of the policy format spec:
//
//  1. Per attachment, per recipient: walk p.Rules top to bottom
//     (skipping Disabled rules) and take the first rule whose When
//     matches (attachment, sender, that recipient); fall back to
//     p.Default if none match (§3.2).
//  2. Aggregate across recipients into one action per attachment,
//     keeping the strongest (worst-case, §3.4).
//  3. Aggregate across attachments into one message-level action,
//     again keeping the strongest (§3.1): any blocked attachment
//     blocks the whole message.
//
// p must already be validated (e.g. via Parse/Load); Evaluate does
// not re-validate it.
//
// Evaluate only computes the decision — it does not perform the MIME
// rewrite, storage upload or link generation implied by ActionReplace,
// nor does it wire into pipeline.Processor itself; see
// pipeline.AttachmentProcessor (ATR-167), which calls Evaluate and
// then carries out the upload/link/rewrite steps its result implies.
func Evaluate(p *Policy, env EnvelopeMeta, atts []message.Attachment) MessageDecision {
	decisions := make([]AttachmentDecision, len(atts))

	msgAction := ActionPass
	msgReason := ""

	for i, att := range atts {
		d := decideAttachment(p, env, att)
		decisions[i] = d

		if actionStrength(d.Action) > actionStrength(msgAction) {
			msgAction = d.Action
			msgReason = d.Reason
		}
	}

	return MessageDecision{
		Action:      msgAction,
		Attachments: decisions,
		Reason:      msgReason,
	}
}

// decideAttachment computes the worst-case AttachmentDecision for a
// single attachment across every envelope recipient (§3.4). A message
// with no recipients still evaluates once against an empty recipient
// string, so sender-only/attachment-only rules and the default branch
// still apply.
func decideAttachment(p *Policy, env EnvelopeMeta, att message.Attachment) AttachmentDecision {
	recipients := env.Recipients
	if len(recipients) == 0 {
		recipients = []string{""}
	}

	worst := decideOne(p, env.Sender, recipients[0], att)
	for _, recipient := range recipients[1:] {
		next := decideOne(p, env.Sender, recipient, att)
		worst = strongerDecision(worst, next)
	}

	return worst
}

// decideOne evaluates p's rules (first-match-wins, §3.2) for one
// (sender, recipient, attachment) triple, falling back to p.Default
// when no rule matches.
func decideOne(p *Policy, sender, recipient string, att message.Attachment) AttachmentDecision {
	for _, r := range p.Rules {
		if r.Disabled {
			continue
		}
		if matchWhen(r.When, sender, recipient, att) {
			return AttachmentDecision{
				Action:      r.Then.Action,
				RuleName:    r.Name,
				Params:      r.Then.ActionParams,
				Reason:      r.Then.Reason,
				DryRun:      r.Then.DryRun,
				InlineOptIn: r.When != nil && r.When.Attachment != nil && len(r.When.Attachment.Disposition) > 0,
			}
		}
	}

	return AttachmentDecision{
		Action: p.Default.Action,
		Params: p.Default.ActionParams,
		Reason: p.Default.Reason,
		DryRun: p.Default.DryRun,
	}
}

// strongerDecision combines two recipients' decisions for the same
// attachment into the worst-case result (§3.4): the more severe
// action wins outright. When both sides produced the same action and
// it is ActionReplace, the parameters are merged to the most
// restrictive value per field (§4/§8.2 item 3) rather than picking
// either side wholesale, and InlineOptIn is OR'd: if either
// recipient's winning rule explicitly opted an inline asset into
// replacement (ADR-016), that deliberate choice must not be lost by
// arbitrarily picking the other recipient's decision.
func strongerDecision(a, b AttachmentDecision) AttachmentDecision {
	switch {
	case actionStrength(b.Action) > actionStrength(a.Action):
		return b
	case actionStrength(a.Action) > actionStrength(b.Action):
		return a
	case a.Action == ActionReplace:
		a.Params = MostRestrictiveParams(a.Params, b.Params)
		a.InlineOptIn = a.InlineOptIn || b.InlineOptIn
		return a
	default:
		return a
	}
}

// MostRestrictiveParams combines two ActionReplace parameter sets
// into the more restrictive of the two per field independently
// (smaller ttl, smaller max_downloads, smaller retention), per the
// worst-case parameter rule in §4/§8.2 item 3. A nil field (no
// limit/unset) loses to any non-nil field from the other side, since
// an explicit bound is always at least as restrictive as "unbounded".
//
// Exported (beyond Evaluate's own internal use merging across
// recipients) so callers that must merge ActionReplace parameters
// across a different axis — e.g. pipeline.AttachmentProcessor merging
// across every replace-decided attachment in a message before calling
// link.Engine.CreateLinks, which applies a single parameter set per
// message (docs/architecture/package-page-decision.md §7 item 3) —
// reuse the exact same merge rule instead of duplicating it.
func MostRestrictiveParams(a, b ActionParams) ActionParams {
	return ActionParams{
		TTL:          mostRestrictiveDuration(a.TTL, b.TTL),
		MaxDownloads: mostRestrictiveInt(a.MaxDownloads, b.MaxDownloads),
		Retention:    mostRestrictiveDuration(a.Retention, b.Retention),
	}
}

// mostRestrictiveDuration returns whichever of a, b is the smaller
// duration (more restrictive), treating a nil bound as "unbounded"
// and therefore less restrictive than any set value.
func mostRestrictiveDuration(a, b *Duration) *Duration {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case *a <= *b:
		return a
	default:
		return b
	}
}

// mostRestrictiveInt returns whichever of a, b is the smaller value
// (more restrictive), treating a nil bound as "unbounded" and
// therefore less restrictive than any set value.
func mostRestrictiveInt(a, b *int) *int {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case *a <= *b:
		return a
	default:
		return b
	}
}
