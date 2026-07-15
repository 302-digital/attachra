package policy

import "log/slog"

// dryRunVerdict is the human-readable verdict word logged for a
// dry-run decision, chosen to read naturally next to the action it
// stands in for ("would-replace", "would-block") — see §3.5-style
// structured audit logging and T-4.2.2's acceptance criteria.
func dryRunVerdict(action Action) string {
	switch action {
	case ActionReplace:
		return "would-replace"
	case ActionBlock:
		return "would-block"
	case ActionPass:
		return "would-pass"
	default:
		return "would-" + string(action)
	}
}

// EffectiveDryRun resolves whether a given AttachmentDecision should
// run in dry-run mode, combining the global policy.dry_run config
// setting with the winning rule's (or Default's) optional per-rule
// `then.dry_run` override (§2.4/T-4.2.2): a non-nil d.DryRun always
// wins over globalDryRun, since it is a deliberate, rule-specific
// choice by the policy author; a nil d.DryRun defers to
// globalDryRun.
func EffectiveDryRun(d AttachmentDecision, globalDryRun bool) bool {
	if d.DryRun != nil {
		return *d.DryRun
	}
	return globalDryRun
}

// ApplyMode reconciles a single attachment's policy decision with
// dry-run mode (US-4.2/T-4.2.2). When dry-run is not in effect for d
// (see EffectiveDryRun), ApplyMode returns d unchanged.
//
// When dry-run is in effect, ApplyMode logs a structured record of
// what the policy *would* have done — rule name, the action that
// would have been taken, and a verdict word ("would-replace",
// "would-block", "would-pass") — and returns a copy of d with Action
// forced to ActionPass, so that whatever calls ApplyMode always ends
// up delivering the attachment/message unmodified in dry-run mode,
// regardless of which action the policy actually computed.
//
// attachmentName identifies the attachment in the log record (e.g.
// its filename); it may be empty if unknown/not yet available to the
// caller. logger may be nil, in which case ApplyMode still adjusts
// the returned decision but skips logging.
//
// ApplyMode is called by pipeline.AttachmentProcessor (ATR-167), which
// wires Evaluate's result into a milter verdict: it calls ApplyMode on
// each AttachmentDecision (or ApplyModeToMessage on the whole
// MessageDecision) before acting on the result, so dry-run is enforced
// in exactly one place.
func ApplyMode(d AttachmentDecision, globalDryRun bool, attachmentName string, logger *slog.Logger) AttachmentDecision {
	if !EffectiveDryRun(d, globalDryRun) {
		return d
	}

	if logger != nil {
		logger.Info("policy dry-run: action suppressed",
			"rule", d.RuleName,
			"attachment", attachmentName,
			"action", string(d.Action),
			"verdict", dryRunVerdict(d.Action),
		)
	}

	out := d
	out.Action = ActionPass
	return out
}

// ApplyModeToMessage applies ApplyMode to every attachment decision in
// m and re-aggregates the message-level Action/Reason from the
// mode-adjusted per-attachment decisions, mirroring the aggregation
// Evaluate performs (§3.1: the strongest per-attachment action wins at
// the message level). attachmentNames, if non-nil, must be the same
// length as m.Attachments and supplies the attachmentName ApplyMode
// logs for each entry; pass nil to log without file names.
//
// Like ApplyMode, this is a thin wrapper meant to be reused as-is by
// the ATR-167 Processor rather than reimplemented at that call site.
func ApplyModeToMessage(m MessageDecision, globalDryRun bool, attachmentNames []string, logger *slog.Logger) MessageDecision {
	out := MessageDecision{
		Attachments: make([]AttachmentDecision, len(m.Attachments)),
	}

	for i, d := range m.Attachments {
		var name string
		if attachmentNames != nil && i < len(attachmentNames) {
			name = attachmentNames[i]
		}

		adjusted := ApplyMode(d, globalDryRun, name, logger)
		out.Attachments[i] = adjusted

		if actionStrength(adjusted.Action) > actionStrength(out.Action) {
			out.Action = adjusted.Action
			out.Reason = adjusted.Reason
		}
	}

	return out
}
