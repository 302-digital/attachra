package policy

import (
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/message"
)

// mustParse parses data (from testdata unless it starts with
// "version:", in which case it is treated as inline YAML) and fails
// the test on any error or warning-producing surprise.
func mustParseFile(t *testing.T, file string) *Policy {
	t.Helper()
	data := readTestdata(t, file)
	p, _, err := Parse(data, file)
	if err != nil {
		t.Fatalf("Parse(%s) returned error: %v", file, err)
	}
	return p
}

func mustParseInline(t *testing.T, data string) *Policy {
	t.Helper()
	p, _, err := Parse([]byte(data), "inline")
	if err != nil {
		t.Fatalf("Parse(inline) returned error: %v\n%s", err, data)
	}
	return p
}

// TestEvaluate_FirstMatchWins covers §3.2: rules are evaluated top to
// bottom and the first match wins; a rule after a match never runs.
func TestEvaluate_FirstMatchWins(t *testing.T) {
	p := mustParseInline(t, `
version: 1
name: "priority"
rules:
  - name: "first: exe -> block"
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
      reason: "exe blocked"
  - name: "second: catch-all -> replace"
    then:
      action: replace
      ttl: "1d"
default:
  action: pass
`)

	att := message.Attachment{Filename: "tool.exe", Size: 10}
	decision := Evaluate(p, EnvelopeMeta{Sender: "a@a.com", Recipients: []string{"b@b.com"}}, []message.Attachment{att})

	if decision.Action != ActionBlock {
		t.Fatalf("Action = %q, want block", decision.Action)
	}
	if got := decision.Attachments[0].RuleName; got != "first: exe -> block" {
		t.Errorf("RuleName = %q, want first rule name (first-match-wins)", got)
	}
}

// TestEvaluate_DefaultWhenNoRuleMatches covers §3.2's fallback to
// `default` when no rule matches.
func TestEvaluate_DefaultWhenNoRuleMatches(t *testing.T) {
	p := mustParseInline(t, `
version: 1
name: "default fallback"
rules:
  - name: "only exe"
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
default:
  action: replace
  ttl: "7d"
`)

	att := message.Attachment{Filename: "report.pdf", Size: 10}
	decision := Evaluate(p, EnvelopeMeta{Sender: "a@a.com", Recipients: []string{"b@b.com"}}, []message.Attachment{att})

	ad := decision.Attachments[0]
	if ad.Action != ActionReplace {
		t.Fatalf("Action = %q, want replace (default)", ad.Action)
	}
	if ad.RuleName != "" {
		t.Errorf("RuleName = %q, want empty string for default branch", ad.RuleName)
	}
	if ad.Params.TTL == nil || ad.Params.TTL.Duration() != 7*24*time.Hour {
		t.Errorf("Params.TTL = %v, want 7d", ad.Params.TTL)
	}
}

// TestEvaluate_InlineOptIn covers ADR-016: InlineOptIn is true only
// when the winning rule explicitly constrained
// when.attachment.disposition, false for a rule matching on other
// fields and false for the Policy.Default branch (which has no `when`
// to constrain disposition with).
func TestEvaluate_InlineOptIn(t *testing.T) {
	p := mustParseInline(t, `
version: 1
name: "inline opt-in"
rules:
  - name: "opt-in: replace inline images too"
    when:
      attachment:
        disposition: ["inline"]
        mime_type: ["image/*"]
    then:
      action: replace
      ttl: "1d"
  - name: "no disposition constraint"
    when:
      attachment:
        mime_type: ["application/pdf"]
    then:
      action: replace
      ttl: "1d"
default:
  action: replace
  ttl: "1d"
`)

	tests := []struct {
		name string
		att  message.Attachment
		want bool
	}{
		{"rule with explicit disposition constraint", message.Attachment{DetectedType: "image/png", InlineAsset: true}, true},
		{"rule without disposition constraint", message.Attachment{DetectedType: "application/pdf"}, false},
		{"default branch", message.Attachment{DetectedType: "application/zip"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := Evaluate(p, EnvelopeMeta{Sender: "a@a.com", Recipients: []string{"b@b.com"}}, []message.Attachment{tt.att})
			if got := decision.Attachments[0].InlineOptIn; got != tt.want {
				t.Errorf("InlineOptIn = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestStrongerDecision_InlineOptInORsAcrossRecipients covers ADR-016:
// when two recipients' winning rules both decide ActionReplace for the
// same attachment but only one explicitly opted the disposition in,
// the merged worst-case decision must preserve InlineOptIn=true rather
// than arbitrarily discarding it (this is a correctness requirement
// for the pipeline's protective downgrade, which must not
// re-downgrade an attachment a policy author deliberately opted in).
func TestStrongerDecision_InlineOptInORsAcrossRecipients(t *testing.T) {
	a := AttachmentDecision{Action: ActionReplace, InlineOptIn: true}
	b := AttachmentDecision{Action: ActionReplace, InlineOptIn: false}

	if got := strongerDecision(a, b); !got.InlineOptIn {
		t.Errorf("strongerDecision(opt-in, no-opt-in).InlineOptIn = %v, want true", got.InlineOptIn)
	}
	if got := strongerDecision(b, a); !got.InlineOptIn {
		t.Errorf("strongerDecision(no-opt-in, opt-in).InlineOptIn = %v, want true", got.InlineOptIn)
	}
}

// TestEvaluate_DisabledRuleIsSkipped covers §2.2's `disabled: true`.
func TestEvaluate_DisabledRuleIsSkipped(t *testing.T) {
	p := mustParseInline(t, `
version: 1
name: "disabled rule"
rules:
  - name: "disabled block"
    disabled: true
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
default:
  action: pass
`)

	att := message.Attachment{Filename: "tool.exe", Size: 10}
	decision := Evaluate(p, EnvelopeMeta{Sender: "a@a.com", Recipients: []string{"b@b.com"}}, []message.Attachment{att})

	if decision.Action != ActionPass {
		t.Fatalf("Action = %q, want pass (disabled rule must be skipped, falling to default)", decision.Action)
	}
}

// TestEvaluate_WorstCaseAcrossRecipients covers §3.4: the action for
// an attachment is the strongest among all recipients.
func TestEvaluate_WorstCaseAcrossRecipients(t *testing.T) {
	p := mustParseInline(t, `
version: 1
name: "worst case"
rules:
  - name: "internal recipients pass"
    when:
      recipient:
        domain: ["example.com"]
    then:
      action: pass
  - name: "external recipients replace"
    then:
      action: replace
      ttl: "30d"
default:
  action: pass
`)

	att := message.Attachment{Filename: "report.pdf", Size: 10}
	decision := Evaluate(p, EnvelopeMeta{
		Sender:     "alice@example.com",
		Recipients: []string{"mary@example.com", "bob@partner.com"},
	}, []message.Attachment{att})

	if decision.Attachments[0].Action != ActionReplace {
		t.Fatalf("Action = %q, want replace (worst-case across recipients: internal pass + external replace -> replace for all)", decision.Attachments[0].Action)
	}
}

// TestEvaluate_WorstCaseBlockWinsOverEverything covers §3.4: if any
// recipient's rule evaluation yields block, the whole message blocks.
func TestEvaluate_WorstCaseBlockWinsOverEverything(t *testing.T) {
	p := mustParseInline(t, `
version: 1
name: "block wins"
rules:
  - name: "internal recipients pass"
    when:
      recipient:
        domain: ["example.com"]
      attachment:
        extension: ["exe"]
    then:
      action: pass
  - name: "external recipients blocked"
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
      reason: "no executables to external recipients"
default:
  action: pass
`)

	att := message.Attachment{Filename: "tool.exe", Size: 10}
	decision := Evaluate(p, EnvelopeMeta{
		Sender:     "alice@example.com",
		Recipients: []string{"mary@example.com", "bob@partner.com"},
	}, []message.Attachment{att})

	if decision.Action != ActionBlock {
		t.Fatalf("Action = %q, want block", decision.Action)
	}
	if decision.Reason == "" {
		t.Error("Reason is empty, want the blocking rule's reason")
	}
}

// TestEvaluate_PerAttachmentIndependence covers §3.1: policy is
// computed independently per attachment; one attachment's verdict
// must not leak into another's.
func TestEvaluate_PerAttachmentIndependence(t *testing.T) {
	p := mustParseInline(t, `
version: 1
name: "per attachment"
rules:
  - name: "large files replace"
    when:
      attachment:
        size: { min: "10MB" }
    then:
      action: replace
      ttl: "30d"
default:
  action: pass
`)

	atts := []message.Attachment{
		{Filename: "small.pdf", Size: 200 * 1000},
		{Filename: "big.zip", Size: 40_000_000},
		{Filename: "tool.exe", Size: 10},
	}
	decision := Evaluate(p, EnvelopeMeta{Sender: "a@a.com", Recipients: []string{"b@b.com"}}, atts)

	want := []Action{ActionPass, ActionReplace, ActionPass}
	for i, w := range want {
		if decision.Attachments[i].Action != w {
			t.Errorf("Attachments[%d].Action = %q, want %q", i, decision.Attachments[i].Action, w)
		}
	}
	if decision.Action != ActionReplace {
		t.Errorf("message Action = %q, want replace (no block present, at least one replace)", decision.Action)
	}
}

// TestEvaluate_MessageBlockAggregation covers §3.1: any attachment
// decision of block blocks the whole message, regardless of other
// attachments' verdicts.
func TestEvaluate_MessageBlockAggregation(t *testing.T) {
	p := mustParseInline(t, `
version: 1
name: "message block"
rules:
  - name: "exe blocked"
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
      reason: "exe blocked"
default:
  action: pass
`)

	atts := []message.Attachment{
		{Filename: "notes.pdf", Size: 10},
		{Filename: "tool.exe", Size: 10},
	}
	decision := Evaluate(p, EnvelopeMeta{Sender: "a@a.com", Recipients: []string{"b@b.com"}}, atts)

	if decision.Action != ActionBlock {
		t.Fatalf("message Action = %q, want block", decision.Action)
	}
}

// TestEvaluate_NoAttachmentsPassesThrough covers §3.1: a message with
// no attachments produces no attachment decisions and an overall pass.
func TestEvaluate_NoAttachmentsPassesThrough(t *testing.T) {
	p := mustParseInline(t, `
version: 1
name: "no attachments"
rules: []
default:
  action: block
  reason: "should never apply: no attachments to evaluate"
`)

	decision := Evaluate(p, EnvelopeMeta{Sender: "a@a.com", Recipients: []string{"b@b.com"}}, nil)
	if decision.Action != ActionPass {
		t.Fatalf("Action = %q, want pass for a message with no attachments", decision.Action)
	}
	if len(decision.Attachments) != 0 {
		t.Errorf("Attachments = %v, want empty", decision.Attachments)
	}
}

// TestEvaluate_MostRestrictiveParamsOnConflict covers §4/§8.2 item 3:
// when two recipients both yield `replace` with different
// ttl/max_downloads/retention, the most restrictive (smallest) value
// per field wins.
func TestEvaluate_MostRestrictiveParamsOnConflict(t *testing.T) {
	p := mustParseInline(t, `
version: 1
name: "conflicting params"
rules:
  - name: "finance recipients: short ttl"
    when:
      recipient:
        domain: ["finance.example.com"]
    then:
      action: replace
      ttl: "7d"
      max_downloads: 2
      retention: "10d"
  - name: "everyone else: long ttl"
    then:
      action: replace
      ttl: "30d"
      max_downloads: 5
      retention: "90d"
default:
  action: pass
`)

	att := message.Attachment{Filename: "report.pdf", Size: 10}
	decision := Evaluate(p, EnvelopeMeta{
		Sender:     "a@a.com",
		Recipients: []string{"cfo@finance.example.com", "bob@other.com"},
	}, []message.Attachment{att})

	ad := decision.Attachments[0]
	if ad.Action != ActionReplace {
		t.Fatalf("Action = %q, want replace", ad.Action)
	}
	if ad.Params.TTL == nil || ad.Params.TTL.Duration() != 7*24*time.Hour {
		t.Errorf("Params.TTL = %v, want 7d (most restrictive)", ad.Params.TTL)
	}
	if ad.Params.MaxDownloads == nil || *ad.Params.MaxDownloads != 2 {
		t.Errorf("Params.MaxDownloads = %v, want 2 (most restrictive)", ad.Params.MaxDownloads)
	}
	if ad.Params.Retention == nil || ad.Params.Retention.Duration() != 10*24*time.Hour {
		t.Errorf("Params.Retention = %v, want 10d (most restrictive)", ad.Params.Retention)
	}
}

// TestEvaluate_GoldenScenarios exercises Evaluate against the 5
// worked scenarios from docs/architecture/policy-format-v1.md §5,
// checking the specific outcomes each scenario's prose describes.
func TestEvaluate_GoldenScenarios(t *testing.T) {
	t.Run("a: large attachment internal vs external", func(t *testing.T) {
		p := mustParseFile(t, "scenario_a_large_attachments.yaml")
		big := message.Attachment{Filename: "archive.zip", Size: 20_000_000}
		small := message.Attachment{Filename: "notes.txt", Size: 1000}

		internal := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@example.com"}}, []message.Attachment{big, small})
		if internal.Attachments[0].Action != ActionPass {
			t.Errorf("internal-only large attachment: Action = %q, want pass", internal.Attachments[0].Action)
		}

		external := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@partner.com"}}, []message.Attachment{big, small})
		if external.Attachments[0].Action != ActionReplace {
			t.Errorf("external large attachment: Action = %q, want replace", external.Attachments[0].Action)
		}
		if external.Attachments[1].Action != ActionPass {
			t.Errorf("small attachment: Action = %q, want pass (per-attachment independence)", external.Attachments[1].Action)
		}

		// Mixed internal+external recipients: worst-case -> replace for all.
		mixed := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@example.com", "c@partner.com"}}, []message.Attachment{big})
		if mixed.Attachments[0].Action != ActionReplace {
			t.Errorf("mixed recipients large attachment: Action = %q, want replace (worst-case)", mixed.Attachments[0].Action)
		}
	})

	t.Run("b: finance to internal vs external", func(t *testing.T) {
		p := mustParseFile(t, "scenario_b_finance_outbound.yaml")
		att := message.Attachment{Filename: "statement.pdf", Size: 1000}

		internal := Evaluate(p, EnvelopeMeta{Sender: "alice@finance.example.com", Recipients: []string{"bob@example.com"}}, []message.Attachment{att})
		if internal.Attachments[0].Action != ActionPass {
			t.Errorf("finance to internal: Action = %q, want pass", internal.Attachments[0].Action)
		}

		external := Evaluate(p, EnvelopeMeta{Sender: "alice@finance.example.com", Recipients: []string{"bob@partner.com"}}, []message.Attachment{att})
		ad := external.Attachments[0]
		if ad.Action != ActionReplace {
			t.Fatalf("finance to external: Action = %q, want replace", ad.Action)
		}
		if ad.Params.MaxDownloads == nil || *ad.Params.MaxDownloads != 3 {
			t.Errorf("MaxDownloads = %v, want 3", ad.Params.MaxDownloads)
		}

		nonFinance := Evaluate(p, EnvelopeMeta{Sender: "bob@example.com", Recipients: []string{"carl@partner.com"}}, []message.Attachment{att})
		if nonFinance.Attachments[0].Action != ActionPass {
			t.Errorf("non-finance sender: Action = %q, want pass (default)", nonFinance.Attachments[0].Action)
		}
	})

	t.Run("c: executables internal vs external", func(t *testing.T) {
		p := mustParseFile(t, "scenario_c_block_executables.yaml")
		exe := message.Attachment{Filename: "tool.exe", Size: 1000}

		internal := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@example.com"}}, []message.Attachment{exe})
		if internal.Action != ActionPass {
			t.Errorf("exe to internal: Action = %q, want pass", internal.Action)
		}

		external := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@partner.com"}}, []message.Attachment{exe})
		if external.Action != ActionBlock {
			t.Errorf("exe to external: Action = %q, want block", external.Action)
		}
		if external.Reason == "" {
			t.Error("Reason is empty, want the block rule's reason")
		}

		// Mixed recipients: worst-case -> block the whole message.
		mixed := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@example.com", "c@partner.com"}}, []message.Attachment{exe})
		if mixed.Action != ActionBlock {
			t.Errorf("mixed recipients with exe: Action = %q, want block", mixed.Action)
		}
	})

	t.Run("d: internal untouched, external defaults to replace", func(t *testing.T) {
		p := mustParseFile(t, "scenario_d_internal_untouched.yaml")
		att := message.Attachment{Filename: "notes.txt", Size: 10}

		internal := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@example.com"}}, []message.Attachment{att})
		if internal.Attachments[0].Action != ActionPass {
			t.Errorf("internal: Action = %q, want pass", internal.Attachments[0].Action)
		}

		external := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@partner.com"}}, []message.Attachment{att})
		if external.Attachments[0].Action != ActionReplace {
			t.Errorf("external (default branch): Action = %q, want replace", external.Attachments[0].Action)
		}

		// Mixed internal+external: worst-case -> replace for all,
		// including the internal recipient (§3.4 surprise case).
		mixed := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@example.com", "c@partner.com"}}, []message.Attachment{att})
		if mixed.Attachments[0].Action != ActionReplace {
			t.Errorf("mixed recipients: Action = %q, want replace (worst-case, internal sees a link too)", mixed.Attachments[0].Action)
		}
	})

	t.Run("e: GDPR starter EU vs non-EU retention", func(t *testing.T) {
		p := mustParseFile(t, "scenario_e_gdpr_starter.yaml")
		att := message.Attachment{Filename: "contract.pdf", Size: 1000}

		eu := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@partner.de"}}, []message.Attachment{att})
		euAD := eu.Attachments[0]
		if euAD.Action != ActionReplace {
			t.Fatalf("EU recipient: Action = %q, want replace", euAD.Action)
		}
		if euAD.Params.Retention == nil || euAD.Params.Retention.Duration() != 30*24*time.Hour {
			t.Errorf("EU recipient Retention = %v, want 30d", euAD.Params.Retention)
		}

		nonEU := Evaluate(p, EnvelopeMeta{Sender: "a@example.com", Recipients: []string{"b@elsewhere.com"}}, []message.Attachment{att})
		nonEUAD := nonEU.Attachments[0]
		if nonEUAD.Action != ActionReplace {
			t.Fatalf("non-EU recipient: Action = %q, want replace", nonEUAD.Action)
		}
		if nonEUAD.Params.Retention == nil || nonEUAD.Params.Retention.Duration() != 90*24*time.Hour {
			t.Errorf("non-EU recipient Retention = %v, want 90d", nonEUAD.Params.Retention)
		}
	})
}

// TestActionStrength_Ordering covers §3.1/§3.4: pass < replace <
// block.
func TestActionStrength_Ordering(t *testing.T) {
	if actionStrength(ActionPass) >= actionStrength(ActionReplace) {
		t.Error("pass is not weaker than replace")
	}
	if actionStrength(ActionReplace) >= actionStrength(ActionBlock) {
		t.Error("replace is not weaker than block")
	}
}

func TestStrongestAction(t *testing.T) {
	tests := []struct {
		a, b, want Action
	}{
		{ActionPass, ActionReplace, ActionReplace},
		{ActionBlock, ActionPass, ActionBlock},
		{ActionReplace, ActionReplace, ActionReplace},
		{ActionBlock, ActionBlock, ActionBlock},
	}
	for _, tt := range tests {
		if got := strongestAction(tt.a, tt.b); got != tt.want {
			t.Errorf("strongestAction(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}
