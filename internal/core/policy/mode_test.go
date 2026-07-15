package policy

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestEffectiveDryRun(t *testing.T) {
	tests := []struct {
		name         string
		decisionFlag *bool
		globalDryRun bool
		want         bool
	}{
		{"nil defers to global true", nil, true, true},
		{"nil defers to global false", nil, false, false},
		{"rule override true beats global false", boolPtr(true), false, true},
		{"rule override false beats global true", boolPtr(false), true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := AttachmentDecision{DryRun: tt.decisionFlag}
			if got := EffectiveDryRun(d, tt.globalDryRun); got != tt.want {
				t.Errorf("EffectiveDryRun() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyMode_NotDryRun_ReturnsUnchanged(t *testing.T) {
	d := AttachmentDecision{Action: ActionBlock, RuleName: "block-exe", Reason: "no exe"}

	got := ApplyMode(d, false, "malware.exe", nil)

	if got.Action != ActionBlock {
		t.Errorf("Action = %v, want unchanged ActionBlock", got.Action)
	}
	if got.Reason != "no exe" {
		t.Errorf("Reason = %q, want unchanged %q", got.Reason, "no exe")
	}
}

func TestApplyMode_GlobalDryRun_ForcesAccept(t *testing.T) {
	tests := []struct {
		name   string
		action Action
	}{
		{"replace becomes pass", ActionReplace},
		{"block becomes pass", ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := AttachmentDecision{Action: tt.action, RuleName: "r1"}

			got := ApplyMode(d, true, "file.bin", nil)

			if got.Action != ActionPass {
				t.Errorf("Action = %v, want ActionPass (dry-run always accepts)", got.Action)
			}
		})
	}
}

func TestApplyMode_PerRuleOverride(t *testing.T) {
	tests := []struct {
		name         string
		ruleDryRun   *bool
		globalDryRun bool
		wantAction   Action
	}{
		{"rule forces dry-run despite global off", boolPtr(true), false, ActionPass},
		{"rule forces real action despite global dry-run", boolPtr(false), true, ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := AttachmentDecision{Action: ActionBlock, RuleName: "r1", DryRun: tt.ruleDryRun}

			got := ApplyMode(d, tt.globalDryRun, "file.bin", nil)

			if got.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", got.Action, tt.wantAction)
			}
		})
	}
}

func TestApplyMode_LogsStructuredDryRunRecord(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	d := AttachmentDecision{Action: ActionReplace, RuleName: "large-files"}
	ApplyMode(d, true, "report.pdf", logger)

	out := buf.String()
	for _, want := range []string{"rule=large-files", "attachment=report.pdf", "action=replace", "verdict=would-replace"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output = %q, want substring %q", out, want)
		}
	}
}

func TestApplyMode_NilLogger_DoesNotPanic(t *testing.T) {
	d := AttachmentDecision{Action: ActionBlock}
	got := ApplyMode(d, true, "x", nil)
	if got.Action != ActionPass {
		t.Errorf("Action = %v, want ActionPass", got.Action)
	}
}

func TestDryRunVerdict(t *testing.T) {
	tests := []struct {
		action Action
		want   string
	}{
		{ActionPass, "would-pass"},
		{ActionReplace, "would-replace"},
		{ActionBlock, "would-block"},
	}
	for _, tt := range tests {
		if got := dryRunVerdict(tt.action); got != tt.want {
			t.Errorf("dryRunVerdict(%v) = %q, want %q", tt.action, got, tt.want)
		}
	}
}

func TestApplyModeToMessage_AllDryRun_MessageBecomesAccept(t *testing.T) {
	m := MessageDecision{
		Action: ActionBlock,
		Reason: "exe blocked",
		Attachments: []AttachmentDecision{
			{Action: ActionReplace, RuleName: "large"},
			{Action: ActionBlock, RuleName: "block-exe", Reason: "exe blocked"},
		},
	}

	got := ApplyModeToMessage(m, true, []string{"big.zip", "malware.exe"}, nil)

	if got.Action != ActionPass {
		t.Errorf("message Action = %v, want ActionPass under global dry-run", got.Action)
	}
	if got.Reason != "" {
		t.Errorf("message Reason = %q, want empty once every attachment is forced to pass", got.Reason)
	}
	for i, ad := range got.Attachments {
		if ad.Action != ActionPass {
			t.Errorf("Attachments[%d].Action = %v, want ActionPass", i, ad.Action)
		}
	}
}

func TestApplyModeToMessage_NotDryRun_PreservesAggregation(t *testing.T) {
	m := MessageDecision{
		Action: ActionBlock,
		Reason: "exe blocked",
		Attachments: []AttachmentDecision{
			{Action: ActionReplace, RuleName: "large"},
			{Action: ActionBlock, RuleName: "block-exe", Reason: "exe blocked"},
		},
	}

	got := ApplyModeToMessage(m, false, nil, nil)

	if got.Action != ActionBlock {
		t.Errorf("message Action = %v, want ActionBlock preserved", got.Action)
	}
	if got.Reason != "exe blocked" {
		t.Errorf("message Reason = %q, want %q", got.Reason, "exe blocked")
	}
}

func TestApplyModeToMessage_MixedPerRuleOverride(t *testing.T) {
	// Global dry-run is on, but the block rule opted out of dry-run
	// via its own then.dry_run: false, so the message must still be
	// blocked for real even though the replace attachment is
	// suppressed to pass.
	m := MessageDecision{
		Attachments: []AttachmentDecision{
			{Action: ActionReplace, RuleName: "large"},
			{Action: ActionBlock, RuleName: "block-exe", Reason: "exe blocked", DryRun: boolPtr(false)},
		},
	}

	got := ApplyModeToMessage(m, true, nil, nil)

	if got.Action != ActionBlock {
		t.Errorf("message Action = %v, want ActionBlock (rule opted out of dry-run)", got.Action)
	}
	if got.Attachments[0].Action != ActionPass {
		t.Errorf("Attachments[0].Action = %v, want ActionPass (still under global dry-run)", got.Attachments[0].Action)
	}
	if got.Attachments[1].Action != ActionBlock {
		t.Errorf("Attachments[1].Action = %v, want ActionBlock (opted out)", got.Attachments[1].Action)
	}
}
