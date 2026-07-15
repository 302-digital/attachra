package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readTestdata reads a fixture from testdata/, failing the test on
// error.
func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // fixed test fixture directory, not attacker-controlled
	if err != nil {
		t.Fatalf("read testdata %q: %v", name, err)
	}
	return data
}

// TestParse_GoldenScenarios parses each of the 5 scenarios from
// docs/architecture/policy-format-v1.md §5, asserting they are valid
// and that the parsed structure has the shape the spec describes.
func TestParse_GoldenScenarios(t *testing.T) {
	tests := []struct {
		file          string
		wantRuleCount int
		wantDefault   Action
		// wantWarnings is the number of warnings the scenario is
		// expected to produce, e.g. scenarios (a), (b) and (d) set an
		// explicit ttl on a replace action without retention, which
		// §3.5 flags as a (non-fatal) warning.
		wantWarnings int
	}{
		{"scenario_a_large_attachments.yaml", 2, ActionPass, 1},
		{"scenario_b_finance_outbound.yaml", 2, ActionPass, 1},
		{"scenario_c_block_executables.yaml", 2, ActionPass, 0},
		{"scenario_d_internal_untouched.yaml", 1, ActionReplace, 1},
		{"scenario_e_gdpr_starter.yaml", 2, ActionPass, 0},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data := readTestdata(t, tt.file)
			p, warnings, err := Parse(data, tt.file)
			if err != nil {
				t.Fatalf("Parse(%s) returned error: %v", tt.file, err)
			}
			if len(warnings) != tt.wantWarnings {
				t.Errorf("Parse(%s) warnings = %v, want %d warning(s)", tt.file, warnings, tt.wantWarnings)
			}
			if len(p.Rules) != tt.wantRuleCount {
				t.Errorf("Parse(%s) rule count = %d, want %d", tt.file, len(p.Rules), tt.wantRuleCount)
			}
			if p.Default.Action != tt.wantDefault {
				t.Errorf("Parse(%s) default action = %q, want %q", tt.file, p.Default.Action, tt.wantDefault)
			}
			if p.Version != 1 {
				t.Errorf("Parse(%s) version = %d, want 1", tt.file, p.Version)
			}
			if p.Name == "" {
				t.Errorf("Parse(%s) name is empty", tt.file)
			}
		})
	}
}

func TestParse_MinimalValidTemplate(t *testing.T) {
	data := readTestdata(t, "minimal_valid.yaml")
	p, warnings, err := Parse(data, "minimal_valid.yaml")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if len(p.Rules) != 0 {
		t.Errorf("Rules = %v, want empty", p.Rules)
	}
	if p.Default.Action != ActionPass {
		t.Errorf("Default.Action = %q, want pass", p.Default.Action)
	}
}

func TestParse_MissingDefaultIsRejected(t *testing.T) {
	// SR-119-1: a policy without a default must never be applied.
	data := readTestdata(t, "invalid_missing_default.yaml")
	p, _, err := Parse(data, "invalid_missing_default.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for a policy missing `default`")
	}
	if p != nil {
		t.Error("Parse returned a non-nil *Policy alongside an error")
	}
	if !strings.Contains(err.Error(), "default") {
		t.Errorf("error message %q does not mention `default`", err.Error())
	}
}

func TestParse_UnknownTopLevelFieldIsRejected(t *testing.T) {
	data := readTestdata(t, "invalid_unknown_top_level_field.yaml")
	_, _, err := Parse(data, "invalid_unknown_top_level_field.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for an unknown top-level field")
	}
}

func TestParse_WrongFieldForActionIsRejected(t *testing.T) {
	data := readTestdata(t, "invalid_wrong_field_for_action.yaml")
	_, _, err := Parse(data, "invalid_wrong_field_for_action.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for ttl on a block action")
	}
	if !strings.Contains(err.Error(), `"ttl"`) || !strings.Contains(err.Error(), `"replace"`) || !strings.Contains(err.Error(), `"block"`) {
		t.Errorf("error message %q does not match the §3.5 example shape", err.Error())
	}
}

func TestParse_MultiDocumentIsRejected(t *testing.T) {
	// §2.1: multi-document YAML is not supported in v1.
	data := readTestdata(t, "invalid_multi_document.yaml")
	_, _, err := Parse(data, "invalid_multi_document.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for a multi-document YAML file")
	}
}

func TestParse_UnreachableRuleWarns(t *testing.T) {
	// §3.3: a rule after a catch-all is unreachable — a warning, not
	// an error, since the policy is still well-formed and applicable.
	data := readTestdata(t, "warning_unreachable_rule.yaml")
	p, warnings, err := Parse(data, "warning_unreachable_rule.yaml")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if p == nil {
		t.Fatal("Parse returned nil *Policy for a policy that should still apply")
	}
	if len(warnings) == 0 {
		t.Fatal("Parse returned no warnings for an unreachable rule")
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "unreachable") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want one mentioning \"unreachable\"", warnings)
	}
}

func TestParse_EmptyDocumentIsRejected(t *testing.T) {
	_, _, err := Parse([]byte(""), "empty.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for an empty document")
	}
}

func TestParse_VersionTooNewIsRejected(t *testing.T) {
	data := []byte(`
version: 2
name: "future"
rules: []
default:
  action: pass
`)
	_, _, err := Parse(data, "future.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for an unsupported future version")
	}
	if !strings.Contains(err.Error(), "upgrade Attachra") {
		t.Errorf("error message %q does not mention upgrading, per §7.1", err.Error())
	}
}

func TestParse_MissingVersionIsRejected(t *testing.T) {
	data := []byte(`
name: "no version"
rules: []
default:
  action: pass
`)
	_, _, err := Parse(data, "no-version.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for a policy missing `version`")
	}
}

func TestParse_RuleWithoutNameIsRejected(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - then:
      action: pass
default:
  action: pass
`)
	_, _, err := Parse(data, "no-rule-name.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for a rule without a name")
	}
}

func TestParse_RuleWithoutThenIsRejected(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "no then"
default:
  action: pass
`)
	_, _, err := Parse(data, "no-then.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for a rule without `then`")
	}
}

func TestParse_InvalidActionEnumIsRejected(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "bogus action"
    then:
      action: quarantine
default:
  action: pass
`)
	_, _, err := Parse(data, "bad-action.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for an invalid action enum value")
	}
}

func TestParse_ReasonOnNonBlockIsRejected(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "reason on replace"
    then:
      action: replace
      reason: "should not be allowed here"
default:
  action: pass
`)
	_, _, err := Parse(data, "reason-on-replace.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for `reason` on a non-block action")
	}
}

// TestParse_ValidDispositionIsAccepted covers ADR-016: `disposition:
// [inline]` and `disposition: [attachment]` are both valid values in
// when.attachment.
func TestParse_ValidDispositionIsAccepted(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "inline opt-in"
    when:
      attachment:
        disposition: ["inline"]
    then:
      action: replace
      ttl: "1d"
  - name: "attachment only"
    when:
      attachment:
        disposition: ["attachment"]
    then:
      action: block
      reason: "no attachments"
default:
  action: pass
`)
	_, _, err := Parse(data, "valid-disposition.yaml")
	if err != nil {
		t.Fatalf("Parse returned error for valid disposition values: %v", err)
	}
}

// TestParse_InvalidDispositionIsRejected covers ADR-016's validator:
// any value outside {inline, attachment} must be rejected at
// policy-load time, not surfaced as a silent no-match at evaluation
// time.
func TestParse_InvalidDispositionIsRejected(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "bogus disposition"
    when:
      attachment:
        disposition: ["embedded"]
    then:
      action: replace
default:
  action: pass
`)
	_, _, err := Parse(data, "bad-disposition.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for an invalid disposition value")
	}
}

func TestParse_InvalidSizeFormatIsRejected(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "bad size"
    when:
      attachment:
        size: { min: "10 megabytes" }
    then:
      action: pass
default:
  action: pass
`)
	_, _, err := Parse(data, "bad-size.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for a malformed size string")
	}
}

func TestParse_InvalidDurationFormatIsRejected(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "bad ttl"
    then:
      action: replace
      ttl: "1d12h"
default:
  action: pass
`)
	_, _, err := Parse(data, "bad-ttl.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for a composite duration (1d12h)")
	}
}

func TestParse_ZeroDurationIsRejected(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "zero ttl"
    then:
      action: replace
      ttl: "0"
default:
  action: pass
`)
	_, _, err := Parse(data, "zero-ttl.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for a zero duration")
	}
}

func TestParse_EmptySizeRangeWarns(t *testing.T) {
	// §3.5: an inverted/empty size range is a warning, not an error.
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "impossible size"
    when:
      attachment:
        size: { min: "10MB", max: "1MB" }
    then:
      action: block
      reason: "unreachable"
default:
  action: pass
`)
	p, warnings, err := Parse(data, "empty-range.yaml")
	if err != nil {
		t.Fatalf("Parse returned error for a well-formed but empty range: %v", err)
	}
	if p == nil {
		t.Fatal("Parse returned nil *Policy")
	}
	if len(warnings) == 0 {
		t.Fatal("Parse returned no warnings for an empty size range")
	}
}

func TestLoad_ReadsFromDisk(t *testing.T) {
	p, err := Load(filepath.Join("testdata", "minimal_valid.yaml"))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if p.Name != "Policy name" {
		t.Errorf("Name = %q, want %q", p.Name, "Policy name")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "does_not_exist.yaml"))
	if err == nil {
		t.Fatal("Load returned nil error for a missing file")
	}
}
