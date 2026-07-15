package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validateTestValidPolicy = `
version: 1
name: "Valid policy"
rules: []
default:
  action: pass
`

const validateTestInvalidPolicy = `
version: 1
name: "Invalid policy"
rules:
  - name: "bad ttl"
    then:
      action: pass
      ttl: "30d"
default:
  action: pass
`

const validateTestWarningPolicy = `
version: 1
name: "Warning policy"
rules:
  - name: "catch-all"
    then:
      action: pass
  - name: "unreachable"
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
      reason: "never reached"
default:
  action: pass
`

func writeValidateTestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

func TestRunPolicyValidate_ValidFile_ExitZero(t *testing.T) {
	path := writeValidateTestFile(t, validateTestValidPolicy)
	var stdout, stderr bytes.Buffer

	code := runPolicyValidate([]string{path}, &stdout, &stderr)

	if code != policyValidateOK {
		t.Errorf("exit code = %d, want %d; stderr = %q", code, policyValidateOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "is valid") {
		t.Errorf("stdout = %q, want a success message", stdout.String())
	}
}

func TestRunPolicyValidate_InvalidFile_ExitOneWithErrors(t *testing.T) {
	path := writeValidateTestFile(t, validateTestInvalidPolicy)
	var stdout, stderr bytes.Buffer

	code := runPolicyValidate([]string{path}, &stdout, &stderr)

	if code != policyValidateInvalid {
		t.Errorf("exit code = %d, want %d", code, policyValidateInvalid)
	}
	if !strings.Contains(stderr.String(), "ttl") {
		t.Errorf("stderr = %q, want it to name the offending field %q", stderr.String(), "ttl")
	}
	if !strings.Contains(stderr.String(), "bad ttl") {
		t.Errorf("stderr = %q, want it to name the offending rule %q", stderr.String(), "bad ttl")
	}
}

func TestRunPolicyValidate_WarningsWithoutStrict_ExitZero(t *testing.T) {
	path := writeValidateTestFile(t, validateTestWarningPolicy)
	var stdout, stderr bytes.Buffer

	code := runPolicyValidate([]string{path}, &stdout, &stderr)

	if code != policyValidateOK {
		t.Errorf("exit code = %d, want %d (warnings alone should not fail without --strict)", code, policyValidateOK)
	}
	if !strings.Contains(stdout.String(), "unreachable") {
		t.Errorf("stdout = %q, want it to mention the unreachable rule warning", stdout.String())
	}
}

func TestRunPolicyValidate_WarningsWithStrict_ExitTwo(t *testing.T) {
	path := writeValidateTestFile(t, validateTestWarningPolicy)
	var stdout, stderr bytes.Buffer

	code := runPolicyValidate([]string{"--strict", path}, &stdout, &stderr)

	if code != policyValidateWarnings {
		t.Errorf("exit code = %d, want %d (warnings escalate under --strict)", code, policyValidateWarnings)
	}
}

func TestRunPolicyValidate_ValidWithStrict_ExitZero(t *testing.T) {
	path := writeValidateTestFile(t, validateTestValidPolicy)
	var stdout, stderr bytes.Buffer

	code := runPolicyValidate([]string{"--strict", path}, &stdout, &stderr)

	if code != policyValidateOK {
		t.Errorf("exit code = %d, want %d (no warnings means --strict has no effect)", code, policyValidateOK)
	}
}

func TestRunPolicyValidate_MissingFile_ExitOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	var stdout, stderr bytes.Buffer

	code := runPolicyValidate([]string{path}, &stdout, &stderr)

	if code != policyValidateInvalid {
		t.Errorf("exit code = %d, want %d", code, policyValidateInvalid)
	}
}

func TestRunPolicyValidate_NoArgs_ExitOne(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runPolicyValidate(nil, &stdout, &stderr)

	if code != policyValidateInvalid {
		t.Errorf("exit code = %d, want %d", code, policyValidateInvalid)
	}
}

func TestRunPolicyCommand_UnknownSubcommand_ExitOne(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runPolicyCommand([]string{"frobnicate"}, &stdout, &stderr)

	if code != policyValidateInvalid {
		t.Errorf("exit code = %d, want %d", code, policyValidateInvalid)
	}
}

func TestRunPolicyCommand_Validate_Dispatches(t *testing.T) {
	path := writeValidateTestFile(t, validateTestValidPolicy)
	var stdout, stderr bytes.Buffer

	code := runPolicyCommand([]string{"validate", path}, &stdout, &stderr)

	if code != policyValidateOK {
		t.Errorf("exit code = %d, want %d; stderr = %q", code, policyValidateOK, stderr.String())
	}
}

// TestRun_PolicyValidateSubcommand exercises the top-level run() entry
// point end to end, confirming `attachra policy validate <file>`
// short-circuits before config.Load (so it works without any app
// config at all).
func TestRun_PolicyValidateSubcommand(t *testing.T) {
	path := writeValidateTestFile(t, validateTestValidPolicy)
	var stdout, stderr bytes.Buffer

	code := run([]string{"policy", "validate", path}, &stdout, &stderr)

	if code != policyValidateOK {
		t.Errorf("run() exit code = %d, want %d; stderr = %q", code, policyValidateOK, stderr.String())
	}
}
