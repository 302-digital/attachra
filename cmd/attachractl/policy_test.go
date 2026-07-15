package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/store"
)

func TestPolicyCurrent(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	code, stdout, stderr := runCLI(t, ts, secret, "policy", "current")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "test-policy") {
		t.Errorf("stdout = %q, want it to mention the policy name", stdout)
	}
	if !strings.Contains(stdout, "block executables") {
		t.Errorf("stdout = %q, want it to list the rule", stdout)
	}
}

func TestPolicyCurrent_JSON(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	code, stdout, stderr := runCLI(t, ts, secret, "--json", "policy", "current")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, `"name":"test-policy"`) {
		t.Errorf("stdout = %q, want compact JSON with the policy name", stdout)
	}
	if strings.Count(stdout, "\n") != 1 {
		t.Errorf("stdout = %q, want exactly one JSON line", stdout)
	}
}

func TestPolicyValidate_Valid(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)

	path := filepath.Join(t.TempDir(), "valid.yaml")
	if err := os.WriteFile(path, []byte(defaultTestPolicyYAML), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	code, stdout, stderr := runCLI(t, ts, secret, "policy", "validate", path)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "VALID") {
		t.Errorf("stdout = %q, want it to report VALID", stdout)
	}
}

func TestPolicyValidate_Invalid(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)

	path := filepath.Join(t.TempDir(), "invalid.yaml")
	// Missing the required top-level `default` action.
	if err := os.WriteFile(path, []byte("version: 1\nname: bad\nrules: []\n"), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	code, stdout, stderr := runCLI(t, ts, secret, "policy", "validate", path)
	if code != exitValidation {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitValidation, stdout, stderr)
	}
	if !strings.Contains(stdout, "INVALID") {
		t.Errorf("stdout = %q, want it to report INVALID", stdout)
	}
	if !strings.Contains(stdout, "errors:") {
		t.Errorf("stdout = %q, want an errors table", stdout)
	}
}

func TestPolicyValidate_MissingFile(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)

	code, _, stderr := runCLI(t, ts, secret, "policy", "validate", "/no/such/file.yaml")
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitUsage, stderr)
	}
}

func TestPolicyReload_Success(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)

	code, stdout, stderr := runCLI(t, ts, secret, "policy", "reload")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "policy reloaded") {
		t.Errorf("stdout = %q, want a reload confirmation", stdout)
	}
}

func TestPolicyReload_ForbiddenForViewer(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	code, _, stderr := runCLI(t, ts, secret, "policy", "reload")
	if code != exitForbidden {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitForbidden, stderr)
	}
	if !strings.Contains(stderr, "attachractl:") {
		t.Errorf("stderr = %q, want the attachractl error prefix", stderr)
	}
}

func TestPolicyReload_InvalidPolicyOnDisk(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)

	// Corrupt the policy file the server is configured to reload from.
	if err := os.WriteFile(ts.policyPath, []byte("version: 1\nname: broken\nrules: []\n"), 0o600); err != nil {
		t.Fatalf("corrupt policy file: %v", err)
	}

	code, _, stderr := runCLI(t, ts, secret, "policy", "reload")
	if code != exitConflict {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitConflict, stderr)
	}
}

func TestPolicyDryRun_Flags(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	code, stdout, stderr := runCLI(t, ts, secret,
		"policy", "dry-run",
		"--sender", "alice@example.com",
		"--recipient", "bob@example.com",
		"--attachment", "malware.exe:12345:application/octet-stream",
	)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "block") {
		t.Errorf("stdout = %q, want it to report the block decision for an .exe attachment", stdout)
	}
}

func TestPolicyDryRun_MissingFlags(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	code, _, stderr := runCLI(t, ts, secret, "policy", "dry-run", "--sender", "alice@example.com")
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitUsage, stderr)
	}
}

func TestPolicyDryRun_FromFile(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	reqPath := filepath.Join(t.TempDir(), "dryrun.json")
	body := `{"sender":"alice@example.com","recipients":["bob@example.com"],"attachments":[{"filename":"clean.pdf","size":100,"detected_type":"application/pdf"}]}`
	if err := os.WriteFile(reqPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write dry-run request file: %v", err)
	}

	code, stdout, stderr := runCLI(t, ts, secret, "policy", "dry-run", "--file", reqPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "pass") {
		t.Errorf("stdout = %q, want it to report the pass decision for a non-matching attachment", stdout)
	}
}
