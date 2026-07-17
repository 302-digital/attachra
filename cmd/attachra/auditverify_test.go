package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// emptyAuditStore opens a fresh store with no events.
func emptyAuditStore(t *testing.T) *sqlite.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit-verify-test.db")
	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestRunAuditVerify_LiveChainOK(t *testing.T) {
	st := newAuditTestStore(t) // seeds 3 chained events
	var stdout, stderr bytes.Buffer

	code := runAuditVerify(nil, st, &stdout, &stderr)
	if code != auditVerifyOK {
		t.Fatalf("code = %d, want %d; stderr=%s", code, auditVerifyOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "verified") {
		t.Errorf("stdout = %q, want it to report a verified chain", stdout.String())
	}
}

func TestRunAuditVerify_EmptyLogOK(t *testing.T) {
	st := emptyAuditStore(t)
	var stdout, stderr bytes.Buffer

	code := runAuditVerify(nil, st, &stdout, &stderr)
	if code != auditVerifyOK {
		t.Fatalf("code = %d, want %d; stderr=%s", code, auditVerifyOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "empty") {
		t.Errorf("stdout = %q, want it to report an empty log", stdout.String())
	}
}

func TestRunAuditVerify_RejectsExtraArgs(t *testing.T) {
	st := emptyAuditStore(t)
	var stdout, stderr bytes.Buffer

	code := runAuditVerify([]string{"unexpected"}, st, &stdout, &stderr)
	if code != auditVerifyError {
		t.Errorf("code = %d, want %d for an unexpected positional argument", code, auditVerifyError)
	}
}

// TestRunAuditVerify_JSONLSegmentOK exports the seeded chain to a file and
// verifies it offline (--jsonl), without consulting the passed store.
func TestRunAuditVerify_JSONLSegmentOK(t *testing.T) {
	st := newAuditTestStore(t)
	path := exportToFile(t, st)

	var stdout, stderr bytes.Buffer
	// Pass a fresh empty store to prove --jsonl reads the file, not the DB.
	code := runAuditVerify([]string{"--jsonl", path}, emptyAuditStore(t), &stdout, &stderr)
	if code != auditVerifyOK {
		t.Fatalf("code = %d, want %d; stderr=%s", code, auditVerifyOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "exported segment") {
		t.Errorf("stdout = %q, want it to name the exported segment source", stdout.String())
	}
}

// TestRunAuditVerify_JSONLSegmentTampered flips a byte in the exported
// segment and confirms the command reports tamper with a non-zero exit.
func TestRunAuditVerify_JSONLSegmentTampered(t *testing.T) {
	st := newAuditTestStore(t)
	path := exportToFile(t, st)

	raw, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path.
	if err != nil {
		t.Fatalf("read export error = %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"actor":"test"`), []byte(`"actor":"evil"`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("test setup: no actor field was replaced")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil { //nolint:gosec // test-controlled temp path from t.TempDir().
		t.Fatalf("write tampered export error = %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runAuditVerify([]string{"--jsonl", path}, emptyAuditStore(t), &stdout, &stderr)
	if code != auditVerifyTampered {
		t.Fatalf("code = %d, want %d (tampered); stdout=%s", code, auditVerifyTampered, stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAILED") {
		t.Errorf("stdout = %q, want a FAILED verdict", stdout.String())
	}
}

func TestRunAuditVerify_JSONLMissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAuditVerify([]string{"--jsonl", filepath.Join(t.TempDir(), "nope.jsonl")}, emptyAuditStore(t), &stdout, &stderr)
	if code != auditVerifyError {
		t.Errorf("code = %d, want %d for a missing segment file", code, auditVerifyError)
	}
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want a diagnostic message")
	}
}

// TestRunAuditCommand_RoutesVerify confirms the audit dispatcher routes
// the verify subcommand.
func TestRunAuditCommand_RoutesVerify(t *testing.T) {
	st := newAuditTestStore(t)
	var stdout, stderr bytes.Buffer
	code := runAuditCommand([]string{"verify"}, st, &stdout, &stderr)
	if code != auditVerifyOK {
		t.Fatalf("code = %d, want %d; stderr=%s", code, auditVerifyOK, stderr.String())
	}
}

// exportToFile writes the store's audit log as JSON Lines into a temp file
// and returns its path.
func exportToFile(t *testing.T, src audit.Reader) string {
	t.Helper()
	var buf bytes.Buffer
	if err := audit.ExportJSONL(context.Background(), src, &buf, audit.Filter{}); err != nil {
		t.Fatalf("ExportJSONL() error = %v, want nil", err)
	}
	path := filepath.Join(t.TempDir(), "segment.jsonl")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write segment error = %v", err)
	}
	return path
}
