package main

import (
	"bufio"
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// newAuditTestStore opens a fresh sqlite store under t.TempDir() and
// seeds it with a small, mixed-type audit trail for the export command
// tests below.
func newAuditTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit-export-test.db")
	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	events := []audit.Event{
		{Type: audit.TypeDownload, Actor: "test", MessageID: "m1"},
		{Type: audit.TypeRevoke, Actor: "test", MessageID: "m1"},
		{Type: audit.TypeError, Actor: "test", MessageID: "m2"},
	}
	for _, ev := range events {
		if _, err := st.Record(ctx, ev); err != nil {
			t.Fatalf("Record() error = %v, want nil", err)
		}
	}
	return st
}

func TestRunAuditExport_AllEvents(t *testing.T) {
	st := newAuditTestStore(t)
	var stdout, stderr bytes.Buffer

	code := runAuditExport(nil, st, &stdout, &stderr)
	if code != auditExportOK {
		t.Fatalf("runAuditExport() code = %d, want %d; stderr=%s", code, auditExportOK, stderr.String())
	}

	lines := countLines(t, &stdout)
	if lines != 3 {
		t.Errorf("exported %d lines, want 3", lines)
	}
}

func TestRunAuditExport_TypeFilter(t *testing.T) {
	st := newAuditTestStore(t)
	var stdout, stderr bytes.Buffer

	code := runAuditExport([]string{"--type", "revoke"}, st, &stdout, &stderr)
	if code != auditExportOK {
		t.Fatalf("runAuditExport() code = %d, want %d; stderr=%s", code, auditExportOK, stderr.String())
	}

	if !strings.Contains(stdout.String(), `"type":"revoke"`) {
		t.Errorf("stdout = %q, want it to contain a revoke event", stdout.String())
	}
	if strings.Contains(stdout.String(), `"type":"download"`) {
		t.Errorf("stdout = %q, want it to exclude the download event", stdout.String())
	}
}

func TestRunAuditExport_InvalidFromFlag(t *testing.T) {
	st := newAuditTestStore(t)
	var stdout, stderr bytes.Buffer

	code := runAuditExport([]string{"--from", "not-a-timestamp"}, st, &stdout, &stderr)
	if code != auditExportError {
		t.Errorf("runAuditExport() code = %d, want %d for an invalid --from value", code, auditExportError)
	}
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want a diagnostic message")
	}
}

func TestRunAuditExport_RejectsExtraArgs(t *testing.T) {
	st := newAuditTestStore(t)
	var stdout, stderr bytes.Buffer

	code := runAuditExport([]string{"unexpected-arg"}, st, &stdout, &stderr)
	if code != auditExportError {
		t.Errorf("runAuditExport() code = %d, want %d for an unexpected positional argument", code, auditExportError)
	}
}

func TestRunAuditCommand_UnknownSubcommand(t *testing.T) {
	st := newAuditTestStore(t)
	var stdout, stderr bytes.Buffer

	code := runAuditCommand([]string{"bogus"}, st, &stdout, &stderr)
	if code != auditExportError {
		t.Errorf("runAuditCommand() code = %d, want %d for an unknown subcommand", code, auditExportError)
	}
}

func TestParseAuditExportFilter(t *testing.T) {
	f, err := parseAuditExportFilter("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "download")
	if err != nil {
		t.Fatalf("parseAuditExportFilter() error = %v, want nil", err)
	}
	if f.Type != audit.TypeDownload {
		t.Errorf("Type = %q, want %q", f.Type, audit.TypeDownload)
	}
	wantFrom := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !f.From.Equal(wantFrom) {
		t.Errorf("From = %v, want %v", f.From, wantFrom)
	}

	empty, err := parseAuditExportFilter("", "", "")
	if err != nil {
		t.Fatalf("parseAuditExportFilter(empty) error = %v, want nil", err)
	}
	if !empty.From.IsZero() || !empty.To.IsZero() || empty.Type != "" {
		t.Errorf("parseAuditExportFilter(empty) = %+v, want zero value", empty)
	}

	if _, err := parseAuditExportFilter("not-a-time", "", ""); err == nil {
		t.Error("parseAuditExportFilter() with invalid --from error = nil, want an error")
	}
}

// countLines reports the number of newline-terminated lines in buf.
func countLines(t *testing.T, buf *bytes.Buffer) int {
	t.Helper()
	scanner := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	n := 0
	for scanner.Scan() {
		n++
	}
	return n
}
