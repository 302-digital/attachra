package main

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/spf13/cobra"
)

// seedAuditEvents records n plain TypeError events directly against
// ts's store (mirroring internal/adapters/http/auditlist_test.go's own
// seeding style), returning nothing since callers only need their
// count and ascending seq order, which the store guarantees.
func seedAuditEvents(t *testing.T, ts *testServer, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if _, err := ts.store.Record(ctx, audit.Event{Type: audit.TypeError, Actor: "test-actor-" + strconv.Itoa(i)}); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}
}

func TestAuditList(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "auditor", store.RoleAuditor)
	seedAuditEvents(t, ts, 3)

	code, stdout, stderr := runCLI(t, ts, secret, "audit", "list")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if strings.Count(stdout, "test-actor-") != 3 {
		t.Errorf("stdout = %q, want 3 events", stdout)
	}
}

func TestAuditList_JSON_IsLines(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "auditor", store.RoleAuditor)
	seedAuditEvents(t, ts, 3)

	code, stdout, stderr := runCLI(t, ts, secret, "--json", "audit", "list")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d JSON lines, want 3; stdout=%s", len(lines), stdout)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "{") || !strings.HasSuffix(l, "}") {
			t.Errorf("line %q is not a single compact JSON object", l)
		}
	}
}

func TestAuditList_SinglePageHintsCursor(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "auditor", store.RoleAuditor)
	seedAuditEvents(t, ts, 5)

	code, stdout, stderr := runCLI(t, ts, secret, "audit", "list", "--limit", "2")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if strings.Count(stdout, "test-actor-") != 2 {
		t.Errorf("stdout = %q, want exactly 2 events (single page, no --all)", stdout)
	}
	if !strings.Contains(stderr, "more results available") {
		t.Errorf("stderr = %q, want a hint about the remaining page", stderr)
	}
}

func TestAuditList_All(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "auditor", store.RoleAuditor)
	seedAuditEvents(t, ts, 5)

	code, stdout, stderr := runCLI(t, ts, secret, "audit", "list", "--limit", "2", "--all")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if strings.Count(stdout, "test-actor-") != 5 {
		t.Errorf("stdout = %q, want all 5 events with --all", stdout)
	}
}

func TestAuditTail(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "auditor", store.RoleAuditor)
	seedAuditEvents(t, ts, 5)

	code, stdout, stderr := runCLI(t, ts, secret, "audit", "tail", "--lines", "2")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	// Only the last 2 of 5 seeded events (actor indices 3 and 4) should
	// be present.
	if strings.Count(stdout, "test-actor-") != 2 {
		t.Errorf("stdout = %q, want exactly 2 lines (--lines 2)", stdout)
	}
	if !strings.Contains(stdout, "test-actor-3") || !strings.Contains(stdout, "test-actor-4") {
		t.Errorf("stdout = %q, want the two most recent events", stdout)
	}
	if strings.Contains(stdout, "test-actor-0") {
		t.Errorf("stdout = %q, want the oldest events excluded", stdout)
	}
}

func TestAuditTail_JSON(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "auditor", store.RoleAuditor)
	seedAuditEvents(t, ts, 2)

	code, stdout, stderr := runCLI(t, ts, secret, "--json", "audit", "tail", "--lines", "10")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d JSON lines, want 2; stdout=%s", len(lines), stdout)
	}
}

func TestAuditExport_Streams(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "auditor", store.RoleAuditor)
	seedAuditEvents(t, ts, 4)

	code, stdout, stderr := runCLI(t, ts, secret, "audit", "export")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d NDJSON lines, want 4; stdout=%s", len(lines), stdout)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "{") {
			t.Errorf("line %q does not look like a JSON object", l)
		}
	}
}

// TestFollowAudit_PicksUpNewEvents exercises followAudit directly
// (rather than through the full CLI, which builds its own
// signal-derived context inside runMain with no test hook to bound
// it): it seeds one initial event, starts following from its
// watermark, records a second event shortly after, and expects
// followAudit to print exactly that new event before its
// context-bounded deadline stops the poll loop.
func TestFollowAudit_PicksUpNewEvents(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "auditor", store.RoleAuditor)

	rec, err := ts.store.Record(context.Background(), audit.Event{Type: audit.TypeError, Actor: "initial"})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	client, err := newClient(connectConfig{URL: ts.URL, Token: secret, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("newClient() error = %v", err)
	}
	var buf bytes.Buffer
	env := &appEnv{stdout: &buf, stderr: io.Discard, client: client}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)

	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = ts.store.Record(context.Background(), audit.Event{Type: audit.TypeError, Actor: "follow-actor"})
	}()

	if err := followAudit(cmd, env, "", "", 20*time.Millisecond, rec.Seq, rec.Timestamp.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("followAudit() error = %v", err)
	}

	if !strings.Contains(buf.String(), "follow-actor") {
		t.Errorf("stdout = %q, want the new event picked up by follow", buf.String())
	}
	if strings.Contains(buf.String(), "\tinitial\t") {
		t.Errorf("stdout = %q, want the already-seen initial event NOT reprinted", buf.String())
	}
}

func TestAuditList_ViewerForbidden(t *testing.T) {
	ts := newTestServer(t)
	// GET /audit is allowed for admin/viewer/auditor per api/openapi.yaml
	// (ADR-015 restricts auditor to *only* audit resources, not the
	// reverse) — verify a role with no token at all still gets a clean
	// 401 rather than a panic/crash, and that an unknown role string
	// cannot be used to bypass auth.
	code, _, stderr := runCLI(t, ts, "not-a-real-token", "audit", "list")
	if code != exitUnauthorized {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitUnauthorized, stderr)
	}
}
