package main

import (
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/store"
)

func TestStatsSummary(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	code, stdout, stderr := runCLI(t, ts, secret, "stats", "summary", "--from", "2020-01-01T00:00:00Z", "--to", "2030-01-01T00:00:00Z")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "downloads=0") {
		t.Errorf("stdout = %q, want an empty-window summary", stdout)
	}
	if !strings.Contains(stdout, "messages by day:") {
		t.Errorf("stdout = %q, want the messages-by-day section", stdout)
	}
}

func TestStatsSummary_RequiresFromTo(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	code, _, stderr := runCLI(t, ts, secret, "stats", "summary")
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitUsage, stderr)
	}
}

func TestStatsDeliverability_Empty(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	code, stdout, stderr := runCLI(t, ts, secret, "stats", "deliverability", "--from", "2020-01-01T00:00:00Z", "--to", "2030-01-01T00:00:00Z")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "(no results)") {
		t.Errorf("stdout = %q, want the empty-table marker", stdout)
	}
}

func TestStatsSummary_Auditor_Forbidden(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "auditor", store.RoleAuditor)

	code, _, stderr := runCLI(t, ts, secret, "stats", "summary", "--from", "2020-01-01T00:00:00Z", "--to", "2030-01-01T00:00:00Z")
	if code != exitForbidden {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitForbidden, stderr)
	}
}
