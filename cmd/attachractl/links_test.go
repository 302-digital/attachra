package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/store"
)

func TestLinksList(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)
	seedLink(t, ts, "msg-1", "link-1", "alice@example.com")
	seedLink(t, ts, "msg-1", "link-2", "bob@example.com")

	code, stdout, stderr := runCLI(t, ts, secret, "links", "list")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "link-1") || !strings.Contains(stdout, "link-2") {
		t.Errorf("stdout = %q, want both seeded links", stdout)
	}
}

func TestLinksList_AutoPagination(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	const n = 7
	for i := 0; i < n; i++ {
		id := "link-" + strconv.Itoa(i)
		seedLink(t, ts, "msg-page", id, "user"+strconv.Itoa(i)+"@example.com")
	}

	// A small --limit forces multiple pages; fetchAllPages must walk
	// every one of them so all n links appear in the output.
	code, stdout, stderr := runCLI(t, ts, secret, "--json", "links", "list", "--limit", "2")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != n {
		t.Fatalf("got %d JSON lines, want %d (auto-pagination should walk every page); stdout=%s", len(lines), n, stdout)
	}
}

func TestLinksList_FilterByRecipient(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)
	seedLink(t, ts, "msg-1", "link-1", "alice@example.com")
	seedLink(t, ts, "msg-1", "link-2", "bob@example.com")

	code, stdout, stderr := runCLI(t, ts, secret, "links", "list", "--recipient", "alice@example.com")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "link-1") {
		t.Errorf("stdout = %q, want link-1", stdout)
	}
	if strings.Contains(stdout, "link-2") {
		t.Errorf("stdout = %q, want link-2 filtered out", stdout)
	}
}

func TestLinksGet(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)
	seedLink(t, ts, "msg-1", "link-1", "alice@example.com")

	code, stdout, stderr := runCLI(t, ts, secret, "links", "get", "link-1")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "link-1") || !strings.Contains(stdout, "alice@example.com") {
		t.Errorf("stdout = %q, want link-1 details", stdout)
	}
}

func TestLinksGet_NotFound(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	code, _, stderr := runCLI(t, ts, secret, "links", "get", "no-such-link")
	if code != exitNotFound {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitNotFound, stderr)
	}
}

func TestLinksRevoke_ByID(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)
	seedLink(t, ts, "msg-1", "link-1", "alice@example.com")

	code, stdout, stderr := runCLI(t, ts, secret, "links", "revoke", "link-1")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "revoked") {
		t.Errorf("stdout = %q, want a revoke confirmation", stdout)
	}
}

func TestLinksRevoke_RequiresAdmin(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)
	seedLink(t, ts, "msg-1", "link-1", "alice@example.com")

	code, _, stderr := runCLI(t, ts, secret, "links", "revoke", "link-1")
	if code != exitForbidden {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitForbidden, stderr)
	}
}

func TestLinksRevoke_ByMessageID(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)
	seedLink(t, ts, "msg-1", "link-1", "alice@example.com")
	seedLink(t, ts, "msg-1", "link-2", "bob@example.com")

	code, stdout, stderr := runCLI(t, ts, secret, "links", "revoke", "--message-id", "msg-1")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "2 link(s) revoked") {
		t.Errorf("stdout = %q, want both links reported revoked", stdout)
	}
}

func TestLinksRevoke_BySender(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)
	seedLink(t, ts, "msg-1", "link-1", "alice@example.com")

	code, stdout, stderr := runCLI(t, ts, secret, "links", "revoke", "--sender", "sender@example.com")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "1 link(s) revoked") {
		t.Errorf("stdout = %q, want one link reported revoked", stdout)
	}
}

func TestLinksRevoke_RequiresExactlyOneMode(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)

	code, _, stderr := runCLI(t, ts, secret, "links", "revoke")
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitUsage, stderr)
	}

	code, _, stderr = runCLI(t, ts, secret, "links", "revoke", "link-1", "--message-id", "msg-1")
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitUsage, stderr)
	}
}

func TestLinksHoldAndUnhold(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)
	seedLink(t, ts, "msg-1", "link-1", "alice@example.com")

	code, stdout, stderr := runCLI(t, ts, secret, "links", "hold", "link-1")
	if code != exitOK {
		t.Fatalf("hold: exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "held") {
		t.Errorf("hold stdout = %q, want a hold confirmation", stdout)
	}

	// A held link cannot be revoked (409 held -> exitConflict).
	code, _, stderr = runCLI(t, ts, secret, "links", "revoke", "link-1")
	if code != exitConflict {
		t.Fatalf("revoke while held: exit code = %d, want %d; stderr=%s", code, exitConflict, stderr)
	}

	code, stdout, stderr = runCLI(t, ts, secret, "links", "unhold", "link-1")
	if code != exitOK {
		t.Fatalf("unhold: exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "released from hold") {
		t.Errorf("unhold stdout = %q, want an unhold confirmation", stdout)
	}

	code, stdout, stderr = runCLI(t, ts, secret, "links", "revoke", "link-1")
	if code != exitOK {
		t.Fatalf("revoke after unhold: exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
}
