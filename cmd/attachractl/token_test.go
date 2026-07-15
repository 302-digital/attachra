package main

import (
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/store"
)

func TestTokenCreate(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "bootstrap-admin", store.RoleAdmin)

	code, stdout, stderr := runCLI(t, ts, secret, "token", "create", "--name", "ci-bot", "--role", "viewer")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	rawSecret := strings.TrimSpace(stdout)
	if rawSecret == "" {
		t.Fatalf("stdout = %q, want the raw secret on stdout", stdout)
	}
	if strings.Contains(rawSecret, "\n") {
		t.Errorf("stdout contains more than the secret: %q", stdout)
	}
	if !strings.Contains(stderr, "ci-bot") {
		t.Errorf("stderr = %q, want the token name in the confirmation line", stderr)
	}
	if strings.Contains(stderr, rawSecret) {
		t.Errorf("stderr must never contain the secret, got %q", stderr)
	}
}

func TestTokenCreate_RequiresNameAndRole(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)

	code, _, stderr := runCLI(t, ts, secret, "token", "create", "--role", "viewer")
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitUsage, stderr)
	}

	code, _, stderr = runCLI(t, ts, secret, "token", "create", "--name", "x")
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitUsage, stderr)
	}
}

func TestTokenCreate_RequiresAdmin(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	code, _, stderr := runCLI(t, ts, secret, "token", "create", "--name", "x", "--role", "viewer")
	if code != exitForbidden {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitForbidden, stderr)
	}
}

func TestTokenList(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)
	seedToken(t, ts, "viewer-1", store.RoleViewer)
	seedToken(t, ts, "auditor-1", store.RoleAuditor)

	code, stdout, stderr := runCLI(t, ts, secret, "token", "list")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	for _, name := range []string{"admin", "viewer-1", "auditor-1"} {
		if !strings.Contains(stdout, name) {
			t.Errorf("stdout = %q, want token %q listed", stdout, name)
		}
	}
}

func TestTokenRevoke(t *testing.T) {
	ts := newTestServer(t)
	adminID, secret := seedToken(t, ts, "admin", store.RoleAdmin)
	victimID, _ := seedToken(t, ts, "throwaway", store.RoleViewer)
	_ = adminID

	code, stdout, stderr := runCLI(t, ts, secret, "token", "revoke", victimID)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "revoked") {
		t.Errorf("stdout = %q, want a revoke confirmation", stdout)
	}
}

func TestTokenRevoke_NotFound(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "admin", store.RoleAdmin)

	code, _, stderr := runCLI(t, ts, secret, "token", "revoke", "no-such-token-id")
	if code != exitNotFound {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitNotFound, stderr)
	}
}
