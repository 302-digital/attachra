package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// newTokenTestStore opens a fresh sqlite store under t.TempDir() for the
// `attachra token` subcommand tests (ATR-201).
func newTokenTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "token-cli-test.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestTokenCreateHappyPath(t *testing.T) {
	st := newTokenTestStore(t)
	var stdout, stderr bytes.Buffer

	code := runTokenCommand([]string{"create", "--name", "ci-runner", "--role", "admin", "--actor", "bootstrap-operator"}, st, st, &stdout, &stderr)
	if code != tokenOK {
		t.Fatalf("runTokenCommand() = %d, want %d; stderr=%s", code, tokenOK, stderr.String())
	}

	secret := strings.TrimSpace(stdout.String())
	if secret == "" {
		t.Fatalf("no secret printed to stdout")
	}

	// The printed secret must authenticate: its hash resolves to an active
	// admin token in the store.
	tok, err := st.LookupActiveAPIToken(context.Background(), store.HashAPISecret(secret))
	if err != nil {
		t.Fatalf("LookupActiveAPIToken() with printed secret error = %v, want nil", err)
	}
	if tok.Name != "ci-runner" || tok.Role != store.RoleAdmin {
		t.Errorf("stored token = %+v, want name=ci-runner role=admin", tok)
	}

	// The raw secret must never appear in the stored hash (invariant #5).
	if tok.TokenHash == secret {
		t.Errorf("stored TokenHash equals the raw secret, want a hash")
	}
	if strings.Contains(stderr.String(), secret) {
		t.Errorf("stderr leaked the raw secret")
	}
}

// TestTokenCreateRecordsAuditEvent verifies `attachra token create`
// records a TypeTokenChange audit event attributed to the --actor flag,
// carrying the new token's id/name/role and never its secret or hash
// (ATR-296, SR-128-2, invariant #5).
func TestTokenCreateRecordsAuditEvent(t *testing.T) {
	st := newTokenTestStore(t)
	var stdout, stderr bytes.Buffer

	code := runTokenCommand([]string{"create", "--name", "ci-runner", "--role", "admin", "--actor", "bootstrap-operator"}, st, st, &stdout, &stderr)
	if code != tokenOK {
		t.Fatalf("runTokenCommand() = %d, want %d; stderr=%s", code, tokenOK, stderr.String())
	}
	secret := strings.TrimSpace(stdout.String())
	tok, err := st.LookupActiveAPIToken(context.Background(), store.HashAPISecret(secret))
	if err != nil {
		t.Fatalf("LookupActiveAPIToken() error = %v, want nil", err)
	}

	var got []audit.Recorded
	if err := st.StreamEvents(context.Background(), audit.Filter{}, func(r audit.Recorded) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}

	var found bool
	for _, ev := range got {
		if ev.Type != audit.TypeTokenChange || ev.Details["token_id"] != tok.ID {
			continue
		}
		found = true
		if ev.Actor != "bootstrap-operator" {
			t.Errorf("event Actor = %q, want %q", ev.Actor, "bootstrap-operator")
		}
		if ev.Details["action"] != "create" {
			t.Errorf("event Details[action] = %v, want create", ev.Details["action"])
		}
		if ev.Details["name"] != "ci-runner" {
			t.Errorf("event Details[name] = %v, want ci-runner", ev.Details["name"])
		}
		if ev.Details["role"] != "admin" {
			t.Errorf("event Details[role] = %v, want admin", ev.Details["role"])
		}
		for _, v := range ev.Details {
			if s, ok := v.(string); ok && s == secret {
				t.Fatalf("event Details = %+v contains the raw secret, want none", ev.Details)
			}
			if s, ok := v.(string); ok && s == tok.TokenHash {
				t.Fatalf("event Details = %+v contains the token hash, want none", ev.Details)
			}
		}
	}
	if !found {
		t.Fatalf("no TypeTokenChange event found for token %q among %d events: %+v", tok.ID, len(got), got)
	}
}

func TestTokenCreateValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no subcommand", []string{}},
		{"unknown subcommand", []string{"frobnicate"}},
		{"missing name", []string{"create", "--role", "viewer", "--actor", "op"}},
		{"missing role", []string{"create", "--name", "x", "--actor", "op"}},
		{"missing actor", []string{"create", "--name", "x", "--role", "viewer"}},
		{"bad role", []string{"create", "--name", "x", "--role", "root", "--actor", "op"}},
		{"stray positional", []string{"create", "--name", "x", "--role", "viewer", "--actor", "op", "extra"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newTokenTestStore(t)
			var stdout, stderr bytes.Buffer
			if code := runTokenCommand(tc.args, st, st, &stdout, &stderr); code != tokenError {
				t.Errorf("runTokenCommand(%v) = %d, want %d", tc.args, code, tokenError)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q on a failed create, want empty (no secret emitted)", stdout.String())
			}
		})
	}
}

func TestTokenCreateEachRole(t *testing.T) {
	for _, role := range []string{"admin", "viewer", "auditor"} {
		t.Run(role, func(t *testing.T) {
			st := newTokenTestStore(t)
			var stdout, stderr bytes.Buffer
			if code := runTokenCommand([]string{"create", "--name", role + "-tok", "--role", role, "--actor", "op"}, st, st, &stdout, &stderr); code != tokenOK {
				t.Fatalf("create %s: code = %d, stderr=%s", role, code, stderr.String())
			}
			secret := strings.TrimSpace(stdout.String())
			tok, err := st.LookupActiveAPIToken(context.Background(), store.HashAPISecret(secret))
			if err != nil {
				t.Fatalf("lookup %s token error = %v", role, err)
			}
			if string(tok.Role) != role {
				t.Errorf("role = %q, want %q", tok.Role, role)
			}
		})
	}
}
