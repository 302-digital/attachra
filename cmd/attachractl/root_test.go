package main

import (
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/store"
)

func TestVersionCommand_NeedsNoConnection(t *testing.T) {
	// version must work with no --url/--token-file/env at all — it is
	// the one command exempt from PersistentPreRunE's connection
	// resolution (root.go).
	t.Setenv("ATTACHRACTL_URL", "")
	t.Setenv("ATTACHRACTL_TOKEN", "")

	var out strings.Builder
	root, _ := newRootCmd(&out, newDiscardBuf())
	root.SetArgs([]string{"--config", "/nonexistent/config.yaml", "version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, want nil", err)
	}
	if !strings.Contains(out.String(), "attachractl") {
		t.Errorf("output = %q, want it to mention attachractl", out.String())
	}
}

func TestRun_MissingConnectionConfig(t *testing.T) {
	code, _, stderr := runCLIWithoutServer(t, "links", "list")
	if code != exitError {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitError, stderr)
	}
	if !strings.Contains(stderr, "attachractl:") {
		t.Errorf("stderr = %q, want the attachractl error prefix", stderr)
	}
}

func TestRun_Unauthorized(t *testing.T) {
	ts := newTestServer(t)

	code, _, stderr := runCLI(t, ts, "totally-bogus-secret", "links", "list")
	if code != exitUnauthorized {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitUnauthorized, stderr)
	}
}

func TestRun_InsecureFlagWarns(t *testing.T) {
	ts := newTestServer(t)
	_, secret := seedToken(t, ts, "viewer", store.RoleViewer)

	t.Setenv("ATTACHRACTL_URL", ts.URL)
	t.Setenv("ATTACHRACTL_TOKEN", secret)

	var stdout, stderr strings.Builder
	code := runMain([]string{"--config", "/nonexistent/config.yaml", "--insecure", "links", "list"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "WARNING") {
		t.Errorf("stderr = %q, want a TLS-verification warning", stderr.String())
	}
}

// newDiscardBuf returns a fresh, unshared io.Writer sink — a small
// helper so tests that do not care about one of stdout/stderr do not
// need to import io for io.Discard directly (kept local to this file
// for readability at call sites above).
func newDiscardBuf() *strings.Builder {
	return &strings.Builder{}
}

// runCLIWithoutServer runs attachractl with no ATTACHRACTL_URL/TOKEN
// set and no config file, exercising the "nothing configured" error
// path independent of any test server.
func runCLIWithoutServer(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("ATTACHRACTL_URL", "")
	t.Setenv("ATTACHRACTL_TOKEN", "")

	var outBuf, errBuf strings.Builder
	fullArgs := append([]string{"--config", "/nonexistent/config.yaml"}, args...)
	code = runMain(fullArgs, &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}
