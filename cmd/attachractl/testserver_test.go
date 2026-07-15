package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	adapterhttp "github.com/302-digital/attachra/internal/adapters/http"
	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// defaultTestPolicyYAML is the active policy loaded for every test
// server: a single rule blocking ".exe" attachments, falling back to
// pass otherwise, so `policy current`/`policy dry-run` have a
// non-trivial rule to exercise, and `policy reload` has somewhere to
// reload from (mirrors internal/adapters/http/policies_test.go's own
// fixture).
const defaultTestPolicyYAML = `
version: 1
name: "test-policy"
rules:
  - name: "block executables"
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
      reason: "no executables"
default:
  action: pass
`

// testServer bundles everything a command test needs: a running
// httptest.Server backed by a real adapterhttp.APIHandler (exactly the
// production wiring, not a mock), the underlying sqlite store to seed
// fixtures directly, and the policy file path so reload tests can
// rewrite it.
type testServer struct {
	URL        string
	store      *sqlite.Store
	policyPath string
}

// newTestServer builds a fresh, isolated Attachra API server for one
// test: a temp-file sqlite store, a link.Engine over it, a
// *policy.Store loaded from a temp policy file, and the real
// APIHandler wired exactly as cmd/attachra/main.go wires it in
// production. This is deliberately the same "real handler over
// httptest" pattern internal/adapters/http's own tests use
// (api_test.go's newAPITestServer) — attachractl's tests exercise the
// client and command layer against the genuine contract
// implementation, not a hand-rolled stub that could silently drift
// from it.
func newTestServer(t *testing.T) *testServer {
	t.Helper()

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "attachractl-test.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New()

	linkEngine, err := link.NewEngine(st, link.Defaults{
		TTL:          72 * time.Hour,
		MaxDownloads: 0,
		TokenBytes:   link.MinTokenBytes,
	}, st)
	if err != nil {
		t.Fatalf("link.NewEngine() error = %v", err)
	}

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(defaultTestPolicyYAML), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	policyStore, err := policy.NewStore(policyPath)
	if err != nil {
		t.Fatalf("policy.NewStore() error = %v", err)
	}

	api := adapterhttp.NewAPIHandler(st, st, linkEngine, policyStore, logger, st, st, m, adapterhttp.APIConfig{
		AuthFailuresPerMinute: 1000,
		AuthFailuresBurst:     1000,
	})

	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)

	return &testServer{URL: ts.URL, store: st, policyPath: policyPath}
}

// seedToken mints a token of the given role directly in the test
// server's store and returns its raw secret — the value a client
// sends as its Bearer credential, mirroring
// internal/adapters/http/api_test.go's own seedToken helper.
func seedToken(t *testing.T, ts *testServer, name string, role store.Role) (id, secret string) {
	t.Helper()

	id, err := store.NewTokenID()
	if err != nil {
		t.Fatalf("NewTokenID() error = %v", err)
	}
	secret, hash, err := store.GenerateAPISecret(store.MinAPISecretBytes)
	if err != nil {
		t.Fatalf("GenerateAPISecret() error = %v", err)
	}
	if err := ts.store.CreateAPIToken(context.Background(), store.NewAPITokenParams{
		ID: id, Name: name, Role: role, TokenHash: hash,
	}); err != nil {
		t.Fatalf("CreateAPIToken() error = %v", err)
	}
	return id, secret
}

// seedLink creates a Message + one Attachment + one Link directly
// against ts's store (there is no HTTP endpoint that creates a link —
// that only happens via the milter pipeline/link.Engine.CreateLinks),
// mirroring internal/adapters/http/links_test.go's own seedLink
// helper, for tests that only need to read/mutate an existing link
// through the CLI.
func seedLink(t *testing.T, ts *testServer, messageID, linkID, recipient string) {
	t.Helper()
	ctx := context.Background()

	if err := ts.store.CreateMessage(ctx, store.NewMessageParams{
		ID:      messageID,
		QueueID: "queue-" + messageID,
		Sender:  "sender@example.com",
	}); err != nil {
		if _, getErr := ts.store.GetMessage(ctx, messageID); getErr != nil {
			t.Fatalf("CreateMessage(%q) error = %v, want nil", messageID, err)
		}
	}

	attachmentID := linkID + "-att"
	if err := ts.store.CreateAttachment(ctx, store.NewAttachmentParams{
		ID:           attachmentID,
		MessageID:    messageID,
		PartRef:      "1",
		Filename:     "report.pdf",
		DeclaredType: "application/pdf",
		DetectedType: "application/pdf",
		Size:         1024,
		StorageKey:   "ab/" + linkID,
	}); err != nil {
		t.Fatalf("CreateAttachment(%q) error = %v, want nil", attachmentID, err)
	}

	if err := ts.store.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           linkID,
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    recipient,
		TokenHash:    "hash-" + linkID,
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano),
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink(%q) error = %v, want nil", linkID, err)
	}
}

// runCLI executes the attachractl command tree with args against ts,
// authenticated as the given token secret (ATTACHRACTL_TOKEN env,
// never a flag — matching production's own rule), returning the exit
// code and captured stdout/stderr. baseArgs are prepended so a test can
// add --json etc.
func runCLI(t *testing.T, ts *testServer, tokenSecret string, args ...string) (code int, stdout, stderr string) {
	t.Helper()

	t.Setenv("ATTACHRACTL_URL", ts.URL)
	t.Setenv("ATTACHRACTL_TOKEN", tokenSecret)

	var outBuf, errBuf bytes.Buffer
	// --config points at a nonexistent path so no real
	// ~/.config/attachractl/config.yaml on the test-running machine can
	// leak into (or fail) the test.
	fullArgs := append([]string{"--config", filepath.Join(t.TempDir(), "does-not-exist.yaml")}, args...)
	code = runMain(fullArgs, &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}
