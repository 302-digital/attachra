package pipeline_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/pipeline"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/rewrite"
	"github.com/302-digital/attachra/internal/core/storage"
	fsstorage "github.com/302-digital/attachra/internal/core/storage/fs"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// defaultTTL is the link TTL fallback used by newTestHarness's
// link.Engine when a policy leaves ttl unset.
const defaultTTL = 7 * 24 * time.Hour

// testMessage is a small, valid multipart/mixed message with one
// text/plain body part and one binary "attachment" part, used as the
// input fixture across this file's scenarios.
const testMessage = "From: sender@example.com\r\n" +
	"To: rcpt@example.com\r\n" +
	"Subject: test\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n" +
	"\r\n" +
	"--BOUNDARY\r\n" +
	"Content-Type: text/plain\r\n" +
	"\r\n" +
	"Hello, please find the report attached.\r\n" +
	"--BOUNDARY\r\n" +
	"Content-Type: application/octet-stream\r\n" +
	"Content-Disposition: attachment; filename=\"report.bin\"\r\n" +
	"Content-Transfer-Encoding: base64\r\n" +
	"\r\n" +
	"aGVsbG8gd29ybGQgYXR0YWNobWVudCBjb250ZW50\r\n" +
	"--BOUNDARY--\r\n"

// buildPolicyFile writes a minimal, valid policy YAML document to a
// temp file and returns its path.
func buildPolicyFile(t *testing.T, yamlBody string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := writeFile(path, yamlBody); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// testHarness wires a real fs storage driver, real sqlite metadata
// store (also used as the audit.AuditSink, since *sqlite.Store
// implements both), real link.Engine and real rewrite templates
// together, mirroring cmd/attachra's own production wiring but rooted
// under t.TempDir() so each test gets an isolated environment.
type testHarness struct {
	storage   storage.Driver
	link      *link.Engine
	tmpl      *rewrite.Templates
	auditSink *sqlite.Store
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	baseDir := filepath.Join(t.TempDir(), "objects")
	if err := os.MkdirAll(baseDir, 0o750); err != nil {
		t.Fatalf("mkdir base dir: %v", err)
	}
	drv, err := fsstorage.New(fsstorage.Config{BaseDir: baseDir})
	if err != nil {
		t.Fatalf("fsstorage.New() error = %v, want nil", err)
	}

	dbPath := filepath.Join(t.TempDir(), "attachra-test.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Store.Close() error = %v", err)
		}
	})

	engine, err := link.NewEngine(st, link.Defaults{
		TTL:          defaultTTL,
		MaxDownloads: 0,
		TokenBytes:   16,
	}, st)
	if err != nil {
		t.Fatalf("link.NewEngine() error = %v, want nil", err)
	}

	tmpl, err := rewrite.LoadTemplates(rewrite.TemplateConfig{})
	if err != nil {
		t.Fatalf("rewrite.LoadTemplates() error = %v, want nil", err)
	}

	return &testHarness{storage: drv, link: engine, tmpl: tmpl, auditSink: st}
}

func newProcessor(t *testing.T, h *testHarness, policyYAML string, dryRun bool) *pipeline.AttachmentProcessor {
	t.Helper()

	policyPath := buildPolicyFile(t, policyYAML)
	store, err := policy.NewStore(policyPath)
	if err != nil {
		t.Fatalf("policy.NewStore() error = %v, want nil", err)
	}

	proc, err := pipeline.NewAttachmentProcessor(pipeline.AttachmentProcessorParams{
		PolicyStore:       store,
		Storage:           h.storage,
		LinkEngine:        h.link,
		Templates:         h.tmpl,
		Limits:            message.DefaultLimits(),
		MaxAttachmentSize: 10 << 20,
		PublicBaseURL:     "https://links.example.com",
		DryRun:            dryRun,
		AuditSink:         h.auditSink,
	})
	if err != nil {
		t.Fatalf("NewAttachmentProcessor() error = %v, want nil", err)
	}
	return proc
}

const replaceAllPolicy = `
version: 1
name: "replace everything"
rules: []
default:
  action: replace
  ttl: "7d"
`

const passAllPolicy = `
version: 1
name: "pass everything"
rules: []
default:
  action: pass
`

const blockExePolicy = `
version: 1
name: "block executables"
rules:
  - name: "block exe"
    when:
      attachment:
        extension: ["bin"]
    then:
      action: block
      reason: "executable attachments are not allowed"
default:
  action: pass
`

func envelopeFor(body string) *pipeline.Envelope {
	return &pipeline.Envelope{
		Sender:     "sender@example.com",
		Recipients: []string{"rcpt@example.com"},
		QueueID:    "QID-1",
		Body:       strings.NewReader(body),
	}
}

// TestProcess_ReplaceUploadsAndRewrites is the primary end-to-end
// scenario: a replace-decided attachment must be uploaded to storage,
// have a link created for it, and the returned Verdict must carry a
// rewritten body containing the package URL.
func TestProcess_ReplaceUploadsAndRewrites(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(testMessage))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite", verdict.Action)
	}
	if verdict.NewBody == nil {
		t.Fatal("verdict.NewBody = nil, want a rewritten body")
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	rewrittenStr := string(rewritten)

	if strings.Contains(rewrittenStr, "aGVsbG8gd29ybGQ") {
		t.Error("rewritten body still contains the original attachment's base64 content, want it removed")
	}
	if !strings.Contains(rewrittenStr, "https://links.example.com/p/") {
		t.Errorf("rewritten body does not contain the expected package URL prefix:\n%s", rewrittenStr)
	}
	if !strings.Contains(rewrittenStr, "report.bin") {
		t.Error("rewritten body does not mention the replaced attachment's file name")
	}
}

// TestProcess_PassPolicyLeavesMessageUntouched verifies that when
// every attachment decides pass, Process returns VerdictAccept and
// never touches storage.
func TestProcess_PassPolicyLeavesMessageUntouched(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessor(t, h, passAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(testMessage))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictAccept {
		t.Errorf("verdict.Action = %v, want VerdictAccept", verdict.Action)
	}
	if verdict.NewBody != nil {
		t.Error("verdict.NewBody != nil for a pass-only decision, want nil")
	}
}

// TestProcess_BlockPolicyRejectsMessage verifies that a block decision
// produces VerdictReject with the policy's reason, and never reaches
// storage/link/rewrite.
func TestProcess_BlockPolicyRejectsMessage(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessor(t, h, blockExePolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(testMessage))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictReject {
		t.Fatalf("verdict.Action = %v, want VerdictReject", verdict.Action)
	}
	if !strings.Contains(verdict.Reason, "executable") {
		t.Errorf("verdict.Reason = %q, want it to mention the policy's reason", verdict.Reason)
	}
}

// TestProcess_DryRunAcceptsButWouldHaveReplaced verifies that dry-run
// mode always accepts the message unmodified even though the policy
// would have replaced the attachment, per US-4.2/T-4.2.2 and
// policy.ApplyModeToMessage's contract.
func TestProcess_DryRunAcceptsButWouldHaveReplaced(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, true)

	verdict, err := proc.Process(context.Background(), envelopeFor(testMessage))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictAccept {
		t.Errorf("verdict.Action = %v, want VerdictAccept (dry-run must never replace/block)", verdict.Action)
	}
}

// TestNewAttachmentProcessor_RequiresDependencies verifies the
// constructor rejects a missing required dependency instead of
// producing a processor that would panic or misbehave later, since
// community-edition passthrough (no policy configured at all) is
// handled by cmd/attachra choosing PassthroughProcessor instead of
// constructing an AttachmentProcessor in the first place.
func TestNewAttachmentProcessor_RequiresDependencies(t *testing.T) {
	h := newTestHarness(t)
	policyPath := buildPolicyFile(t, passAllPolicy)
	store, err := policy.NewStore(policyPath)
	if err != nil {
		t.Fatalf("policy.NewStore() error = %v, want nil", err)
	}

	base := pipeline.AttachmentProcessorParams{
		PolicyStore: store,
		Storage:     h.storage,
		LinkEngine:  h.link,
		Templates:   h.tmpl,
	}

	tests := []struct {
		name   string
		modify func(p *pipeline.AttachmentProcessorParams)
	}{
		{"nil PolicyStore", func(p *pipeline.AttachmentProcessorParams) { p.PolicyStore = nil }},
		{"nil Storage", func(p *pipeline.AttachmentProcessorParams) { p.Storage = nil }},
		{"nil LinkEngine", func(p *pipeline.AttachmentProcessorParams) { p.LinkEngine = nil }},
		{"nil Templates", func(p *pipeline.AttachmentProcessorParams) { p.Templates = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := base
			tt.modify(&p)
			if _, err := pipeline.NewAttachmentProcessor(p); err == nil {
				t.Errorf("NewAttachmentProcessor() error = nil, want an error for %s", tt.name)
			}
		})
	}
}

// errStorage wraps a storage.Driver and fails every Nth Put call (1
// == fail immediately), to exercise Process's behavior when storage
// fails partway through a multi-attachment upload.
type errStorage struct {
	storage.Driver
	failAfter int // Put calls after which failures start (0 == fail on first call).
	mu        sync.Mutex
	calls     int
	puts      []string // keys successfully Put, for asserting rollback.
}

func (e *errStorage) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	e.mu.Lock()
	e.calls++
	call := e.calls
	e.mu.Unlock()

	if call > e.failAfter {
		return fmt.Errorf("errStorage: simulated failure on call %d", call)
	}
	if err := e.Driver.Put(ctx, key, r, size); err != nil {
		return err
	}
	e.mu.Lock()
	e.puts = append(e.puts, key)
	e.mu.Unlock()
	return nil
}

// TestProcess_StorageFailureReturnsErrorNotAccept verifies invariant
// #3's core contract for this task: a storage failure must surface as
// a Go error from Process (which the milter adapter then resolves
// into fail-open/fail-closed), never as a silent VerdictAccept that
// would lose the intended replace action, and never as a
// VerdictRewrite with a partially-uploaded/broken link.
func TestProcess_StorageFailureReturnsErrorNotAccept(t *testing.T) {
	h := newTestHarness(t)
	failing := &errStorage{Driver: h.storage, failAfter: 0}
	h.storage = failing

	policyPath := buildPolicyFile(t, replaceAllPolicy)
	store, err := policy.NewStore(policyPath)
	if err != nil {
		t.Fatalf("policy.NewStore() error = %v, want nil", err)
	}

	proc, err := pipeline.NewAttachmentProcessor(pipeline.AttachmentProcessorParams{
		PolicyStore:       store,
		Storage:           failing,
		LinkEngine:        h.link,
		Templates:         h.tmpl,
		Limits:            message.DefaultLimits(),
		MaxAttachmentSize: 10 << 20,
		PublicBaseURL:     "https://links.example.com",
	})
	if err != nil {
		t.Fatalf("NewAttachmentProcessor() error = %v, want nil", err)
	}

	verdict, err := proc.Process(context.Background(), envelopeFor(testMessage))
	if err == nil {
		t.Fatalf("Process() error = nil, want a storage error; verdict = %+v", verdict)
	}
	if verdict != nil {
		t.Errorf("Process() verdict = %+v, want nil on error", verdict)
	}
}

// TestProcess_PartialStorageFailureRollsBackUploads exercises a
// message with two replace-decided attachments where the first Put
// succeeds and the second fails: Process must return an error (not a
// rewrite with a dangling link for only the first attachment) and must
// roll back (delete) the first attachment's already-uploaded object,
// so no orphaned blob survives a failed message.
func TestProcess_PartialStorageFailureRollsBackUploads(t *testing.T) {
	const twoAttachmentMessage = "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n" +
		"\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Two attachments below.\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"first.bin\"\r\n" +
		"\r\n" +
		"first content\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"second.bin\"\r\n" +
		"\r\n" +
		"second content\r\n" +
		"--BOUNDARY--\r\n"

	h := newTestHarness(t)
	failing := &errStorage{Driver: h.storage, failAfter: 1}

	policyPath := buildPolicyFile(t, replaceAllPolicy)
	store, err := policy.NewStore(policyPath)
	if err != nil {
		t.Fatalf("policy.NewStore() error = %v, want nil", err)
	}

	proc, err := pipeline.NewAttachmentProcessor(pipeline.AttachmentProcessorParams{
		PolicyStore:       store,
		Storage:           failing,
		LinkEngine:        h.link,
		Templates:         h.tmpl,
		Limits:            message.DefaultLimits(),
		MaxAttachmentSize: 10 << 20,
		PublicBaseURL:     "https://links.example.com",
	})
	if err != nil {
		t.Fatalf("NewAttachmentProcessor() error = %v, want nil", err)
	}

	verdict, err := proc.Process(context.Background(), envelopeFor(twoAttachmentMessage))
	if err == nil {
		t.Fatalf("Process() error = nil, want a storage error; verdict = %+v", verdict)
	}

	failing.mu.Lock()
	uploadedKeys := append([]string(nil), failing.puts...)
	failing.mu.Unlock()

	if len(uploadedKeys) != 1 {
		t.Fatalf("expected exactly one successful Put before the simulated failure, got %d", len(uploadedKeys))
	}

	// The single object that did succeed must have been rolled back
	// (deleted) by Process's cleanup, since the overall message failed.
	if _, statErr := h.storage.Stat(context.Background(), uploadedKeys[0]); !errors.Is(statErr, storage.ErrNotFound) {
		t.Errorf("Stat(%q) after rollback error = %v, want wrapping storage.ErrNotFound", uploadedKeys[0], statErr)
	}
}

// TestProcess_NoRecipientsWithReplaceDecisionErrors verifies that a
// replace decision with zero envelope recipients (which would leave
// link.Engine.CreateLinks with nothing to build per-recipient tokens
// for) surfaces as an error rather than silently accepting or
// panicking.
func TestProcess_NoRecipientsWithReplaceDecisionErrors(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	env := &pipeline.Envelope{
		Sender:     "sender@example.com",
		Recipients: nil,
		QueueID:    "QID-2",
		Body:       strings.NewReader(testMessage),
	}

	verdict, err := proc.Process(context.Background(), env)
	if err == nil {
		t.Fatalf("Process() error = nil, want an error for replace decision with no recipients; verdict = %+v", verdict)
	}
}

// TestProcess_EmptyBodyAccepts verifies Process degrades gracefully
// (VerdictAccept, no error) when Envelope.Body is nil, matching
// PassthroughProcessor's behavior for the same edge case.
func TestProcess_EmptyBodyAccepts(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	env := &pipeline.Envelope{
		Sender:     "sender@example.com",
		Recipients: []string{"rcpt@example.com"},
		QueueID:    "QID-3",
		Body:       nil,
	}

	verdict, err := proc.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictAccept {
		t.Errorf("verdict.Action = %v, want VerdictAccept", verdict.Action)
	}
}

// TestProcess_OversizedAttachmentErrors verifies that an attachment
// exceeding AttachmentProcessorParams.MaxAttachmentSize surfaces as a
// Process error (which the milter adapter resolves into
// fail-open/fail-closed) rather than being silently accepted or
// truncated — CLAUDE.md invariant #3 forbids resolving a limit
// violation into a silent pass, and #4 forbids buffering past the
// configured bound.
func TestProcess_OversizedAttachmentErrors(t *testing.T) {
	h := newTestHarness(t)

	policyPath := buildPolicyFile(t, replaceAllPolicy)
	store, err := policy.NewStore(policyPath)
	if err != nil {
		t.Fatalf("policy.NewStore() error = %v, want nil", err)
	}

	proc, err := pipeline.NewAttachmentProcessor(pipeline.AttachmentProcessorParams{
		PolicyStore:       store,
		Storage:           h.storage,
		LinkEngine:        h.link,
		Templates:         h.tmpl,
		Limits:            message.DefaultLimits(),
		MaxAttachmentSize: 8, // Smaller than the ~30-byte decoded attachment in testMessage.
		PublicBaseURL:     "https://links.example.com",
	})
	if err != nil {
		t.Fatalf("NewAttachmentProcessor() error = %v, want nil", err)
	}

	verdict, err := proc.Process(context.Background(), envelopeFor(testMessage))
	if err == nil {
		t.Fatalf("Process() error = nil, want an error for an oversized attachment; verdict = %+v", verdict)
	}
}
