package milter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dmilter "github.com/d--j/go-milter"
	dmessagetextproto "github.com/emersion/go-message/textproto"

	"github.com/302-digital/attachra/internal/adapters/milter"
	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/pipeline"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/rewrite"
	fsstorage "github.com/302-digital/attachra/internal/core/storage/fs"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// replaceAllPolicyYAML is a minimal "replace every attachment" policy,
// mirroring internal/core/pipeline's own processor_test.go fixture, used
// here to drive the real pipeline.AttachmentProcessor (not a fake) all
// the way through rewrite.Rewrite for the promotion-path regression test
// below.
const replaceAllPolicyYAML = `
version: 1
name: "replace everything"
rules: []
default:
  action: replace
  ttl: "7d"
`

// newRealAttachmentProcessor wires a real fs storage driver, real sqlite
// metadata store/audit sink, real link.Engine and real rewrite templates
// together — the same production-shaped components
// internal/core/pipeline's own processor_test.go harness uses — so this
// test exercises the milter adapter against rewrite.Rewrite's actual
// output rather than a hand-crafted approximation of it.
func newRealAttachmentProcessor(t *testing.T, policyYAML string) pipeline.Processor {
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
		TTL:          7 * 24 * time.Hour,
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

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	policyStore, err := policy.NewStore(policyPath)
	if err != nil {
		t.Fatalf("policy.NewStore() error = %v, want nil", err)
	}

	proc, err := pipeline.NewAttachmentProcessor(pipeline.AttachmentProcessorParams{
		PolicyStore:       policyStore,
		Storage:           drv,
		LinkEngine:        engine,
		Templates:         tmpl,
		Limits:            message.DefaultLimits(),
		MaxAttachmentSize: 10 << 20,
		PublicBaseURL:     "https://links.example.com",
		AuditSink:         st,
	})
	if err != nil {
		t.Fatalf("pipeline.NewAttachmentProcessor() error = %v, want nil", err)
	}
	return proc
}

// TestRewriteMessage_PromotionPath is the ATR-289 review's promotion-path
// regression test (docs/architecture/tech-debt.md TD-8). It reproduces
// the exact scenario internal/core/rewrite.Rewrite's
// rewriteTopLevelSinglePart handles specially: a message whose ENTIRE
// body is a single, non-multipart, replace-decided "attachment" (no
// multipart/mixed wrapper at all). Rewrite promotes such a message into
// a synthetic multipart/mixed envelope by writing a NEW "Content-Type:
// multipart/mixed; ..." line into the output stream AFTER the original
// top-level header block has already been written — so NewBody's parsed
// header block still carries the ORIGINAL (now stale) Content-Type,
// while the actual MIME structure that follows is multipart. Applied
// naively through milter's body-only ReplaceBody, this would deliver a
// message whose Content-Type header (kept by the MTA, e.g.
// "application/octet-stream") no longer matches its multipart/mixed
// body — silent, MUA-breaking corruption, not just a missing link.
//
// bodyLooksLikeHeaderBlock's fail-safe must catch this (the general
// per-header value comparison in replaceMessage cannot: the changed
// Content-Type line never appears in NewBody's parsed header block at
// all, see that function's own doc comment), so the whole message must
// come back as a true fail-open — accepted completely unmodified, i.e.
// ZERO modify actions on the wire — rather than a corrupted rewrite.
func TestRewriteMessage_PromotionPath(t *testing.T) {
	proc := newRealAttachmentProcessor(t, replaceAllPolicyYAML)
	addr := startTestServer(t, proc, func(c *milter.Config) {
		c.FailureMode = milter.FailOpen
	})

	client := dmilter.NewClient("tcp", addr, dmilter.WithAction(dmilter.AllClientSupportedActionMasks))
	sess, err := client.Session(dmilter.NewMacroBag())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close() //nolint:errcheck // best-effort cleanup

	steps := []struct {
		name string
		fn   func() (*dmilter.Action, error)
	}{
		{"conn", func() (*dmilter.Action, error) {
			return sess.Conn("test-client.example", dmilter.FamilyInet, 25, "127.0.0.1")
		}},
		{"helo", func() (*dmilter.Action, error) { return sess.Helo("test-client.example") }},
		{"mail", func() (*dmilter.Action, error) { return sess.Mail("sender@example.com", "") }},
		{"rcpt", func() (*dmilter.Action, error) { return sess.Rcpt("rcpt@example.com", "") }},
		{"data", func() (*dmilter.Action, error) { return sess.DataStart() }},
		{"header", func() (*dmilter.Action, error) {
			var hdr dmessagetextproto.Header
			// No multipart/mixed at all: the whole message is a single
			// non-multipart part with a replace-eligible disposition,
			// which is exactly what triggers rewrite's promotion path.
			hdr.Add("Subject", "single-part promotion test")
			hdr.Add("Content-Type", "application/octet-stream")
			hdr.Add("Content-Disposition", `attachment; filename="report.bin"`)
			return sess.Header(hdr)
		}},
	}
	for _, step := range steps {
		act, err := step.fn()
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if act.StopProcessing() {
			t.Fatalf("%s: unexpected stop: %v", step.name, act)
		}
	}

	const rawAttachment = "raw single-part attachment bytes, no multipart wrapper at all"
	modifyActs, act, err := sess.BodyReadFrom(strings.NewReader(rawAttachment))
	if err != nil {
		t.Fatalf("body/end: %v", err)
	}

	requireAccept(t, act)

	if len(modifyActs) != 0 {
		t.Fatalf("expected zero modify actions (true fail-open, unmodified delivery) on the promotion path, got %d: %+v", len(modifyActs), modifyActs)
	}
}
