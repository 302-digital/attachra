package milter_test

import (
	"bytes"
	"io"
	"mime"
	"net/mail"
	"net/textproto"
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
	}, st, nil)
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

// TestRewriteMessage_PromotionPath is the ATR-290/291 promotion-path
// regression test (ATR-291). It reproduces
// the exact scenario internal/core/rewrite.Rewrite's
// rewriteTopLevelSinglePart handles specially: a message whose ENTIRE
// body is a single, non-multipart, replace-decided "attachment" (no
// multipart/mixed wrapper at all). Rewrite promotes such a message into a
// synthetic multipart/mixed envelope, changing the top-level Content-Type
// in place and dropping the promoted single part's stale content headers.
//
// After ATR-291 (Content-Type kept inside NewBody's header block) and
// ATR-290 (this adapter applying that change via milter ChangeHeader),
// the promotion path must now WORK end-to-end rather than fail open. This
// test asserts the milter PROTOCOL semantics directly — a ChangeHeader
// for Content-Type, a delete (ChangeHeader with empty value) for the
// dropped Content-Disposition, and a ReplaceBody — and then reconstructs
// the message the MTA would deliver (original headers with those
// modifications applied, plus the replaced body) and verifies it is a
// valid multipart/mixed message carrying the replacement link.
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

	// The headers the MTA holds, in arrival order, mirrored below when
	// reconstructing the delivered message.
	origHeaders := []hdrKV{
		{"Subject", "single-part promotion test"},
		{"Content-Type", "application/octet-stream"},
		{"Content-Disposition", `attachment; filename="report.bin"`},
	}

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
			for _, h := range origHeaders {
				hdr.Add(h.name, h.value)
			}
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

	// --- Protocol-level assertions (the ATR-290 mechanism). ---
	var (
		sawContentTypeChange bool
		sawDispositionDelete bool
		sawReplaceBody       bool
		replacedBody         []byte
	)
	for _, ma := range modifyActs {
		switch ma.Type {
		case dmilter.ActionChangeHeader:
			switch textproto.CanonicalMIMEHeaderKey(ma.HeaderName) {
			case "Content-Type":
				if ma.HeaderValue == "" {
					t.Errorf("Content-Type must be CHANGED, not deleted: %+v", ma)
				}
				mt, _, perr := mime.ParseMediaType(ma.HeaderValue)
				if perr != nil || mt != "multipart/mixed" {
					t.Errorf("ChangeHeader Content-Type = %q (mt=%q err=%v), want multipart/mixed", ma.HeaderValue, mt, perr)
				}
				if ma.HeaderIndex != 1 {
					t.Errorf("ChangeHeader Content-Type index = %d, want 1 (the single original occurrence)", ma.HeaderIndex)
				}
				sawContentTypeChange = true
			case "Content-Disposition":
				if ma.HeaderValue != "" {
					t.Errorf("Content-Disposition must be DELETED (empty value), got %q", ma.HeaderValue)
				}
				sawDispositionDelete = true
			}
		case dmilter.ActionReplaceBody:
			sawReplaceBody = true
			replacedBody = append(replacedBody, ma.Body...)
		}
	}
	if !sawContentTypeChange {
		t.Error("expected a ChangeHeader modify action promoting Content-Type to multipart/mixed (ATR-290)")
	}
	if !sawDispositionDelete {
		t.Error("expected a ChangeHeader delete of the dropped Content-Disposition")
	}
	if !sawReplaceBody {
		t.Error("expected a ReplaceBody modify action")
	}

	// --- End-to-end: reconstruct and validate the delivered message. ---
	delivered := applyModifyActions(t, origHeaders, modifyActs, replacedBody)

	msg, err := mail.ReadMessage(bytes.NewReader(delivered))
	if err != nil {
		t.Fatalf("delivered message did not parse: %v\n--- delivered ---\n%s", err, delivered)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Fatalf("delivered Content-Type = %q (mt=%q err=%v), want multipart/mixed", msg.Header.Get("Content-Type"), mt, err)
	}
	if params["boundary"] == "" {
		t.Fatalf("delivered multipart/mixed has no boundary parameter")
	}
	if got := msg.Header.Get("Content-Disposition"); got != "" {
		t.Errorf("delivered message still carries the dropped Content-Disposition: %q", got)
	}
	if got := msg.Header.Get("Subject"); got != "single-part promotion test" {
		t.Errorf("Subject not preserved through promotion: %q", got)
	}

	// The whole reconstructed message must re-parse as valid MIME via the
	// codebase parser, and the original attachment bytes must be gone.
	if err := message.Parse(bytes.NewReader(delivered), message.DefaultLimits(), func(_ *message.Attachment, body io.Reader) error {
		_, cerr := io.Copy(io.Discard, body)
		return cerr
	}); err != nil {
		t.Fatalf("delivered message failed to re-parse as valid MIME: %v\n--- delivered ---\n%s", err, delivered)
	}
	if bytes.Contains(delivered, []byte(rawAttachment)) {
		t.Errorf("dropped attachment bytes still present in the delivered message:\n%s", delivered)
	}
	if !bytes.Contains(delivered, []byte("links.example.com")) {
		t.Errorf("delivered message does not carry the replacement package link:\n%s", delivered)
	}
}

// applyModifyActions reconstructs the RFC 5322 message the MTA would
// deliver by applying the milter ModifyActions (AddHeader / ChangeHeader /
// delete) to the original header list in arrival order, then appending
// the replaced body. It reimplements only the header semantics this
// adapter exercises: single-occurrence Change and delete plus AddHeader
// (append), which is enough to validate the promotion path faithfully.
func applyModifyActions(t *testing.T, orig []hdrKV, actions []dmilter.ModifyAction, body []byte) []byte {
	t.Helper()

	headers := make([]hdrKV, len(orig))
	copy(headers, orig)

	nthIndex := func(name string, idx uint32) int {
		canon := textproto.CanonicalMIMEHeaderKey(name)
		count := uint32(0)
		for i, h := range headers {
			if textproto.CanonicalMIMEHeaderKey(h.name) == canon {
				count++
				if count == idx {
					return i
				}
			}
		}
		return -1
	}

	for _, ma := range actions {
		switch ma.Type {
		case dmilter.ActionAddHeader:
			headers = append(headers, hdrKV{name: ma.HeaderName, value: ma.HeaderValue})
		case dmilter.ActionChangeHeader:
			pos := nthIndex(ma.HeaderName, ma.HeaderIndex)
			if pos < 0 {
				t.Fatalf("ChangeHeader references missing header %q[%d]", ma.HeaderName, ma.HeaderIndex)
			}
			if ma.HeaderValue == "" {
				headers = append(headers[:pos], headers[pos+1:]...)
			} else {
				headers[pos].value = ma.HeaderValue
			}
		}
	}

	var buf bytes.Buffer
	for _, h := range headers {
		buf.WriteString(h.name)
		buf.WriteString(": ")
		buf.WriteString(h.value)
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}
