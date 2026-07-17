package pipeline_test

// Tests in this file cover ADR-016 (ATR-305: inline/CID attachment
// protection) and its companion fix ATR-306 (structural body parts are
// never replace candidates), end to end through
// pipeline.AttachmentProcessor.Process. See docs/Attachra_ADR.md
// ADR-016 for the full design and docs/architecture/policy-format-v1.md
// §2.3.2 for the `disposition` matcher grammar.
//
// Fixtures are numbered (comment "Fixture N") to trace back to the
// design's original 10+1 required scenarios plus the additions from
// the architect/security review of the first version of this change
// (fixtures 12-15): that review's BLOCKER found that an earlier
// version of the ATR-306 fix skipped structural body parts before
// policy.Evaluate entirely, which silently defeated detected-type/
// block enforcement on anything shaped like a message body (e.g. ZIP
// bytes declared `Content-Type: text/plain`). The fix now evaluates
// every part unconditionally and only downgrades a REPLACE verdict —
// see pipeline.protectStructuralBodies. Fixtures 14-15 exist
// specifically to pin that fix down.
//
// Fixture 8 (Content-ID normalization / InlineAsset classification
// across mixed/related/alternative nesting) lives in
// internal/core/message/parser_test.go, since it is a pure parser
// concern with no pipeline/policy involvement.

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/pipeline"
	"github.com/302-digital/attachra/internal/core/policy"
)

// pngMagicBytes is the 8-byte PNG signature (RFC unofficial, WHATWG
// MIME Sniffing / net/http's own sniffer table) that makes
// message.DetectType report "image/png" for content starting with it.
var pngMagicBytes = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// pngPayload returns totalSize decoded bytes starting with
// pngMagicBytes followed by a distinctive ASCII marker and zero
// padding, so tests can both assert DetectType == "image/png" and
// search the rewritten message for the marker to prove the payload
// survived (or was removed).
func pngPayload(t *testing.T, totalSize int) []byte {
	t.Helper()
	const marker = "PNGDATAMARKER"
	if totalSize < len(pngMagicBytes)+len(marker) {
		t.Fatalf("pngPayload: totalSize %d too small for magic+marker", totalSize)
	}
	b := make([]byte, totalSize)
	copy(b, pngMagicBytes)
	copy(b[len(pngMagicBytes):], marker)
	return b
}

// zipMasqueradingAsPNG returns content whose magic bytes are a ZIP
// local file header ("PK\x03\x04", message.DetectType ->
// "application/zip") even though the part's declared Content-Type
// will be image/png, simulating a masquerading/mislabeled attachment.
func zipMasqueradingAsPNG() []byte {
	b := []byte{'P', 'K', 0x03, 0x04}
	return append(b, []byte("ZIPDATAMARKER")...)
}

// b64 base64-encodes payload for embedding as a part body with
// Content-Transfer-Encoding: base64, matching this repo's existing
// testdata/*.eml fixture convention (a single unwrapped line, which
// encoding/base64's streaming Decoder requires — embedded newlines are
// not tolerated).
func b64(payload []byte) string {
	return base64.StdEncoding.EncodeToString(payload)
}

// newProcessorWithInlineMaxSize mirrors newProcessor (processor_test.go)
// but sets AttachmentProcessorParams.InlineMaxSize explicitly, for
// tests that need a small threshold to keep fixtures small (rather
// than generating a real >256KB message to exceed the default).
func newProcessorWithInlineMaxSize(t *testing.T, h *testHarness, policyYAML string, inlineMaxSize int64) *pipeline.AttachmentProcessor {
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
		InlineMaxSize:     inlineMaxSize,
		PublicBaseURL:     "https://links.example.com",
		AuditSink:         h.auditSink,
	})
	if err != nil {
		t.Fatalf("NewAttachmentProcessor() error = %v, want nil", err)
	}
	return proc
}

// newProcessorWithDryRunLogger mirrors newProcessor but wires a custom
// *slog.Logger and forces dry-run mode, for asserting the exact text
// of policy.ApplyMode's structured dry-run log record (fixture 13).
func newProcessorWithDryRunLogger(t *testing.T, h *testHarness, policyYAML string, logger *slog.Logger) *pipeline.AttachmentProcessor {
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
		DryRun:            true,
		Logger:            logger,
		AuditSink:         h.auditSink,
	})
	if err != nil {
		t.Fatalf("NewAttachmentProcessor() error = %v, want nil", err)
	}
	return proc
}

// newProcessorWithLogger mirrors newProcessor but wires a custom
// *slog.Logger (NOT dry-run), for asserting Process's own log output —
// e.g. the B2 cid-scan gate's Debug-level "skipped" line (fixtures
// 21/22), which newProcessorWithDryRunLogger's forced DryRun mode would
// otherwise short-circuit before Process ever reaches.
func newProcessorWithLogger(t *testing.T, h *testHarness, policyYAML string, logger *slog.Logger) *pipeline.AttachmentProcessor {
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
		Logger:            logger,
		AuditSink:         h.auditSink,
	})
	if err != nil {
		t.Fatalf("NewAttachmentProcessor() error = %v, want nil", err)
	}
	return proc
}

// protectedPartPaths extracts a policy_decision audit detail keyed
// detailKey (either "inline_protected" or "body_protected" — both a
// []interface{} of part path strings after the sqlite AuditSink's
// JSON round trip) from every policy_decision event in got, in event
// order.
func protectedPartPaths(t *testing.T, got []audit.Recorded, detailKey string) [][]any {
	t.Helper()
	var out [][]any
	for _, e := range got {
		if e.Type != audit.TypePolicyDecision {
			continue
		}
		v, ok := e.Details[detailKey]
		if !ok {
			continue
		}
		list, ok := v.([]any)
		if !ok {
			t.Fatalf("policy_decision Details[%s] has unexpected type %T: %v", detailKey, v, v)
		}
		out = append(out, list)
	}
	return out
}

// inlineProtectedPartPaths extracts the "inline_protected" detail from
// every policy_decision event in got, in event order.
func inlineProtectedPartPaths(t *testing.T, got []audit.Recorded) [][]any {
	t.Helper()
	return protectedPartPaths(t, got, "inline_protected")
}

// bodyProtectedPartPaths extracts the "body_protected" detail from
// every policy_decision event in got, in event order.
func bodyProtectedPartPaths(t *testing.T, got []audit.Recorded) [][]any {
	t.Helper()
	return protectedPartPaths(t, got, "body_protected")
}

// relatedWithPNGAndPDFMessage builds "related(html+cid-png) inside
// mixed, alongside a real PDF attachment": the canonical inline-asset
// shape (a logo referenced from an HTML body via cid:) plus a genuine
// downloadable attachment, matching the grommunio pilot repro
// (ADR-016's Context section).
func relatedWithPNGAndPDFMessage(pngContentType string, pngPayload []byte) string {
	return "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: inline logo plus real attachment\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"MIXED\"\r\n" +
		"\r\n" +
		"--MIXED\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body>Hello <img src=\"cid:logo123\"></body></html>\r\n" +
		"--REL\r\n" +
		"Content-Type: " + pngContentType + "\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(pngPayload) + "\r\n" +
		"--REL--\r\n" +
		"--MIXED\r\n" +
		"Content-Type: application/pdf\r\n" +
		"Content-Disposition: attachment; filename=\"doc.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64([]byte("%PDF-1.4\nPDFDATAMARKER\n")) + "\r\n" +
		"--MIXED--\r\n"
}

// TestProcess_InlineCIDPngProtected_RealPDFReplaced is Fixture 1
// (also covers Fixture 9, the audit inline_protected assertion below):
// a related(html+cid-png) group inside mixed alongside a real PDF
// attachment. The PNG must survive untouched (protected, ADR-016) and
// the HTML body must stay intact (including its cid: reference,
// itself downgraded rather than excluded — ATR-306); the PDF must be
// replaced normally.
func TestProcess_InlineCIDPngProtected_RealPDFReplaced(t *testing.T) {
	png := pngPayload(t, 64)
	msg := relatedWithPNGAndPDFMessage("image/png", png)

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite", verdict.Action)
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	body := string(rewritten)

	if !strings.Contains(body, b64(png)) {
		t.Error("rewritten body no longer contains the inline PNG payload, want it preserved (protected)")
	}
	if !strings.Contains(body, "cid:logo123") {
		t.Error("rewritten body lost the HTML body's cid: reference, want the HTML part intact")
	}
	if strings.Contains(body, b64([]byte("%PDF-1.4\nPDFDATAMARKER\n"))) {
		t.Error("rewritten body still contains the PDF payload, want it replaced")
	}
	if !strings.Contains(body, "doc.pdf") {
		t.Error("rewritten body does not mention the replaced PDF's file name")
	}

	got := collectEvents(t, h)
	counts := countByType(got)
	if counts[audit.TypeAttachmentStored] != 1 {
		t.Errorf("TypeAttachmentStored count = %d, want 1 (only the PDF; the PNG is protected, never uploaded)", counts[audit.TypeAttachmentStored])
	}

	protectedLists := inlineProtectedPartPaths(t, got)
	if len(protectedLists) != 1 || len(protectedLists[0]) != 1 {
		t.Fatalf("inline_protected lists = %v, want exactly one event with exactly one protected part path", protectedLists)
	}

	// The HTML body itself is also submitted to policy.Evaluate and
	// decided replace by replaceAllPolicy's default, then downgraded by
	// protectStructuralBodies (ATR-306) — the security-reviewed fix
	// evaluates it rather than excluding it outright.
	bodyLists := bodyProtectedPartPaths(t, got)
	if len(bodyLists) != 1 || len(bodyLists[0]) != 1 {
		t.Fatalf("body_protected lists = %v, want exactly one event with exactly one protected part path", bodyLists)
	}
}

// TestProcess_AppleMailStyleInlineAttachmentReplaced is Fixture 2: an
// attachment marked Content-Disposition: inline with a filename but no
// Content-ID (the Apple Mail pattern ADR-016's Context section calls
// out), sitting directly in multipart/mixed (no multipart/related
// container). It must NOT be classified InlineAsset (no Content-ID)
// and must replace normally — treating the raw "inline" header as
// authoritative here would be exactly the policy bypass ADR-016
// rejects.
func TestProcess_AppleMailStyleInlineAttachmentReplaced(t *testing.T) {
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: apple mail style inline pdf\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"MIXED\"\r\n" +
		"\r\n" +
		"--MIXED\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"See attached.\r\n" +
		"--MIXED\r\n" +
		"Content-Type: application/pdf\r\n" +
		"Content-Disposition: inline; filename=\"doc.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64([]byte("%PDF-1.4\nAPPLEMAILPDFMARKER\n")) + "\r\n" +
		"--MIXED--\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite", verdict.Action)
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	body := string(rewritten)

	if strings.Contains(body, b64([]byte("%PDF-1.4\nAPPLEMAILPDFMARKER\n"))) {
		t.Error("rewritten body still contains the Apple Mail-style inline PDF payload, want it replaced (no Content-ID -> not InlineAsset)")
	}
	if !strings.Contains(body, "doc.pdf") {
		t.Error("rewritten body does not mention the replaced attachment's file name")
	}
	// "See attached." is the structural text/plain body (ATR-306): it is
	// still fully evaluated by policy.Evaluate (decided replace, like
	// the PDF, under replaceAllPolicy's default) but protectStructuralBodies
	// downgrades it to pass, so it must survive untouched (with the
	// replacement block appended), never itself actually being removed.
	if !strings.Contains(body, "See attached.") {
		t.Error("rewritten body lost the original text/plain body content")
	}

	got := collectEvents(t, h)
	bodyLists := bodyProtectedPartPaths(t, got)
	if len(bodyLists) != 1 || len(bodyLists[0]) != 1 {
		t.Fatalf("body_protected lists = %v, want exactly one event with exactly one protected part path", bodyLists)
	}
}

// TestProcess_CIDNotReferencedFromHTML_Replaced is Fixture 3, updated
// for ADR-016 phase 2 (ATR-307): a Content-ID + multipart/related PNG
// whose Content-ID is never referenced anywhere in the HTML body via
// cid:. Phase 1 protected such a part on the structural signal alone (an
// accepted over-protection); phase 2 verifies the cid: reference, so an
// unreferenced Content-ID asset is no longer an InlineAsset in the
// protective sense and REPLACES normally like any other attachment. The
// HTML body itself (a structural body part) is still downgraded/preserved
// by protectStructuralBodies.
func TestProcess_CIDNotReferencedFromHTML_Replaced(t *testing.T) {
	png := pngPayload(t, 64)
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: cid with no html reference\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body>No image reference here.</body></html>\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(png) + "\r\n" +
		"--REL--\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite (unreferenced CID asset now replaces)", verdict.Action)
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	if strings.Contains(string(rewritten), b64(png)) {
		t.Error("rewritten body still contains the PNG payload, want it replaced (Content-ID never referenced from HTML)")
	}

	got := collectEvents(t, h)
	counts := countByType(got)
	if counts[audit.TypeAttachmentStored] != 1 {
		t.Errorf("TypeAttachmentStored count = %d, want 1 (the unreferenced PNG is now uploaded)", counts[audit.TypeAttachmentStored])
	}
	// The PNG must NOT appear as protected any more.
	if lists := inlineProtectedPartPaths(t, got); len(lists) != 0 {
		t.Errorf("inline_protected lists = %v, want none (unreferenced CID asset is no longer protected)", lists)
	}
	// The HTML structural body is still downgraded/preserved.
	bodyLists := bodyProtectedPartPaths(t, got)
	if len(bodyLists) != 1 || len(bodyLists[0]) != 1 {
		t.Fatalf("body_protected lists = %v, want exactly one event with exactly one protected part path", bodyLists)
	}
}

// TestProcess_OversizedInlinePNGReplaced is Fixture 4: an InlineAsset
// image whose size exceeds the configured limits.inline_max_size must
// replace normally — the protective downgrade only covers small
// logo/signature-shaped assets.
func TestProcess_OversizedInlinePNGReplaced(t *testing.T) {
	const inlineMaxSize = 32 // Smaller than the 64-byte PNG fixture below.
	png := pngPayload(t, 64)
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: oversized inline png\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><img src=\"cid:logo123\"></body></html>\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(png) + "\r\n" +
		"--REL--\r\n"

	h := newTestHarness(t)
	proc := newProcessorWithInlineMaxSize(t, h, replaceAllPolicy, inlineMaxSize)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite (oversized inline asset must still be replaced)", verdict.Action)
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	if strings.Contains(string(rewritten), b64(png)) {
		t.Error("rewritten body still contains the oversized inline PNG payload, want it replaced")
	}

	got := collectEvents(t, h)
	if protectedLists := inlineProtectedPartPaths(t, got); len(protectedLists) != 0 {
		t.Errorf("inline_protected lists = %v, want none (oversized asset is not protected)", protectedLists)
	}
}

// TestProcess_MasqueradingInlineAssetReplaced is Fixture 5: a part
// declared image/png (and otherwise InlineAsset-shaped: Content-ID
// inside multipart/related) whose real bytes are a ZIP file. The
// protective downgrade only fires for the DETECTED type (magic bytes),
// so a masquerading part must still be replaced normally — this closes
// the residual bypass surface ADR-016's Consequences section
// documents (bounded by verified type + size).
func TestProcess_MasqueradingInlineAssetReplaced(t *testing.T) {
	zipBytes := zipMasqueradingAsPNG()
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: masquerading inline asset\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><img src=\"cid:logo123\"></body></html>\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(zipBytes) + "\r\n" +
		"--REL--\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite (masquerading part must still be replaced)", verdict.Action)
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	if strings.Contains(string(rewritten), b64(zipBytes)) {
		t.Error("rewritten body still contains the masquerading part's payload, want it replaced")
	}

	got := collectEvents(t, h)
	if protectedLists := inlineProtectedPartPaths(t, got); len(protectedLists) != 0 {
		t.Errorf("inline_protected lists = %v, want none (masquerading part is not protected)", protectedLists)
	}
}

// dispositionInlineReplacePolicy explicitly opts inline assets into
// replacement via when.attachment.disposition (§2.3.2/ADR-016),
// overriding the engine's protective default.
const dispositionInlineReplacePolicy = `
version: 1
name: "explicit inline opt-in"
rules:
  - name: "replace inline assets too"
    when:
      attachment:
        disposition: ["inline"]
    then:
      action: replace
      ttl: "1d"
default:
  action: pass
`

// TestProcess_ExplicitInlineOptInReplacesPNG is Fixture 6: a policy
// rule that explicitly matches disposition: [inline] and decides
// replace must NOT be protected — InlineOptIn (policy.AttachmentDecision)
// overrides the pipeline's protective downgrade, per ADR-016 decision 2.
func TestProcess_ExplicitInlineOptInReplacesPNG(t *testing.T) {
	png := pngPayload(t, 64)
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: explicit inline opt-in\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><img src=\"cid:logo123\"></body></html>\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(png) + "\r\n" +
		"--REL--\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, dispositionInlineReplacePolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite (explicit opt-in must replace the inline PNG)", verdict.Action)
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	if strings.Contains(string(rewritten), b64(png)) {
		t.Error("rewritten body still contains the inline PNG payload, want it replaced (explicit disposition opt-in)")
	}

	got := collectEvents(t, h)
	if protectedLists := inlineProtectedPartPaths(t, got); len(protectedLists) != 0 {
		t.Errorf("inline_protected lists = %v, want none (opt-in rule must not be protected)", protectedLists)
	}
}

// dispositionInlineBlockPolicy blocks any part matching
// disposition: [inline], to verify blocking is never softened by the
// protective downgrade.
const dispositionInlineBlockPolicy = `
version: 1
name: "block inline assets"
rules:
  - name: "block inline assets"
    when:
      attachment:
        disposition: ["inline"]
    then:
      action: block
      reason: "inline assets are not allowed by this policy"
default:
  action: pass
`

// TestProcess_BlockedInlineAssetIsNeverDowngraded is Fixture 7: a
// rule that blocks InlineAsset parts must actually reject the message
// — ADR-016 decision 2 explicitly excludes ActionBlock from the
// protective downgrade ("block is never downgraded").
func TestProcess_BlockedInlineAssetIsNeverDowngraded(t *testing.T) {
	png := pngPayload(t, 64)
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: blocked inline asset\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><img src=\"cid:logo123\"></body></html>\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(png) + "\r\n" +
		"--REL--\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, dispositionInlineBlockPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictReject {
		t.Fatalf("verdict.Action = %v, want VerdictReject (block must never be downgraded)", verdict.Action)
	}
	if !strings.Contains(verdict.Reason, "inline assets are not allowed") {
		t.Errorf("verdict.Reason = %q, want the blocking rule's reason", verdict.Reason)
	}
}

// TestProcess_PilotRegression_TextPlusInlineLogoDefaultReplace is
// Fixture 10, the flagship regression for both ATR-305 and ATR-306:
// a message with only a text body and an inline (cid:) logo, under a
// bare `default: replace` policy (the grommunio pilot's actual
// configuration), must be delivered completely unmodified — no MIME
// rewrite at all, since both parts are decided replace by the default
// but both are downgraded to pass by their respective protective
// layers (protectInlineAssets for the logo, protectStructuralBodies
// for the text body).
func TestProcess_PilotRegression_TextPlusInlineLogoDefaultReplace(t *testing.T) {
	png := pngPayload(t, 64)
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: pilot regression: text plus inline logo\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body>Best regards,<br><img src=\"cid:logo123\"></body></html>\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(png) + "\r\n" +
		"--REL--\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictAccept {
		t.Fatalf("verdict.Action = %v, want VerdictAccept (message must be delivered completely unmodified)", verdict.Action)
	}
	if verdict.NewBody != nil {
		t.Error("verdict.NewBody != nil, want no rewrite at all for the pilot regression scenario")
	}

	got := collectEvents(t, h)
	counts := countByType(got)
	if counts[audit.TypeAttachmentStored] != 0 {
		t.Errorf("TypeAttachmentStored count = %d, want 0 (nothing is ever uploaded)", counts[audit.TypeAttachmentStored])
	}
	if counts[audit.TypeLinksCreated] != 0 {
		t.Errorf("TypeLinksCreated count = %d, want 0 (no links are created)", counts[audit.TypeLinksCreated])
	}
	if lists := inlineProtectedPartPaths(t, got); len(lists) != 1 || len(lists[0]) != 1 {
		t.Errorf("inline_protected lists = %v, want exactly one event with exactly one protected part path", lists)
	}
	if lists := bodyProtectedPartPaths(t, got); len(lists) != 1 || len(lists[0]) != 1 {
		t.Errorf("body_protected lists = %v, want exactly one event with exactly one protected part path", lists)
	}
}

// TestProcess_DefaultReplace_BodiesIntact_PDFReplaced is Fixture 11
// ("Plus" in the design), the additional required scenario: a message
// with both a text/plain and text/html alternative body plus a real
// PDF attachment, under `default: replace`. Both bodies must survive
// intact (with the replacement block appended, via downgrade — ATR-306)
// and only the PDF must be replaced.
func TestProcess_DefaultReplace_BodiesIntact_PDFReplaced(t *testing.T) {
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: alternative bodies plus pdf\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"MIXED\"\r\n" +
		"\r\n" +
		"--MIXED\r\n" +
		"Content-Type: multipart/alternative; boundary=\"ALT\"\r\n" +
		"\r\n" +
		"--ALT\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"PLAINBODYMARKER\r\n" +
		"--ALT\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body>HTMLBODYMARKER</body></html>\r\n" +
		"--ALT--\r\n" +
		"--MIXED\r\n" +
		"Content-Type: application/pdf\r\n" +
		"Content-Disposition: attachment; filename=\"report.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64([]byte("%PDF-1.4\nALTPDFMARKER\n")) + "\r\n" +
		"--MIXED--\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite", verdict.Action)
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	body := string(rewritten)

	if !strings.Contains(body, "PLAINBODYMARKER") {
		t.Error("rewritten body lost the text/plain body content")
	}
	if !strings.Contains(body, "HTMLBODYMARKER") {
		t.Error("rewritten body lost the text/html body content")
	}
	if strings.Contains(body, b64([]byte("%PDF-1.4\nALTPDFMARKER\n"))) {
		t.Error("rewritten body still contains the PDF payload, want it replaced")
	}
	if !strings.Contains(body, "report.pdf") {
		t.Error("rewritten body does not mention the replaced PDF's file name")
	}

	got := collectEvents(t, h)
	counts := countByType(got)
	if counts[audit.TypeAttachmentStored] != 1 {
		t.Errorf("TypeAttachmentStored count = %d, want 1 (only the PDF)", counts[audit.TypeAttachmentStored])
	}
	// Both the text/plain and text/html alternative bodies are decided
	// replace by the default and downgraded — two distinct part paths
	// under one policy_decision event.
	bodyLists := bodyProtectedPartPaths(t, got)
	if len(bodyLists) != 1 || len(bodyLists[0]) != 2 {
		t.Fatalf("body_protected lists = %v, want exactly one event with exactly two protected part paths", bodyLists)
	}
}

// genuineTextAttachmentMessage builds a message with a structural
// text/plain body (no filename, default disposition) alongside a
// GENUINE text/plain ATTACHMENT (Content-Disposition: attachment,
// filename set) carrying markerContent as its body — the case
// isStructuralBodyPart is deliberately careful not to match, per its
// own doc comment: a part with a filename is never treated as the
// message body no matter its media type.
func genuineTextAttachmentMessage(markerContent string) string {
	return "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: genuine text attachment\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"MIXED\"\r\n" +
		"\r\n" +
		"--MIXED\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Message body.\r\n" +
		"--MIXED\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Disposition: attachment; filename=\"report.txt\"\r\n" +
		"\r\n" +
		markerContent + "\r\n" +
		"--MIXED--\r\n"
}

// TestProcess_GenuineTextAttachmentReplaced_NotProtected is Fixture 12
// (architect review, M1): a genuine text/plain ATTACHMENT
// (Content-Disposition: attachment; filename="report.txt", alongside
// the message's own structural text/plain body) must remain a replace
// candidate and actually be replaced — isStructuralBodyPart's filename
// guard must not over-protect a real attachment just because it
// happens to share the message body's media type. The structural body
// itself is still downgraded as usual.
func TestProcess_GenuineTextAttachmentReplaced_NotProtected(t *testing.T) {
	const marker = "REPORTTEXTMARKER"
	msg := genuineTextAttachmentMessage(marker)

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite (the genuine text attachment must be replaced)", verdict.Action)
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	body := string(rewritten)

	if strings.Contains(body, marker) {
		t.Error("rewritten body still contains the genuine text attachment's payload, want it replaced")
	}
	if !strings.Contains(body, "report.txt") {
		t.Error("rewritten body does not mention the replaced attachment's file name")
	}
	if !strings.Contains(body, "Message body.") {
		t.Error("rewritten body lost the structural text/plain body content")
	}

	got := collectEvents(t, h)
	counts := countByType(got)
	if counts[audit.TypeAttachmentStored] != 1 {
		t.Errorf("TypeAttachmentStored count = %d, want 1 (only report.txt; the structural body is never uploaded)", counts[audit.TypeAttachmentStored])
	}

	if lists := inlineProtectedPartPaths(t, got); len(lists) != 0 {
		t.Errorf("inline_protected lists = %v, want none", lists)
	}
	// Exactly one part (the structural body, "0.1") is protected; the
	// genuine attachment ("0.2") must never appear here.
	bodyLists := bodyProtectedPartPaths(t, got)
	if len(bodyLists) != 1 || len(bodyLists[0]) != 1 {
		t.Fatalf("body_protected lists = %v, want exactly one event with exactly one protected part path", bodyLists)
	}
	if got := bodyLists[0][0]; got != "0.1" {
		t.Errorf("body_protected path = %v, want %q (the structural body, not the genuine attachment)", got, "0.1")
	}
}

// TestProcess_DryRun_ProtectedPart_LogsWouldPass is Fixture 13
// (architect review, M2b): under dry-run, a part that would have been
// protected (downgraded from replace to pass) in a real run must be
// logged by policy.ApplyMode as "would-pass", never "would-replace" —
// asserting the comment on the protectInlineAssets/protectStructuralBodies
// call site in Process ("so a dry-run log for a protected part
// correctly reads would-pass rather than a misleading would-replace").
// Protection therefore must run BEFORE dry-run reconciliation.
func TestProcess_DryRun_ProtectedPart_LogsWouldPass(t *testing.T) {
	png := pngPayload(t, 64)
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: dry run protected inline asset\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><img src=\"cid:logo123\"></body></html>\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(png) + "\r\n" +
		"--REL--\r\n"

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	h := newTestHarness(t)
	proc := newProcessorWithDryRunLogger(t, h, replaceAllPolicy, logger)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictAccept {
		t.Fatalf("verdict.Action = %v, want VerdictAccept (dry-run never rewrites)", verdict.Action)
	}

	out := logBuf.String()
	if strings.Contains(out, "verdict=would-replace") {
		t.Errorf("dry-run log = %q, want no would-replace verdict for a protected part", out)
	}
	if !strings.Contains(out, "verdict=would-pass") {
		t.Errorf("dry-run log = %q, want at least one would-pass verdict (protection runs before dry-run reconciliation)", out)
	}
}

// textBodyBlockPolicy blocks any part whose real, detected content
// type is text/plain, regardless of declared type or structural-body
// shape.
const textBodyBlockPolicy = `
version: 1
name: "block text/plain content"
rules:
  - name: "block text/plain by detected type"
    when:
      attachment:
        mime_type: ["text/plain*"]
    then:
      action: block
      reason: "text/plain content is blocked for this test"
default:
  action: pass
`

// TestProcess_BlockRuleOnGenuineTextBody_StillBlocks is Fixture 14
// (security review, negative companion to Fixture 15): a rule that
// blocks by DETECTED mime_type ["text/plain*"] must still reject a
// message whose only part is a genuine, structural text/plain body —
// protectStructuralBodies only ever downgrades REPLACE to PASS, never
// touches BLOCK.
func TestProcess_BlockRuleOnGenuineTextBody_StillBlocks(t *testing.T) {
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: block text body\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Hello world body.\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, textBodyBlockPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictReject {
		t.Fatalf("verdict.Action = %v, want VerdictReject (block on a structural body must still fire)", verdict.Action)
	}
	if !strings.Contains(verdict.Reason, "text/plain content is blocked") {
		t.Errorf("verdict.Reason = %q, want the blocking rule's reason", verdict.Reason)
	}
}

// zipBlockPolicy blocks any part whose real, detected content type is
// application/zip, regardless of declared Content-Type.
const zipBlockPolicy = `
version: 1
name: "block zip content"
rules:
  - name: "block zip by detected type"
    when:
      attachment:
        mime_type: ["application/zip"]
    then:
      action: block
      reason: "zip content is blocked for this test"
default:
  action: pass
`

// TestProcess_MasqueradingStructuralBody_DetectedTypeBlockFires is
// Fixture 15 (security review BLOCKER validation): a part shaped
// exactly like a structural body (Content-Type: text/plain, inline,
// no filename — isStructuralBodyPart would match it) but whose real
// bytes are a ZIP file must still be sniffed and matched against a
// detected-type block rule. An earlier version of the ATR-306 fix
// skipped structural body parts before policy.Evaluate entirely,
// which would have silently accepted this exact message (the
// enforcement bypass the security review's BLOCKER flagged); this test
// pins down that the part is fully evaluated and the block fires.
func TestProcess_MasqueradingStructuralBody_DetectedTypeBlockFires(t *testing.T) {
	zipBytes := zipMasqueradingAsPNG() // Same ZIP magic bytes helper; content type is irrelevant here.
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: masquerading structural body\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(zipBytes) + "\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, zipBlockPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictReject {
		t.Fatalf("verdict.Action = %v, want VerdictReject (detected-type block rule must fire on a masquerading structural body)", verdict.Action)
	}
	if !strings.Contains(verdict.Reason, "zip content is blocked") {
		t.Errorf("verdict.Reason = %q, want the blocking rule's reason", verdict.Reason)
	}
}

// --- ADR-016 phase 2 (ATR-307): cid: reference verification -----------
//
// Fixtures 16-22 pin the phase-2 refinement end-to-end: an InlineAsset is
// protected only when its Content-ID is really referenced via cid: from a
// text/html body of the same multipart/related container. See cid_test.go
// for the lower-level scanner/scoping/fail-safe unit tests, including the
// aggregate scan-byte/token budget unit tests. Fixture 20 exercises the
// aggregate token budget end-to-end (a security review of the first
// version of this change found the per-part scan bound alone was
// insufficient: a message with many text/html parts could still
// aggregate several GiB of retained token maps, B1); fixtures 21-22
// exercise the companion fix that skips the scan entirely for a message
// with no inline-asset candidate at all (B2).

// relatedImageBeforeHTML builds a multipart/related where the cid image
// part comes BEFORE the referencing text/html part — RFC 2387 only
// SHOULD (not MUST) put the root/HTML part first, so the pipeline must
// tolerate an image-before-HTML ordering. The pipeline collects every
// HTML body's references before applying protection, so document order
// is irrelevant.
func relatedImageBeforeHTML(png []byte) string {
	return "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: image before html\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(png) + "\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><img src=\"cid:logo123\"></body></html>\r\n" +
		"--REL--\r\n"
}

// TestProcess_InlineImageBeforeHTML_StillProtected is Fixture 16: the
// referencing HTML appears after the image in document order. The image
// must still be recognized as referenced and protected.
func TestProcess_InlineImageBeforeHTML_StillProtected(t *testing.T) {
	png := pngPayload(t, 64)
	msg := relatedImageBeforeHTML(png)

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	// The image is protected and the HTML body is downgraded, so nothing
	// is left to replace: accept untouched.
	if verdict.Action != pipeline.VerdictAccept {
		t.Fatalf("verdict.Action = %v, want VerdictAccept (image-before-HTML must not defeat cid verification)", verdict.Action)
	}

	got := collectEvents(t, h)
	if counts := countByType(got); counts[audit.TypeAttachmentStored] != 0 {
		t.Errorf("TypeAttachmentStored count = %d, want 0 (referenced inline image is protected)", counts[audit.TypeAttachmentStored])
	}
	protectedLists := inlineProtectedPartPaths(t, got)
	if len(protectedLists) != 1 || len(protectedLists[0]) != 1 {
		t.Fatalf("inline_protected lists = %v, want exactly one event with exactly one protected part path", protectedLists)
	}
}

// TestProcess_CIDNoHTMLPart_Replaced is Fixture 17: a multipart/related
// with a Content-ID image and a text/PLAIN body (no text/html at all).
// With no HTML part there can be no cid: reference, so the image is not a
// protected InlineAsset and replaces normally.
func TestProcess_CIDNoHTMLPart_Replaced(t *testing.T) {
	png := pngPayload(t, 64)
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: cid with no html part\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Plain body, cid:logo123 mentioned here does not count.\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(png) + "\r\n" +
		"--REL--\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite (no HTML part => no cid reference => replace)", verdict.Action)
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	if strings.Contains(string(rewritten), b64(png)) {
		t.Error("rewritten body still contains the PNG payload, want it replaced (a cid: token in a text/plain body must not grant protection)")
	}
	if lists := inlineProtectedPartPaths(t, collectEvents(t, h)); len(lists) != 0 {
		t.Errorf("inline_protected lists = %v, want none", lists)
	}
}

// TestProcess_InlineCIDUnquotedAndSingleQuoted_Protected is Fixture 18:
// cid: references written unquoted and single-quoted (rather than the
// canonical double-quoted src="cid:...") must still be recognized. Two
// images, each referenced with a different quoting style, both protected.
func TestProcess_InlineCIDUnquotedAndSingleQuoted_Protected(t *testing.T) {
	pngA := pngPayload(t, 64)
	pngB := pngPayload(t, 65)
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: unquoted and single-quoted cid\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><img src=cid:imgA><img src='cid:imgB'></body></html>\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <imgA>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(pngA) + "\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <imgB>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(pngB) + "\r\n" +
		"--REL--\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictAccept {
		t.Fatalf("verdict.Action = %v, want VerdictAccept (both images protected, HTML downgraded)", verdict.Action)
	}

	got := collectEvents(t, h)
	if counts := countByType(got); counts[audit.TypeAttachmentStored] != 0 {
		t.Errorf("TypeAttachmentStored count = %d, want 0 (both referenced images protected)", counts[audit.TypeAttachmentStored])
	}
	protectedLists := inlineProtectedPartPaths(t, got)
	if len(protectedLists) != 1 || len(protectedLists[0]) != 2 {
		t.Fatalf("inline_protected lists = %v, want exactly one event with exactly two protected part paths", protectedLists)
	}
}

// TestProcess_MultipleHTMLParts_ReferencedProtected_UnreferencedReplaced
// is Fixture 19: a multipart/related whose root is a
// multipart/alternative (text/plain + text/html, the common Outlook
// shape — the HTML is a GRANDCHILD of the related container, not a direct
// sibling) plus two images. The alternative's HTML references only imgA;
// imgA is protected, imgB (never referenced) is replaced. This exercises
// both container scoping across the alternative nesting and the
// per-asset referenced/unreferenced split.
func TestProcess_MultipleHTMLParts_ReferencedProtected_UnreferencedReplaced(t *testing.T) {
	imgA := pngPayload(t, 64)
	imgB := pngPayload(t, 65)
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: alternative root plus two inline images\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: multipart/alternative; boundary=\"ALT\"\r\n" +
		"\r\n" +
		"--ALT\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"See the logo.\r\n" +
		"--ALT\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><img src=\"cid:imgA\"></body></html>\r\n" +
		"--ALT--\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <imgA>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(imgA) + "\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <imgB>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(imgB) + "\r\n" +
		"--REL--\r\n"

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite (imgB is unreferenced and must replace)", verdict.Action)
	}

	rewritten, err := io.ReadAll(verdict.NewBody)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	body := string(rewritten)
	if !strings.Contains(body, b64(imgA)) {
		t.Error("rewritten body lost imgA, want it preserved (referenced from the alternative's HTML)")
	}
	if strings.Contains(body, b64(imgB)) {
		t.Error("rewritten body still contains imgB, want it replaced (never referenced)")
	}

	got := collectEvents(t, h)
	if counts := countByType(got); counts[audit.TypeAttachmentStored] != 1 {
		t.Errorf("TypeAttachmentStored count = %d, want 1 (only the unreferenced imgB)", counts[audit.TypeAttachmentStored])
	}
	protectedLists := inlineProtectedPartPaths(t, got)
	if len(protectedLists) != 1 || len(protectedLists[0]) != 1 {
		t.Fatalf("inline_protected lists = %v, want exactly one event with exactly one protected part path (imgA only)", protectedLists)
	}
}

// aggregateCIDTokenBudget mirrors pipeline's unexported
// maxAggregateCIDTokens (internal/core/pipeline/cid.go) so this
// external test can construct a single html part whose distinct cid:
// token count exceeds the aggregate per-message budget without needing
// to import an unexported constant across the package boundary. Keep
// this in sync with cid.go's maxAggregateCIDTokens.
const aggregateCIDTokenBudget = 65536

// aggregateBudgetOverflowMessage builds a multipart/mixed with two
// multipart/related groups: the first's html body alone carries
// tokenCount distinct cid: tokens (including cid:logoA, so its own
// asset IS present among them) — enough to exceed the aggregate
// per-message cid: token budget (ATR-307 security review, B1) — and the
// second is a normal, tiny, cheap-to-scan html+png pair (cid:logoB).
func aggregateBudgetOverflowMessage(tokenCount int, pngA, pngB []byte) string {
	var htmlA strings.Builder
	for i := 0; i < tokenCount; i++ {
		htmlA.WriteString("cid:")
		htmlA.WriteString(strconv.Itoa(i))
		htmlA.WriteByte(' ')
	}
	htmlA.WriteString("cid:logoA")

	return "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: aggregate cid token budget overflow\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"MIXED\"\r\n" +
		"\r\n" +
		"--MIXED\r\n" +
		"Content-Type: multipart/related; boundary=\"REL1\"\r\n" +
		"\r\n" +
		"--REL1\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		htmlA.String() + "\r\n" +
		"--REL1\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logoA>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(pngA) + "\r\n" +
		"--REL1--\r\n" +
		"--MIXED\r\n" +
		"Content-Type: multipart/related; boundary=\"REL2\"\r\n" +
		"\r\n" +
		"--REL2\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><img src=\"cid:logoB\"></body></html>\r\n" +
		"--REL2\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logoB>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(pngB) + "\r\n" +
		"--REL2--\r\n" +
		"--MIXED--\r\n"
}

// TestProcess_AggregateTokenBudgetExhausted_SubsequentContainerFailSafe
// is Fixture 20 (ATR-307 security review, B1 blocker): the first
// multipart/related group's html body alone carries more distinct
// cid: tokens than the aggregate per-message token budget
// (maxAggregateCIDTokens); collectHTMLCIDRefs discards ALL of that
// part's tokens (never partially retains them) and marks it truncated,
// so even that container's OWN asset (logoA, which really is among the
// tokens) ends up fail-safe-protected-but-unverified rather than
// confidently verified. A second, unrelated, cheap-to-scan group
// (html+png logoB) is then left completely unscanned once the aggregate
// token budget is spent (the top-of-loop budget check in
// collectHTMLCIDRefs, not just the per-part byte cap). Both assets end
// up protected (fail-safe direction — never break a message), and both
// are honestly reported "inline_protected_unverified" in the audit
// trail rather than silently mis-classified as confidently verified.
func TestProcess_AggregateTokenBudgetExhausted_SubsequentContainerFailSafe(t *testing.T) {
	pngA := pngPayload(t, 64)
	pngB := pngPayload(t, 65)
	msg := aggregateBudgetOverflowMessage(aggregateCIDTokenBudget+4000, pngA, pngB)

	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictAccept {
		t.Fatalf("verdict.Action = %v, want VerdictAccept (both pngs fail-safe protected, both html bodies downgraded)", verdict.Action)
	}

	got := collectEvents(t, h)
	counts := countByType(got)
	if counts[audit.TypeAttachmentStored] != 0 {
		t.Errorf("TypeAttachmentStored count = %d, want 0 (both pngs protected, fail-safe direction)", counts[audit.TypeAttachmentStored])
	}

	protectedLists := inlineProtectedPartPaths(t, got)
	if len(protectedLists) != 1 || len(protectedLists[0]) != 2 {
		t.Fatalf("inline_protected lists = %v, want exactly one event with exactly two protected part paths (logoA and logoB)", protectedLists)
	}

	unverifiedLists := protectedPartPaths(t, got, "inline_protected_unverified")
	if len(unverifiedLists) != 1 || len(unverifiedLists[0]) != 2 {
		t.Fatalf("inline_protected_unverified lists = %v, want exactly one event with exactly two unverified part paths (both containers affected by the exhausted aggregate token budget)", unverifiedLists)
	}
}

// TestProcess_NoInlineCandidate_CIDScanSkipped is Fixture 21 (ATR-307
// security review, B2 companion): an ordinary message with a structural
// text/html body only — no Content-ID part anywhere, hence no
// InlineAsset candidate at all — must never pay for a cid: scan.
// Process's hasInlineCandidate gate is asserted directly via its
// Debug-level "skipped" log line (the html body's own spool is
// internal to Process, so instrumenting it directly is not an option
// from this external test package; the log line is the intended,
// documented observability seam for this gate — see the Process doc
// comment at the hasInlineCandidate call site).
func TestProcess_NoInlineCandidate_CIDScanSkipped(t *testing.T) {
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: ordinary html body, no inline assets\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body>Just a plain message, no images at all.</body></html>\r\n"

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	h := newTestHarness(t)
	proc := newProcessorWithLogger(t, h, replaceAllPolicy, logger)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	// The lone text/html part is a structural body (protectStructuralBodies),
	// so nothing is ever left to replace.
	if verdict.Action != pipeline.VerdictAccept {
		t.Fatalf("verdict.Action = %v, want VerdictAccept", verdict.Action)
	}

	if !strings.Contains(logBuf.String(), "cid scan: skipped") {
		t.Errorf("log output = %q, want the B2 gate's skipped line (no InlineAsset candidate in this message)", logBuf.String())
	}
}

// TestProcess_InlineCandidatePresent_CIDScanRuns is Fixture 22, the
// negative companion to Fixture 21: a message that DOES contain an
// InlineAsset candidate must NOT hit the B2 skip branch — the gate must
// not over-trigger and accidentally skip a message that actually needs
// verification.
func TestProcess_InlineCandidatePresent_CIDScanRuns(t *testing.T) {
	png := pngPayload(t, 64)
	msg := "From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: inline candidate present\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
		"\r\n" +
		"--REL\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><img src=\"cid:logo123\"></body></html>\r\n" +
		"--REL\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-ID: <logo123>\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64(png) + "\r\n" +
		"--REL--\r\n"

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	h := newTestHarness(t)
	proc := newProcessorWithLogger(t, h, replaceAllPolicy, logger)

	verdict, err := proc.Process(context.Background(), envelopeFor(msg))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictAccept {
		t.Fatalf("verdict.Action = %v, want VerdictAccept (referenced logo protected, html body downgraded)", verdict.Action)
	}

	if strings.Contains(logBuf.String(), "cid scan: skipped") {
		t.Errorf("log output = %q, want no skipped line (this message has an InlineAsset candidate)", logBuf.String())
	}

	got := collectEvents(t, h)
	if lists := inlineProtectedPartPaths(t, got); len(lists) != 1 || len(lists[0]) != 1 {
		t.Errorf("inline_protected lists = %v, want exactly one event with exactly one protected part path", lists)
	}
}
