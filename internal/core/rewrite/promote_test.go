package rewrite

import (
	"bytes"
	"io"
	"mime"
	"net/mail"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/message"
)

// TestRewrite_PromotionPath_ContentTypeInHeaderBlock is the ATR-291
// golden test: a message whose ENTIRE body is a single non-multipart
// attachment (no multipart wrapper at all) is promoted into a
// multipart/mixed envelope, and the promoted Content-Type must live
// INSIDE the header block — not, as the pre-fix code did, past the blank
// line where it would land in the body. The regression is verified two
// ways: (1) net/mail parses NewBody and reports a multipart/mixed
// top-level Content-Type; (2) message.Parse (the codebase parser)
// re-parses NewBody as valid MIME carrying the replacement block.
func TestRewrite_PromotionPath_ContentTypeInHeaderBlock(t *testing.T) {
	raw := []byte("Subject: single-part promotion test\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"report.bin\"\r\n" +
		"Content-Transfer-Encoding: 7bit\r\n" +
		"\r\n" +
		"raw single-part attachment bytes, no multipart wrapper at all\r\n")

	atts := parseMessageBytes(t, raw)
	if len(atts) != 1 {
		t.Fatalf("expected exactly one attachment (the whole body), got %d: %+v", len(atts), atts)
	}
	decision := decisionReplacingAttachments(atts, atts[0].PartPath)

	result, err := Rewrite(Input{
		Message:     bytes.NewReader(raw),
		Attachments: atts,
		Decision:    decision,
		PackageURL:  "https://dl.example.com/p/promote123",
		SenderName:  "sender@example.com",
	}, testTemplates(t))
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	got := mustReadAll(t, result.Body)

	// (1) net/mail must parse the header block and see a multipart/mixed
	// Content-Type there — the crux of ATR-291. If the promoted
	// Content-Type had leaked into the body, mail.ReadMessage would still
	// parse the header block but Content-Type would be the ORIGINAL
	// application/octet-stream (or the parse of the body would be wrong).
	msg, err := mail.ReadMessage(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("NewBody did not parse as an RFC 5322 message: %v\n--- output ---\n%s", err, got)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse promoted Content-Type %q: %v", msg.Header.Get("Content-Type"), err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("top-level Content-Type = %q, want multipart/mixed (promoted header must be in the header block, not the body)", mediaType)
	}
	if params["boundary"] == "" {
		t.Fatalf("promoted multipart/mixed Content-Type has no boundary parameter: %q", msg.Header.Get("Content-Type"))
	}

	// The per-part content headers of the (now dropped) single part must
	// NOT remain on the multipart envelope: an octet-stream body and an
	// attachment disposition on the whole message would misdescribe it.
	if got := msg.Header.Get("Content-Transfer-Encoding"); got != "" {
		t.Errorf("promoted envelope still carries Content-Transfer-Encoding %q, want none", got)
	}
	if got := msg.Header.Get("Content-Disposition"); got != "" {
		t.Errorf("promoted envelope still carries Content-Disposition %q, want none", got)
	}
	if msg.Header.Get("MIME-Version") == "" {
		t.Errorf("promoted message is missing a MIME-Version header")
	}

	// (2) The whole message must re-parse as valid MIME via the codebase
	// parser, and the replacement block (package URL) must be present.
	assertValidPromotedMessage(t, got, "dl.example.com/p/promote123")

	// The replaced part's body and its content type must be gone entirely
	// (the single part was dropped, not wrapped).
	if bytes.Contains(got, []byte("application/octet-stream")) {
		t.Errorf("dropped part's Content-Type still present in rewritten message:\n%s", got)
	}
	if bytes.Contains(got, []byte("no multipart wrapper at all")) {
		t.Errorf("dropped part's body bytes still present in rewritten message:\n%s", got)
	}
	if len(result.Replaced) != 1 {
		t.Fatalf("Replaced has %d entries, want 1", len(result.Replaced))
	}
}

// assertValidPromotedMessage re-parses got with message.Parse (the parser
// the rest of the codebase relies on) and checks it is valid MIME
// carrying the package URL somewhere and the X-Attachra-Processed header.
func assertValidPromotedMessage(t *testing.T, got []byte, wantURL string) {
	t.Helper()

	err := message.Parse(bytes.NewReader(got), message.DefaultLimits(), func(_ *message.Attachment, body io.Reader) error {
		_, err := io.Copy(io.Discard, body)
		return err
	})
	if err != nil {
		t.Fatalf("promoted message failed to re-parse as valid MIME: %v\n--- output ---\n%s", err, got)
	}
	if !bytes.Contains(got, []byte(wantURL)) {
		t.Errorf("promoted message does not contain the package URL %q", wantURL)
	}
	if !bytes.Contains(got, []byte("X-Attachra-Processed:")) {
		t.Errorf("promoted message is missing X-Attachra-Processed header")
	}
}

// TestPromoteHeaderBlock exercises the pure header-block transform the
// promotion path relies on: envelope headers are preserved verbatim, the
// per-part content headers are dropped, and the multipart/mixed
// Content-Type, MIME-Version and X-Attachra-Processed are appended inside
// the block (before its terminating blank line).
func TestPromoteHeaderBlock(t *testing.T) {
	headerBytes := []byte("Subject: hi\r\n" +
		"From: a@example.com\r\n" +
		"Content-Type: application/pdf\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"x.pdf\"\r\n" +
		"MIME-Version: 1.0\r\n" +
		"\r\n")

	out := promoteHeaderBlock(headerBytes, "BND", "abc123")

	// Parse the produced block back and assert on it, so the test
	// encodes the RESULT's semantics (a valid header block whose
	// Content-Type is multipart/mixed) rather than an exact byte layout.
	msg, err := mail.ReadMessage(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("promoteHeaderBlock output does not parse: %v\n%s", err, out)
	}

	if got := msg.Header.Get("Subject"); got != "hi" {
		t.Errorf("Subject = %q, want preserved %q", got, "hi")
	}
	if got := msg.Header.Get("From"); got != "a@example.com" {
		t.Errorf("From = %q, want preserved", got)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Errorf("Content-Type = %q (mt=%q err=%v), want multipart/mixed", msg.Header.Get("Content-Type"), mt, err)
	}
	if params["boundary"] != "BND" {
		t.Errorf("boundary = %q, want BND", params["boundary"])
	}
	// The dropped per-part headers must not appear (exactly once each is
	// dropped; MIME-Version is regenerated, so exactly one remains).
	if got := msg.Header.Get("Content-Transfer-Encoding"); got != "" {
		t.Errorf("Content-Transfer-Encoding = %q, want dropped", got)
	}
	if got := msg.Header.Get("Content-Disposition"); got != "" {
		t.Errorf("Content-Disposition = %q, want dropped", got)
	}
	if n := strings.Count(string(out), "MIME-Version:"); n != 1 {
		t.Errorf("MIME-Version appears %d times, want exactly 1 (regenerated, original dropped)", n)
	}
	if !strings.Contains(string(out), "X-Attachra-Processed: version=1; id=abc123") {
		t.Errorf("promoted block missing X-Attachra-Processed:\n%s", out)
	}

	// A body byte written after the block must be reachable as body, i.e.
	// the block is terminated by exactly one blank line.
	body, _ := io.ReadAll(msg.Body)
	if len(body) != 0 {
		t.Errorf("unexpected trailing body after a header-only block: %q", body)
	}
}

// TestContentHeaderLines verifies the complement filter keeps exactly the
// per-part content headers, verbatim, so the wrapped-body part on the
// kept-original branch carries them (and nothing else).
func TestContentHeaderLines(t *testing.T) {
	headerBytes := []byte("Subject: hi\r\n" +
		"Content-Type: application/pdf\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n")

	out := string(contentHeaderLines(headerBytes))
	if strings.Contains(out, "Subject:") {
		t.Errorf("content headers must not include the envelope Subject:\n%s", out)
	}
	if !strings.Contains(out, "Content-Type: application/pdf\r\n") {
		t.Errorf("content headers missing Content-Type:\n%s", out)
	}
	if !strings.Contains(out, "Content-Transfer-Encoding: base64\r\n") {
		t.Errorf("content headers missing Content-Transfer-Encoding:\n%s", out)
	}
}

// TestForEachHeaderField_FoldedContinuation ensures a folded header
// (continuation lines starting with whitespace) is treated as a single
// field, its raw bytes preserved, and iteration stops at the blank line.
func TestForEachHeaderField_FoldedContinuation(t *testing.T) {
	headerBytes := []byte("Subject: line one\r\n" +
		"\tfolded continuation\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"body should not be visited\r\n")

	var names []string
	var subjectRaw string
	forEachHeaderField(headerBytes, func(name string, raw []byte) {
		names = append(names, name)
		if name == "Subject" {
			subjectRaw = string(raw)
		}
	})

	if len(names) != 2 || names[0] != "Subject" || names[1] != "Content-Type" {
		t.Fatalf("fields = %v, want [Subject Content-Type]", names)
	}
	want := "Subject: line one\r\n\tfolded continuation\r\n"
	if subjectRaw != want {
		t.Errorf("folded Subject raw = %q, want %q", subjectRaw, want)
	}
}
