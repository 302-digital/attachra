package rewrite

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/policy"
)

// parseTestdata parses the .eml file at path with message.Parse
// (DefaultLimits), returning the ordered attachment list and, for
// each attachment, its raw (still-encoded) body bytes and full raw
// message bytes, mirroring how a real caller would obtain the inputs
// to Rewrite.
func parseTestdata(t *testing.T, path string) (raw []byte, atts []message.Attachment) {
	t.Helper()

	raw, err := os.ReadFile(path) //nolint:gosec // fixed test fixture directory, not attacker-controlled
	if err != nil {
		t.Fatalf("read testdata %q: %v", path, err)
	}
	return raw, parseMessageBytes(t, raw)
}

// parseMessageBytes parses raw with message.Parse (DefaultLimits),
// returning the ordered attachment list. Shared by parseTestdata
// (on-disk fixtures) and tests that construct a message literal
// in-line (e.g. differential_test.go's MUA-style boundary repro).
func parseMessageBytes(t *testing.T, raw []byte) []message.Attachment {
	t.Helper()

	var atts []message.Attachment
	err := message.Parse(bytes.NewReader(raw), message.DefaultLimits(), func(att *message.Attachment, body io.Reader) error {
		buf, readErr := io.ReadAll(body)
		if readErr != nil {
			return readErr
		}
		att.DetectedType = message.DetectType(buf)
		// Parse only fills in att.Size *after* this callback returns
		// (it accounts for any bytes the callback left unread too),
		// so a snapshot taken here would always see Size's zero
		// value; since the callback already read the whole body via
		// io.ReadAll, len(buf) is the same final value Parse would
		// have assigned.
		att.Size = int64(len(buf))
		atts = append(atts, *att)
		return nil
	})
	if err != nil {
		t.Fatalf("message.Parse: %v", err)
	}
	return atts
}

// decisionReplacingAttachments builds a policy.MessageDecision that
// replaces exactly the attachments whose PartPath is in replacePaths
// and passes everything else, aligned index-for-index with atts (the
// contract Rewrite requires).
func decisionReplacingAttachments(atts []message.Attachment, replacePaths ...string) policy.MessageDecision {
	replace := make(map[string]bool, len(replacePaths))
	for _, p := range replacePaths {
		replace[p] = true
	}

	decisions := make([]policy.AttachmentDecision, len(atts))
	action := policy.ActionPass
	for i, att := range atts {
		if replace[att.PartPath] {
			decisions[i] = policy.AttachmentDecision{Action: policy.ActionReplace}
			action = policy.ActionReplace
		} else {
			decisions[i] = policy.AttachmentDecision{Action: policy.ActionPass}
		}
	}
	return policy.MessageDecision{Action: action, Attachments: decisions}
}

func testTemplates(t *testing.T) *Templates {
	t.Helper()
	tmpl, err := LoadTemplates(TemplateConfig{Locale: "en"})
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	return tmpl
}

// mustReadAll reads r fully, closing it afterward if it implements
// io.Closer (spooled results do).
func mustReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	if c, ok := r.(io.Closer); ok {
		if err := c.Close(); err != nil {
			t.Fatalf("close rewritten body: %v", err)
		}
	}
	return b
}

// TestRewrite_NoReplaceDecision_PassthroughByteForByte covers
// Rewrite's documented trivial-bypass guarantee: a decision with no
// ActionReplace verdict at all returns in.Message completely
// untouched, not even re-serialized (see Rewrite's doc comment).
//
// The multipart_related_alternative.eml case additionally pins this
// against future rewrite/walk.go refactors: if the trivial early
// return in Rewrite (rewrite.go's `if !in.hasReplace() { ... }`) is
// ever removed or bypassed for an all-pass decision, every part would
// instead flow through the full rewriteMultipart/boundaryWriter walk
// — the same nested multipart/related + multipart/alternative
// structure whose closing-delimiter CRLF handling regressed once
// already (ATR-235's round-trip corpus test in roundtrip_test.go
// caught it). A real bytes.Equal comparison via the actual Rewrite()
// entry point here catches that regression immediately, independent
// of which code path produces the output.
func TestRewrite_NoReplaceDecision_PassthroughByteForByte(t *testing.T) {
	for _, file := range []string{
		"multipart_mixed_basic.eml",
		"multipart_related_alternative.eml",
	} {
		t.Run(file, func(t *testing.T) {
			path := testdataPath(file)
			raw, atts := parseTestdata(t, path)
			decision := decisionReplacingAttachments(atts /* no replace paths */)

			result, err := Rewrite(Input{
				Message:     bytes.NewReader(raw),
				Attachments: atts,
				Decision:    decision,
				PackageURL:  "https://dl.example.com/p/token",
			}, testTemplates(t))
			if err != nil {
				t.Fatalf("Rewrite: %v", err)
			}

			got := mustReadAll(t, result.Body)
			if !bytes.Equal(got, raw) {
				t.Fatalf("passthrough result differs from original:\n--- got ---\n%s\n--- want ---\n%s", got, raw)
			}
			if len(result.Replaced) != 0 {
				t.Fatalf("Replaced = %v, want empty", result.Replaced)
			}
		})
	}
}

func TestRewrite_ReplacesAttachment_KeepsStructureValid(t *testing.T) {
	for _, tc := range []struct {
		name         string
		file         string
		replacePaths []string
	}{
		{"basic mixed", "multipart_mixed_basic.eml", []string{"0.2"}},
		{"related+alternative", "multipart_related_alternative.eml", []string{"0.2"}},
		{"many parts", "many_parts.eml", []string{"0.1", "0.3"}},
		{"nested rfc822", "nested_message_rfc822.eml", nil}, // filled below
		{"no filename", "attachment_no_filename.eml", []string{"0.2"}},
		{"zero byte", "attachment_zero_byte.eml", []string{"0.2"}},
		{"rfc2047 greek", "filename_rfc2047_greek.eml", []string{"0.2"}},
		{"rfc2231 greek", "filename_rfc2231_greek.eml", []string{"0.2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := testdataPath(tc.file)
			raw, atts := parseTestdata(t, path)

			replacePaths := tc.replacePaths
			if tc.name == "nested rfc822" {
				// Replace whichever attachment is nested inside the
				// forwarded message (identified by having a filename
				// other than "forwarded.eml", the outer envelope
				// itself is left as pass).
				for _, a := range atts {
					if a.Filename != "" && a.Filename != "forwarded.eml" {
						replacePaths = append(replacePaths, a.PartPath)
					}
				}
			}

			decision := decisionReplacingAttachments(atts, replacePaths...)

			result, err := Rewrite(Input{
				Message:     bytes.NewReader(raw),
				Attachments: atts,
				Decision:    decision,
				PackageURL:  "https://dl.example.com/p/abc123",
				SenderName:  "sender@example.com",
			}, testTemplates(t))
			if err != nil {
				t.Fatalf("Rewrite: %v", err)
			}

			got := mustReadAll(t, result.Body)

			removedNames := namesAtPaths(atts, replacePaths)
			assertValidMessageWithBlock(t, got, removedNames)
			assertPassAttachmentsByteIdentical(t, atts, got, replacePaths)

			if len(result.Replaced) != len(replacePaths) {
				t.Fatalf("Replaced has %d entries, want %d", len(result.Replaced), len(replacePaths))
			}
		})
	}
}

// namesAtPaths returns the (non-empty) Filename of each attachment in
// atts whose PartPath is in paths, used to identify removed
// attachments by a stable key (filename) rather than by PartPath,
// since PartPath is recomputed fresh (and will differ) once the
// rewritten message is itself re-parsed.
func namesAtPaths(atts []message.Attachment, paths []string) map[string]bool {
	want := make(map[string]bool, len(paths))
	for _, p := range paths {
		want[p] = true
	}
	names := make(map[string]bool, len(paths))
	for _, a := range atts {
		if want[a.PartPath] {
			names[a.Filename] = true
		}
	}
	return names
}

// assertValidMessageWithBlock re-parses got with message.Parse (the
// same parser this whole codebase relies on for correctness) and
// checks: (1) none of removedNames is present in the output's
// attachments; (2) the package URL string appears in the raw output
// (i.e. some part carries the replacement block).
func assertValidMessageWithBlock(t *testing.T, got []byte, removedNames map[string]bool) {
	t.Helper()

	var reparsed []message.Attachment
	err := message.Parse(bytes.NewReader(got), message.DefaultLimits(), func(att *message.Attachment, body io.Reader) error {
		if _, err := io.Copy(io.Discard, body); err != nil {
			return err
		}
		reparsed = append(reparsed, *att)
		return nil
	})
	if err != nil {
		t.Fatalf("rewritten message failed to re-parse as valid MIME: %v\n--- output ---\n%s", err, got)
	}

	for _, att := range reparsed {
		if att.Filename != "" && removedNames[att.Filename] {
			t.Errorf("attachment %q still present after replace", att.Filename)
		}
	}

	if !bytes.Contains(got, []byte("dl.example.com/p/abc123")) {
		t.Errorf("rewritten message does not contain the package URL")
	}
	if !bytes.Contains(got, []byte("X-Attachra-Processed:")) {
		t.Errorf("rewritten message is missing X-Attachra-Processed header")
	}
}

// assertPassAttachmentsByteIdentical re-parses got and, for every
// original attachment that was NOT replaced and has Disposition ==
// Attachment (a real attachment, as opposed to the inline text/plain
// or text/html body, which is expected to change — the replacement
// block is appended to it), checks that a same-named part in the
// rewritten message has an identical decoded size to the original,
// via a fresh message.Parse (so any accidental decode/re-encode of a
// pass-through part's Content-Transfer-Encoding would change the
// decoded byte count and be caught here). Matching is by file name
// rather than PartPath, since PartPath is recomputed fresh once
// dropped siblings shift the remaining parts' indices.
func assertPassAttachmentsByteIdentical(t *testing.T, origAtts []message.Attachment, got []byte, replacedPaths []string) {
	t.Helper()

	replaced := make(map[string]bool, len(replacedPaths))
	for _, p := range replacedPaths {
		replaced[p] = true
	}

	wantSizeByName := make(map[string]int64)
	for _, a := range origAtts {
		if a.Disposition != message.DispositionAttachment || replaced[a.PartPath] || a.Filename == "" {
			continue
		}
		wantSizeByName[a.Filename] = a.Size
	}

	gotSizeByName := make(map[string]int64)
	err := message.Parse(bytes.NewReader(got), message.DefaultLimits(), func(att *message.Attachment, body io.Reader) error {
		buf, readErr := io.ReadAll(body)
		if readErr != nil {
			return readErr
		}
		if att.Filename != "" {
			gotSizeByName[att.Filename] = int64(len(buf))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("re-parse for byte-identity check: %v", err)
	}

	for name, wantSize := range wantSizeByName {
		gotSize, ok := gotSizeByName[name]
		if !ok {
			t.Errorf("pass-through attachment %q missing from rewritten message", name)
			continue
		}
		if gotSize != wantSize {
			t.Errorf("pass-through attachment %q: decoded size changed: got %d, want %d", name, gotSize, wantSize)
		}
	}
}

func TestRewrite_MessageWithNoAttachmentsAtAll_Passthrough(t *testing.T) {
	// A message with only inline text/body parts and no attachment
	// leaves: every decision must be pass, so this hits the same
	// no-op fast path as TestRewrite_NoReplaceDecision.
	msg := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Plain message\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Hello, no attachments here.\r\n"

	atts := []message.Attachment{} // message.Parse would find none
	decision := decisionReplacingAttachments(atts)

	result, err := Rewrite(Input{
		Message:     strings.NewReader(msg),
		Attachments: atts,
		Decision:    decision,
		PackageURL:  "https://dl.example.com/p/token",
	}, testTemplates(t))
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}

	got := mustReadAll(t, result.Body)
	if string(got) != msg {
		t.Fatalf("passthrough result differs from original:\ngot:  %q\nwant: %q", got, msg)
	}
}

func testdataPath(name string) string {
	return filepath.Join("..", "message", "testdata", name)
}

// TestRewrite_SanitizesCRLFInjectionInCallerSuppliedFields is an
// end-to-end check for SR-118-1: SenderName and PackageURL are
// caller-supplied (in production, derived from envelope/message
// content such as a From: display name or a generated link) and are
// not pre-sanitized by internal/core/message the way Attachment
// filenames are. A malicious value containing CRLF must not survive
// into the rewritten message's raw bytes, since that could inject a
// forged header line or corrupt the MIME structure.
func TestRewrite_SanitizesCRLFInjectionInCallerSuppliedFields(t *testing.T) {
	path := testdataPath("multipart_mixed_basic.eml")
	raw, atts := parseTestdata(t, path)
	decision := decisionReplacingAttachments(atts, "0.2")

	const injection = "attacker\r\nX-Injected-Header: evil"

	result, err := Rewrite(Input{
		Message:     bytes.NewReader(raw),
		Attachments: atts,
		Decision:    decision,
		PackageURL:  "https://dl.example.com/p/" + injection,
		SenderName:  injection,
	}, testTemplates(t))
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}

	got := mustReadAll(t, result.Body)

	// The real injection to guard against is a standalone line of the
	// form "X-Injected-Header: evil" (i.e. the attacker's CRLF
	// successfully started a new line): check line-by-line rather than
	// substring-containment, since the sanitized value legitimately
	// still contains the words "X-Injected-Header: evil" as inert text
	// glued onto the preceding line.
	for _, line := range bytes.Split(got, []byte("\r\n")) {
		if bytes.Equal(bytes.TrimSpace(line), []byte("X-Injected-Header: evil")) {
			t.Fatalf("CRLF injection succeeded: forged standalone line %q present in output:\n%s", line, got)
		}
	}
	// The sanitized (CRLF-stripped) text must still appear somewhere
	// in the block — sanitization should remove the injection
	// characters, not silently drop the whole field.
	if !bytes.Contains(got, []byte("attackerX-Injected-Header: evil")) {
		t.Errorf("sanitized sender name not found in output (want CRLF stripped, rest preserved):\n%s", got)
	}
}

// TestRewrite_CRLFInFilename_DoesNotInjectHeader covers the same
// SR-118-1 concern for the file name listing rendered in the block:
// even though internal/core/message's own filename sanitization
// already strips control characters (decode.go's stripControlRunes),
// rewrite must not assume every caller of this package pre-sanitizes,
// so BlockFile.Name is independently sanitized before rendering (see
// BlockData.toView).
func TestRewrite_CRLFInFilename_DoesNotInjectHeader(t *testing.T) {
	tmpl := testTemplates(t)

	data := BlockData{
		Files:      []BlockFile{{Name: "evil\r\nX-Injected: yes.txt", Size: 10}},
		PackageURL: "https://dl.example.com/p/abc",
	}

	plainText, html, err := renderBlock(tmpl, data)
	if err != nil {
		t.Fatalf("renderBlock: %v", err)
	}

	for _, out := range []string{plainText, html} {
		if strings.Contains(out, "X-Injected:") && strings.Contains(out, "\r\nX-Injected") {
			t.Errorf("CRLF survived into rendered block, injection possible:\n%s", out)
		}
	}
}
