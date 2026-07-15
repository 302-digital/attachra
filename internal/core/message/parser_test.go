package message

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// leafSummary is a comparable, test-friendly projection of an
// Attachment plus its observed body, used to assert golden results
// without depending on Attachment's exact zero-value shape.
type leafSummary struct {
	partPath     string
	filename     string
	declaredType string
	detectedType string
	disposition  Disposition
	size         int64
	contentID    string
	inlineAsset  bool
}

// collectLeaves runs Parse over data with the given limits, sniffing
// DetectedType from each leaf's decoded body, and returns the leaves
// in document order.
func collectLeaves(t *testing.T, data []byte, limits Limits) ([]leafSummary, error) {
	t.Helper()

	// Attachment.Size is finalized by Parse only after PartFunc
	// returns (it reflects bytes read by the callback plus any it
	// left unread that Parse then drains), so pointers to the
	// Attachment values are collected here and turned into summaries
	// after Parse itself returns.
	var atts []*Attachment
	err := Parse(bytes.NewReader(data), limits, func(att *Attachment, body io.Reader) error {
		content, readErr := io.ReadAll(body)
		if readErr != nil {
			return readErr
		}
		att.DetectedType = DetectType(content)
		atts = append(atts, att)
		return nil
	})

	leaves := make([]leafSummary, len(atts))
	for i, att := range atts {
		leaves[i] = leafSummary{
			partPath:     att.PartPath,
			filename:     att.Filename,
			declaredType: att.DeclaredType,
			detectedType: att.DetectedType,
			disposition:  att.Disposition,
			size:         att.Size,
			contentID:    att.ContentID,
			inlineAsset:  att.InlineAsset,
		}
	}
	return leaves, err
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // fixed test fixture directory, not attacker-controlled
	if err != nil {
		t.Fatalf("read testdata %q: %v", name, err)
	}
	return data
}

// TestParse_GoldenCorpus asserts the exact set of leaf parts Parse
// discovers for each synthetic fixture in testdata/, covering
// US-3.1's acceptance criteria: multipart structures of any nesting,
// inline vs attachment, declared vs detected type, and RFC 2231/2047
// filenames (ATR-159).
func TestParse_GoldenCorpus(t *testing.T) {
	tests := []struct {
		file string
		want []leafSummary
	}{
		{
			file: "multipart_mixed_basic.eml",
			want: []leafSummary{
				{partPath: "0.1", declaredType: "text/plain", detectedType: "text/plain; charset=utf-8", disposition: DispositionInline, size: 41},
				{partPath: "0.2", filename: "report.pdf", declaredType: "application/pdf", detectedType: "application/pdf", disposition: DispositionAttachment, size: 46},
			},
		},
		{
			file: "multipart_related_alternative.eml",
			want: []leafSummary{
				{partPath: "0.1.1.1", declaredType: "text/plain", detectedType: "text/plain; charset=utf-8", disposition: DispositionInline, size: 21},
				{partPath: "0.1.1.2", declaredType: "text/html", detectedType: "text/html; charset=utf-8", disposition: DispositionInline, size: 50},
				{partPath: "0.1.2", filename: "logo.png", declaredType: "image/png", detectedType: "image/png", disposition: DispositionInline, size: 27, contentID: "logo123", inlineAsset: true},
				{partPath: "0.2", filename: "attachment.pdf", declaredType: "application/pdf", detectedType: "application/pdf", disposition: DispositionAttachment, size: 27},
			},
		},
		{
			file: "nested_message_rfc822.eml",
			want: []leafSummary{
				{partPath: "0.1", declaredType: "text/plain", detectedType: "text/plain; charset=utf-8", disposition: DispositionInline, size: 30},
				{partPath: "0.2.1", declaredType: "text/plain", detectedType: "text/plain; charset=utf-8", disposition: DispositionInline, size: 36},
				{partPath: "0.2.2", filename: "archive.zip", declaredType: "application/zip", detectedType: "application/zip", disposition: DispositionAttachment, size: 25},
			},
		},
		{
			file: "inline_image.eml",
			want: []leafSummary{
				{partPath: "0.1", declaredType: "text/html", detectedType: "text/html; charset=utf-8", disposition: DispositionInline, size: 50},
				{partPath: "0.2", declaredType: "image/jpeg", detectedType: "image/jpeg", disposition: DispositionInline, size: 24, contentID: "img001", inlineAsset: true},
			},
		},
		{
			file: "filename_rfc2231_greek.eml",
			want: []leafSummary{
				{partPath: "0.1", declaredType: "text/plain", detectedType: "text/plain; charset=utf-8", disposition: DispositionInline, size: 15},
				{partPath: "0.2", filename: "αναφορά.pdf", declaredType: "application/pdf", detectedType: "application/pdf", disposition: DispositionAttachment, size: 30},
			},
		},
		{
			file: "filename_rfc2047_greek.eml",
			want: []leafSummary{
				{partPath: "0.1", declaredType: "text/plain", detectedType: "text/plain; charset=utf-8", disposition: DispositionInline, size: 15},
				{partPath: "0.2", filename: "αναφορά.pdf", declaredType: "application/pdf", detectedType: "application/pdf", disposition: DispositionAttachment, size: 30},
			},
		},
		{
			file: "attachment_no_filename.eml",
			want: []leafSummary{
				{partPath: "0.1", declaredType: "text/plain", detectedType: "text/plain; charset=utf-8", disposition: DispositionInline, size: 15},
				{partPath: "0.2", declaredType: "application/octet-stream", detectedType: "text/plain; charset=utf-8", disposition: DispositionAttachment, size: 22},
			},
		},
		{
			file: "attachment_zero_byte.eml",
			want: []leafSummary{
				{partPath: "0.1", declaredType: "text/plain", detectedType: "text/plain; charset=utf-8", disposition: DispositionInline, size: 26},
				{partPath: "0.2", filename: "empty.bin", declaredType: "application/octet-stream", detectedType: "text/plain; charset=utf-8", disposition: DispositionAttachment, size: 0},
			},
		},
		{
			file: "declared_text_actual_pe.eml",
			want: []leafSummary{
				{partPath: "0.1", declaredType: "text/plain", detectedType: "text/plain; charset=utf-8", disposition: DispositionInline, size: 25},
				{partPath: "0.2", filename: "notes.txt", declaredType: "text/plain", detectedType: "application/vnd.microsoft.portable-executable", disposition: DispositionAttachment, size: 41},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data := readTestdata(t, tt.file)
			got, err := collectLeaves(t, data, Limits{})
			if err != nil {
				t.Fatalf("Parse(%s) error = %v, want nil", tt.file, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Parse(%s) leaves = %+v, want %+v", tt.file, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Parse(%s) leaf[%d] = %+v, want %+v", tt.file, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestParse_DeclaredVsDetectedMismatch is the core SR-117-4 /
// US-3.1 acceptance scenario: a part declares text/plain but its
// bytes are a PE executable, and DetectType must catch it.
func TestParse_DeclaredVsDetectedMismatch(t *testing.T) {
	data := readTestdata(t, "declared_text_actual_pe.eml")
	leaves, err := collectLeaves(t, data, Limits{})
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	var found bool
	for _, l := range leaves {
		if l.filename != "notes.txt" {
			continue
		}
		found = true
		if l.declaredType != "text/plain" {
			t.Errorf("declaredType = %q, want text/plain", l.declaredType)
		}
		if l.detectedType == l.declaredType {
			t.Errorf("detectedType = %q, want a mismatch from declaredType", l.detectedType)
		}
		if l.detectedType != "application/vnd.microsoft.portable-executable" {
			t.Errorf("detectedType = %q, want PE executable type", l.detectedType)
		}
	}
	if !found {
		t.Fatal("expected to find notes.txt attachment")
	}
}

// TestParse_AllLeavesVisited asserts SR-117-3: every leaf part is
// visited, both inline and attachment, across a mixed-disposition
// tree.
func TestParse_AllLeavesVisited(t *testing.T) {
	data := readTestdata(t, "multipart_related_alternative.eml")
	leaves, err := collectLeaves(t, data, Limits{})
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	var inlineCount, attachmentCount int
	for _, l := range leaves {
		switch l.disposition {
		case DispositionInline:
			inlineCount++
		case DispositionAttachment:
			attachmentCount++
		}
	}
	if inlineCount == 0 {
		t.Error("expected at least one inline leaf part")
	}
	if attachmentCount == 0 {
		t.Error("expected at least one attachment leaf part")
	}
}

// TestNormalizeContentID covers ATR-305/ADR-016: a Content-ID header
// value is normalized by stripping optional angle brackets and
// surrounding whitespace, and an absent/empty header normalizes to "".
func TestNormalizeContentID(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"with angle brackets", "<logo123@example.com>", "logo123@example.com"},
		{"without angle brackets", "logo123@example.com", "logo123@example.com"},
		{"surrounding whitespace", "  <logo123@example.com>  ", "logo123@example.com"},
		{"empty", "", ""},
		{"only whitespace", "   ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeContentID(tt.raw); got != tt.want {
				t.Errorf("normalizeContentID(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// TestParse_InlineAssetClassification covers ADR-016's InlineAsset
// classification rule: a part is InlineAsset iff it carries a
// Content-ID AND its immediate parent container is multipart/related.
// Content-ID alone (no multipart/related parent) and multipart/related
// membership alone (no Content-ID) must each fail to classify a part
// as an InlineAsset — only both signals together do.
func TestParse_InlineAssetClassification(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]bool // partPath -> want InlineAsset
	}{
		{
			name: "Content-ID inside multipart/related is InlineAsset",
			raw: "From: a@example.com\r\n" +
				"To: b@example.com\r\n" +
				"Content-Type: multipart/related; boundary=\"B\"\r\n" +
				"\r\n" +
				"--B\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n" +
				"<img src=\"cid:logo123\">\r\n" +
				"--B\r\n" +
				"Content-Type: image/png\r\n" +
				"Content-ID: <logo123>\r\n" +
				"\r\n" +
				"pngbytes\r\n" +
				"--B--\r\n",
			want: map[string]bool{"0.1": false, "0.2": true},
		},
		{
			name: "Content-ID without multipart/related parent is not InlineAsset",
			raw: "From: a@example.com\r\n" +
				"To: b@example.com\r\n" +
				"Content-Type: multipart/mixed; boundary=\"B\"\r\n" +
				"\r\n" +
				"--B\r\n" +
				"Content-Type: text/plain\r\n" +
				"\r\n" +
				"body\r\n" +
				"--B\r\n" +
				"Content-Type: image/png\r\n" +
				"Content-Disposition: attachment; filename=\"logo.png\"\r\n" +
				"Content-ID: <logo123>\r\n" +
				"\r\n" +
				"pngbytes\r\n" +
				"--B--\r\n",
			want: map[string]bool{"0.1": false, "0.2": false},
		},
		{
			name: "multipart/related membership without Content-ID is not InlineAsset",
			raw: "From: a@example.com\r\n" +
				"To: b@example.com\r\n" +
				"Content-Type: multipart/related; boundary=\"B\"\r\n" +
				"\r\n" +
				"--B\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n" +
				"<img src=\"logo.png\">\r\n" +
				"--B\r\n" +
				"Content-Type: image/png\r\n" +
				"\r\n" +
				"pngbytes\r\n" +
				"--B--\r\n",
			want: map[string]bool{"0.1": false, "0.2": false},
		},
		{
			name: "nested mixed/related/alternative: InlineAsset only for the related child with a Content-ID",
			raw: "From: a@example.com\r\n" +
				"To: b@example.com\r\n" +
				"Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n" +
				"\r\n" +
				"--OUTER\r\n" +
				"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
				"\r\n" +
				"--REL\r\n" +
				"Content-Type: multipart/alternative; boundary=\"ALT\"\r\n" +
				"\r\n" +
				"--ALT\r\n" +
				"Content-Type: text/plain\r\n" +
				"\r\n" +
				"plain\r\n" +
				"--ALT\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n" +
				"<img src=\"cid:logo123\">\r\n" +
				"--ALT--\r\n" +
				"--REL\r\n" +
				"Content-Type: image/png\r\n" +
				"Content-ID: <logo123>\r\n" +
				"\r\n" +
				"pngbytes\r\n" +
				"--REL--\r\n" +
				"--OUTER\r\n" +
				"Content-Type: application/pdf\r\n" +
				"Content-Disposition: attachment; filename=\"doc.pdf\"\r\n" +
				"\r\n" +
				"pdfbytes\r\n" +
				"--OUTER--\r\n",
			want: map[string]bool{"0.1.1.1": false, "0.1.1.2": false, "0.1.2": true, "0.2": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaves, err := collectLeaves(t, []byte(tt.raw), Limits{})
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			got := make(map[string]bool, len(leaves))
			for _, l := range leaves {
				got[l.partPath] = l.inlineAsset
			}
			for path, want := range tt.want {
				if got[path] != want {
					t.Errorf("part %q InlineAsset = %v, want %v (all parts: %+v)", path, got[path], want, got)
				}
			}
		})
	}
}

// TestParse_DepthLimit covers SR-117-1: exceeding the configured
// depth limit returns a typed *LimitError, and a tree within the
// limit succeeds.
func TestParse_DepthLimit(t *testing.T) {
	t.Run("within limit succeeds", func(t *testing.T) {
		data := readTestdata(t, "deep_nesting_within_limit.eml")
		_, err := collectLeaves(t, data, Limits{MaxDepth: 10})
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}
	})

	t.Run("exceeding limit returns typed LimitError", func(t *testing.T) {
		data := readTestdata(t, "deep_nesting_exceeds_limit.eml")
		_, err := collectLeaves(t, data, Limits{MaxDepth: 10})
		if err == nil {
			t.Fatal("Parse() error = nil, want depth LimitError")
		}
		var limitErr *LimitError
		if !errors.As(err, &limitErr) {
			t.Fatalf("Parse() error = %v (%T), want *LimitError", err, err)
		}
		if limitErr.Kind != LimitDepth {
			t.Errorf("LimitError.Kind = %q, want %q", limitErr.Kind, LimitDepth)
		}
		if limitErr.Limit != 10 {
			t.Errorf("LimitError.Limit = %d, want 10", limitErr.Limit)
		}
	})

	t.Run("stricter limit rejects an otherwise-ok tree", func(t *testing.T) {
		data := readTestdata(t, "deep_nesting_within_limit.eml")
		_, err := collectLeaves(t, data, Limits{MaxDepth: 2})
		var limitErr *LimitError
		if !errors.As(err, &limitErr) || limitErr.Kind != LimitDepth {
			t.Fatalf("Parse() error = %v, want depth LimitError", err)
		}
	})
}

// TestParse_PartsLimit covers SR-117-1's part-count budget.
func TestParse_PartsLimit(t *testing.T) {
	data := readTestdata(t, "many_parts.eml")

	t.Run("sufficient limit succeeds", func(t *testing.T) {
		leaves, err := collectLeaves(t, data, Limits{MaxParts: 1000})
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}
		if len(leaves) != 50 {
			t.Errorf("len(leaves) = %d, want 50", len(leaves))
		}
	})

	t.Run("insufficient limit returns typed LimitError", func(t *testing.T) {
		_, err := collectLeaves(t, data, Limits{MaxParts: 10})
		var limitErr *LimitError
		if !errors.As(err, &limitErr) {
			t.Fatalf("Parse() error = %v, want *LimitError", err)
		}
		if limitErr.Kind != LimitParts {
			t.Errorf("LimitError.Kind = %q, want %q", limitErr.Kind, LimitParts)
		}
	})
}

// TestParse_HeaderCountLimit covers SR-117-2's header-count budget.
func TestParse_HeaderCountLimit(t *testing.T) {
	data := readTestdata(t, "multipart_mixed_basic.eml")

	_, err := collectLeaves(t, data, Limits{MaxHeaders: 1})
	var limitErr *LimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("Parse() error = %v, want *LimitError", err)
	}
	if limitErr.Kind != LimitHeaders {
		t.Errorf("LimitError.Kind = %q, want %q", limitErr.Kind, LimitHeaders)
	}
}

// TestParse_PartSizeLimit covers SR-117-2's per-part size budget:
// exceeding it while the PartFunc callback reads the body must
// surface as a typed LimitError from the callback's Read, and Parse
// must propagate it rather than swallowing it.
func TestParse_PartSizeLimit(t *testing.T) {
	data := readTestdata(t, "multipart_mixed_basic.eml")

	err := Parse(bytes.NewReader(data), Limits{MaxPartSize: 5}, func(_ *Attachment, body io.Reader) error {
		_, copyErr := io.Copy(io.Discard, body)
		return copyErr
	})
	if err == nil {
		t.Fatal("Parse() error = nil, want part size LimitError")
	}
	var limitErr *LimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("Parse() error = %v, want *LimitError", err)
	}
	if limitErr.Kind != LimitPartSize {
		t.Errorf("LimitError.Kind = %q, want %q", limitErr.Kind, LimitPartSize)
	}
}

// TestParse_PartSizeLimit_EnforcedEvenIfCallbackDoesNotRead ensures
// the size limit is still enforced by Parse's own post-callback drain
// even when a PartFunc implementation does not read the body itself
// (e.g. it only inspects headers), so a caller cannot accidentally
// bypass SR-117-2 by not reading.
func TestParse_PartSizeLimit_EnforcedEvenIfCallbackDoesNotRead(t *testing.T) {
	data := readTestdata(t, "multipart_mixed_basic.eml")

	err := Parse(bytes.NewReader(data), Limits{MaxPartSize: 5}, func(_ *Attachment, _ io.Reader) error {
		return nil // does not read body at all
	})
	var limitErr *LimitError
	if !errors.As(err, &limitErr) || limitErr.Kind != LimitPartSize {
		t.Fatalf("Parse() error = %v, want part size LimitError", err)
	}
}

// TestParse_TotalSizeLimit covers SR-117-2's cumulative message size
// budget across multiple parts.
func TestParse_TotalSizeLimit(t *testing.T) {
	data := readTestdata(t, "multipart_mixed_basic.eml")

	_, err := collectLeaves(t, data, Limits{MaxTotalSize: 10})
	var limitErr *LimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("Parse() error = %v, want *LimitError", err)
	}
	if limitErr.Kind != LimitTotalSize {
		t.Errorf("LimitError.Kind = %q, want %q", limitErr.Kind, LimitTotalSize)
	}
}

// TestParse_MalformedBoundary asserts that a multipart Content-Type
// missing its boundary parameter is a parse error (not a panic and
// not a silently-empty attachment list).
func TestParse_MalformedBoundary(t *testing.T) {
	data := readTestdata(t, "malformed_missing_boundary.eml")
	_, err := collectLeaves(t, data, Limits{})
	if err == nil {
		t.Fatal("Parse() error = nil, want error for missing boundary")
	}
}

// TestParse_PartFuncError asserts that an error returned by PartFunc
// aborts the walk and is surfaced from Parse.
func TestParse_PartFuncError(t *testing.T) {
	data := readTestdata(t, "multipart_mixed_basic.eml")
	sentinel := errors.New("callback refused part")

	callCount := 0
	err := Parse(bytes.NewReader(data), Limits{}, func(_ *Attachment, _ io.Reader) error {
		callCount++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Parse() error = %v, want wrapped sentinel", err)
	}
	if callCount != 1 {
		t.Errorf("PartFunc called %d times, want exactly 1 (walk should abort)", callCount)
	}
}

// TestParse_MalformedContentTypeDefaultsToTextPlain covers walkPart's
// lenient fallback: a part whose Content-Type is present but
// unparsable is still walked (as text/plain) rather than aborting the
// whole message.
func TestParse_MalformedContentTypeDefaultsToTextPlain(t *testing.T) {
	msg := "From: a@example.com\r\nContent-Type: ;;;\r\n\r\nbody content\r\n"

	leaves, err := collectLeaves(t, []byte(msg), Limits{})
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil (lenient fallback)", err)
	}
	if len(leaves) != 1 {
		t.Fatalf("len(leaves) = %d, want 1", len(leaves))
	}
	if leaves[0].declaredType != "text/plain" {
		t.Errorf("declaredType = %q, want text/plain fallback", leaves[0].declaredType)
	}
}

// TestParse_NestedMessageHeaderCountLimit covers SR-117-2 applied to
// headers of a nested message/rfc822 envelope, not just the top-level
// message or a plain multipart child part.
func TestParse_NestedMessageHeaderCountLimit(t *testing.T) {
	var extra strings.Builder
	for i := 0; i < 20; i++ {
		extra.WriteString("X-Extra: value\r\n")
	}

	inner := "From: orig@example.com\r\nTo: origrecipient@example.com\r\n" + extra.String() +
		"Content-Type: text/plain\r\n\r\ninner body\r\n"

	outer := "From: fwd@example.com\r\n" +
		"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n" +
		"--B\r\n" +
		"Content-Type: message/rfc822\r\n\r\n" +
		inner +
		"--B--\r\n"

	_, err := collectLeaves(t, []byte(outer), Limits{MaxHeaders: 5})
	var limitErr *LimitError
	if !errors.As(err, &limitErr) || limitErr.Kind != LimitHeaders {
		t.Fatalf("Parse() error = %v, want header LimitError for nested message", err)
	}
}

// TestParse_MultipartChildHeaderCountLimit covers SR-117-2 enforced
// on a regular (non-rfc822) multipart child part's own headers.
func TestParse_MultipartChildHeaderCountLimit(t *testing.T) {
	var extra strings.Builder
	for i := 0; i < 20; i++ {
		extra.WriteString("X-Extra: value\r\n")
	}

	msg := "From: a@example.com\r\n" +
		"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n" +
		"--B\r\n" +
		"Content-Type: text/plain\r\n" +
		extra.String() +
		"\r\nbody\r\n" +
		"--B--\r\n"

	_, err := collectLeaves(t, []byte(msg), Limits{MaxHeaders: 5})
	var limitErr *LimitError
	if !errors.As(err, &limitErr) || limitErr.Kind != LimitHeaders {
		t.Fatalf("Parse() error = %v, want header LimitError for multipart child", err)
	}
}

// TestParse_EntireCorpusNeverPanics runs every fixture in testdata/
// through Parse with default limits, asserting only that it never
// panics regardless of whether it errors (SR-117-5's no-panic
// guarantee extended to the whole parse path).
func TestParse_EntireCorpusNeverPanics(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".eml") {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse(%s) panicked: %v", name, r)
				}
			}()
			data := readTestdata(t, name)
			_, _ = collectLeaves(t, data, Limits{})
		})
	}
}

// TestParse_TopLevelHeaderCountLimit covers SR-117-2 applied to the
// top-level message headers themselves (not just part headers).
func TestParse_TopLevelHeaderCountLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString("X-Extra-Header-")
		b.WriteString(strings.Repeat("A", 1))
		b.WriteString(": value\r\n")
	}
	msg := "From: a@example.com\r\nTo: b@example.com\r\n" + b.String() +
		"Content-Type: text/plain\r\n\r\nbody\r\n"

	_, err := collectLeaves(t, []byte(msg), Limits{MaxHeaders: 5})
	var limitErr *LimitError
	if !errors.As(err, &limitErr) || limitErr.Kind != LimitHeaders {
		t.Fatalf("Parse() error = %v, want header LimitError", err)
	}
}

// TestParse_EmptyReader ensures a completely empty input is a plain
// error, not a panic.
func TestParse_EmptyReader(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Parse panicked on empty input: %v", r)
		}
	}()
	_, err := collectLeaves(t, []byte(""), Limits{})
	if err == nil {
		t.Fatal("Parse() error = nil, want error for empty input")
	}
}
