package policy

import (
	"testing"

	"github.com/302-digital/attachra/internal/core/message"
)

func mustGlob(t *testing.T, pattern string) glob {
	t.Helper()
	g, err := compileGlob(pattern)
	if err != nil {
		t.Fatalf("compileGlob(%q) returned error: %v", pattern, err)
	}
	return g
}

func TestGlob_CaseInsensitiveMatch(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		{"*.exe", "INVOICE.EXE", true},
		{"*.exe", "invoice.pdf", false},
		{"finance-*@example.com", "Finance-Bob@Example.COM", true},
		{"*@*.example.com", "user@eu.example.com", true},
		{"*@*.example.com", "user@example.com", false}, // no subdomain
		{"invoice-*.pdf", "invoice-2024-Q1.pdf", true},
		{"a?c", "abc", true},
		{"a?c", "abcd", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.input, func(t *testing.T) {
			g := mustGlob(t, tt.pattern)
			if got := g.match(tt.input); got != tt.want {
				t.Errorf("glob(%q).match(%q) = %v, want %v", tt.pattern, tt.input, got, tt.want)
			}
		})
	}
}

func TestCompileGlob_InvalidPattern(t *testing.T) {
	if _, err := compileGlob("[unclosed"); err == nil {
		t.Fatal("compileGlob returned nil error for a malformed pattern")
	}
}

// TestMatchAddress covers §2.3.1: address (exact), domain (exact, no
// subdomain), pattern (glob), all case-insensitive, and OR semantics
// across and within fields.
func TestMatchAddress(t *testing.T) {
	tests := []struct {
		name string
		m    *AddressMatch
		addr string
		want bool
	}{
		{"nil matches everything", nil, "anyone@example.com", true},
		{"exact address match", &AddressMatch{Address: []string{"ceo@example.com"}}, "CEO@Example.com", true},
		{"exact address mismatch", &AddressMatch{Address: []string{"ceo@example.com"}}, "cfo@example.com", false},
		{"domain match", &AddressMatch{Domain: []string{"example.com"}}, "bob@EXAMPLE.COM", true},
		{"domain does not match subdomain", &AddressMatch{Domain: []string{"example.com"}}, "bob@eu.example.com", false},
		{"pattern subdomain match", &AddressMatch{Pattern: []string{"*@*.example.com"}}, "bob@eu.example.com", true},
		{"pattern subdomain mismatch bare domain", &AddressMatch{Pattern: []string{"*@*.example.com"}}, "bob@example.com", false},
		{
			"OR across fields: address or domain",
			&AddressMatch{Address: []string{"ceo@example.com"}, Domain: []string{"partner.com"}},
			"bob@partner.com",
			true,
		},
		{
			"OR within field: multiple domains",
			&AddressMatch{Domain: []string{"a.com", "b.com"}},
			"user@b.com",
			true,
		},
		{"empty AddressMatch matches nothing", &AddressMatch{}, "anyone@example.com", false},
		{
			"finance subdomain pattern (scenario b)",
			&AddressMatch{Pattern: []string{"*@finance.example.com"}},
			"alice@finance.example.com",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchAddress(tt.m, tt.addr); got != tt.want {
				t.Errorf("matchAddress(%+v, %q) = %v, want %v", tt.m, tt.addr, got, tt.want)
			}
		})
	}
}

// TestMatchSize covers §2.3.2 inclusive min/max bounds, including
// exact boundary values.
func TestMatchSize(t *testing.T) {
	mb10 := Bound(10_000_000)
	mb1 := Bound(1_000_000)

	tests := []struct {
		name string
		r    *SizeRange
		size int64
		want bool
	}{
		{"nil range matches everything", nil, 0, true},
		{"min inclusive boundary", &SizeRange{Min: &mb10}, 10_000_000, true},
		{"just below min", &SizeRange{Min: &mb10}, 9_999_999, false},
		{"max inclusive boundary", &SizeRange{Max: &mb10}, 10_000_000, true},
		{"just above max", &SizeRange{Max: &mb10}, 10_000_001, false},
		{"within min/max range", &SizeRange{Min: &mb1, Max: &mb10}, 5_000_000, true},
		{"zero size within unbounded range", &SizeRange{}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchSize(tt.r, tt.size); got != tt.want {
				t.Errorf("matchSize(%+v, %d) = %v, want %v", tt.r, tt.size, got, tt.want)
			}
		})
	}
}

func TestExtensionOf(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"invoice.PDF", "pdf"},
		{"archive.tar.gz", "gz"},
		{"noext", ""},
		{"trailing.", ""},
		{"έγγραφο.docx", "docx"}, // Greek filename, ASCII extension
		{"文档.exe", "exe"},        // CJK filename
		{"résumé.pdf", "pdf"},    // accented filename
		{".hidden", "hidden"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			if got := extensionOf(tt.filename); got != tt.want {
				t.Errorf("extensionOf(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

// TestMatchAttachment covers §2.3.2: AND across fields within
// AttachmentMatch, OR within a single field's list, unicode filenames
// and glob matching on filename/mime types.
func TestMatchAttachment(t *testing.T) {
	mb10 := Bound(10_000_000)

	tests := []struct {
		name string
		m    *AttachmentMatch
		att  message.Attachment
		want bool
	}{
		{
			"nil matches everything",
			nil,
			message.Attachment{Filename: "a.pdf"},
			true,
		},
		{
			"AND: mime_type and size both must match",
			&AttachmentMatch{MimeType: []string{"application/pdf"}, Size: &SizeRange{Min: &mb10}},
			message.Attachment{DetectedType: "application/pdf", Size: 20_000_000},
			true,
		},
		{
			"AND: size fails even though mime_type matches",
			&AttachmentMatch{MimeType: []string{"application/pdf"}, Size: &SizeRange{Min: &mb10}},
			message.Attachment{DetectedType: "application/pdf", Size: 1_000},
			false,
		},
		{
			"mime_type glob wildcard",
			&AttachmentMatch{MimeType: []string{"image/*"}},
			message.Attachment{DetectedType: "image/png"},
			true,
		},
		{
			"claimed vs real mime type spoof detection",
			&AttachmentMatch{ClaimedMimeType: []string{"image/png"}, MimeType: []string{"application/vnd.microsoft.portable-executable"}},
			message.Attachment{DeclaredType: "image/png", DetectedType: "application/vnd.microsoft.portable-executable"},
			true,
		},
		{
			"extension OR list",
			&AttachmentMatch{Extension: []string{"exe", "js", "scr", "bat", "cmd"}},
			message.Attachment{Filename: "payload.JS"},
			true,
		},
		{
			"extension no match",
			&AttachmentMatch{Extension: []string{"exe"}},
			message.Attachment{Filename: "report.pdf"},
			false,
		},
		{
			"filename glob",
			&AttachmentMatch{Filename: []string{"invoice-*.pdf"}},
			message.Attachment{Filename: "invoice-2024.pdf"},
			true,
		},
		{
			"unicode filename glob match",
			&AttachmentMatch{Filename: []string{"*.pdf"}},
			message.Attachment{Filename: "τιμολόγιο.pdf"},
			true,
		},
		{
			"unicode filename extension match",
			&AttachmentMatch{Extension: []string{"docx"}},
			message.Attachment{Filename: "αναφορά_2024.docx"},
			true,
		},
		{
			"unicode filename via extension mismatch",
			&AttachmentMatch{Extension: []string{"exe"}},
			message.Attachment{Filename: "文档.docx"},
			false,
		},
		{
			"empty attachment section matches any attachment (scenario e)",
			&AttachmentMatch{},
			message.Attachment{Filename: "anything.bin", Size: 1},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchAttachment(tt.m, tt.att); got != tt.want {
				t.Errorf("matchAttachment(%+v, %+v) = %v, want %v", tt.m, tt.att, got, tt.want)
			}
		})
	}
}

// TestMatchDisposition covers ADR-016 §2.3.2: disposition matches the
// EFFECTIVE classification (message.Attachment.InlineAsset), not the
// raw Content-Disposition header — an attachment explicitly marked
// Content-Disposition: inline (e.g. Apple Mail style) but with no
// Content-ID/multipart-related membership must still match
// "attachment", never "inline".
func TestMatchDisposition(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		att      message.Attachment
		want     bool
	}{
		{"nil/empty patterns match everything", nil, message.Attachment{InlineAsset: true}, true},
		{"inline pattern matches InlineAsset part", []string{"inline"}, message.Attachment{InlineAsset: true}, true},
		{"inline pattern does not match non-InlineAsset part", []string{"inline"}, message.Attachment{InlineAsset: false}, false},
		{"attachment pattern matches non-InlineAsset part", []string{"attachment"}, message.Attachment{InlineAsset: false}, true},
		{"attachment pattern does not match InlineAsset part", []string{"attachment"}, message.Attachment{InlineAsset: true}, false},
		{"case-insensitive", []string{"INLINE"}, message.Attachment{InlineAsset: true}, true},
		{
			"raw Content-Disposition header is ignored: Apple Mail-style inline attachment with filename",
			[]string{"attachment"},
			message.Attachment{Disposition: message.DispositionInline, Filename: "doc.pdf", InlineAsset: false},
			true,
		},
		{
			"raw Content-Disposition header is ignored: attachment-marked but InlineAsset-classified part",
			[]string{"inline"},
			message.Attachment{Disposition: message.DispositionAttachment, InlineAsset: true},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchDisposition(tt.patterns, tt.att); got != tt.want {
				t.Errorf("matchDisposition(%v, %+v) = %v, want %v", tt.patterns, tt.att, got, tt.want)
			}
		})
	}
}

// TestMatchWhen covers §2.3: AND across sections (sender AND
// recipient AND attachment), and the catch-all nil When (§3.3).
func TestMatchWhen(t *testing.T) {
	att := message.Attachment{Filename: "payload.exe", Size: 100}

	tests := []struct {
		name      string
		w         *When
		sender    string
		recipient string
		att       message.Attachment
		want      bool
	}{
		{"nil When is catch-all", nil, "a@a.com", "b@b.com", att, true},
		{
			"AND across sections: all match",
			&When{
				Sender:     &AddressMatch{Domain: []string{"a.com"}},
				Recipient:  &AddressMatch{Domain: []string{"b.com"}},
				Attachment: &AttachmentMatch{Extension: []string{"exe"}},
			},
			"user@a.com", "user@b.com", att, true,
		},
		{
			"AND across sections: recipient fails",
			&When{
				Sender:    &AddressMatch{Domain: []string{"a.com"}},
				Recipient: &AddressMatch{Domain: []string{"other.com"}},
			},
			"user@a.com", "user@b.com", att, false,
		},
		{
			"absent section does not narrow the match",
			&When{Sender: &AddressMatch{Domain: []string{"a.com"}}},
			"user@a.com", "anyone@anywhere.com", att, true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchWhen(tt.w, tt.sender, tt.recipient, tt.att); got != tt.want {
				t.Errorf("matchWhen(...) = %v, want %v", got, tt.want)
			}
		})
	}
}
