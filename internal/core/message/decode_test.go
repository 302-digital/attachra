package message

import (
	"strings"
	"testing"
)

func TestExtractFilename(t *testing.T) {
	tests := []struct {
		name               string
		contentDisposition string
		contentType        string
		want               string
	}{
		{
			name:               "plain ascii filename in content-disposition",
			contentDisposition: `attachment; filename="report.pdf"`,
			want:               "report.pdf",
		},
		{
			name:               "rfc2231 extended filename with greek",
			contentDisposition: `attachment; filename*=UTF-8''%CE%B1%CE%BD%CE%B1%CF%86%CE%BF%CF%81%CE%AC.pdf`,
			want:               "αναφορά.pdf",
		},
		{
			name:               "rfc2231 continuation split filename",
			contentDisposition: `attachment; filename*0="report"; filename*1="-part2.pdf"`,
			want:               "report-part2.pdf",
		},
		{
			name:               "rfc2047 encoded-word filename",
			contentDisposition: `attachment; filename="=?UTF-8?B?zrHOvc6xz4bOv8+BzqwucGRm?="`,
			want:               "αναφορά.pdf",
		},
		{
			name:        "falls back to content-type name parameter",
			contentType: `application/pdf; name="fallback.pdf"`,
			want:        "fallback.pdf",
		},
		{
			name:               "content-disposition wins over content-type",
			contentDisposition: `attachment; filename="from-disposition.pdf"`,
			contentType:        `application/pdf; name="from-type.pdf"`,
			want:               "from-disposition.pdf",
		},
		{
			name: "no filename anywhere",
			want: "",
		},
		{
			name:               "malformed content-disposition does not panic",
			contentDisposition: `attachment; filename=`,
			want:               "",
		},
		{
			name:               "path traversal is stripped to basename",
			contentDisposition: `attachment; filename="../../etc/passwd"`,
			want:               "passwd",
		},
		{
			name:               "windows path is stripped to basename",
			contentDisposition: `attachment; filename="C:\\evil\\payload.exe"`,
			want:               "payload.exe",
		},
		{
			// Raw NUL/LF bytes inside a header parameter value make the
			// header itself malformed per RFC 5322/2045; ParseMediaType
			// rejects it outright. The important property (asserted by
			// TestExtractFilename_BrokenEncodingDoesNotPanic) is that
			// this never panics — an empty name is an acceptable,
			// safe result for genuinely malformed header syntax.
			name:               "raw control bytes in header make it unparsable, no panic",
			contentDisposition: "attachment; filename=\"evil\x00\x0aname.txt\"",
			want:               "",
		},
		{
			// Control characters that survive header parsing (e.g.
			// embedded via RFC 2047 encoded-word decoding, which
			// operates after the header has already been split into
			// well-formed key/value tokens) must still be stripped
			// from the final name (SR-117-5).
			name:               "control characters from decoded content are stripped",
			contentDisposition: `attachment; filename="=?UTF-8?Q?evil=00=0Aname=2Etxt?="`,
			want:               "evilname.txt",
		},
		{
			name:               "empty filename value",
			contentDisposition: `attachment; filename=""`,
			want:               "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFilename(tt.contentDisposition, tt.contentType)
			if got != tt.want {
				t.Errorf("extractFilename(%q, %q) = %q, want %q", tt.contentDisposition, tt.contentType, got, tt.want)
			}
		})
	}
}

func TestExtractFilename_BrokenEncodingDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("extractFilename panicked: %v", r)
		}
	}()

	inputs := []string{
		`attachment; filename="=?UNKNOWN-CHARSET?B?somegarbage?="`,
		`attachment; filename*=bogus-charset''%FF%FE%00invalid`,
		`attachment; filename*0*=UTF-8''broken%`,
		"attachment; filename=\"\xff\xfe invalid utf8\"",
		`garbage ; ; ; = = filename`,
	}

	for _, in := range inputs {
		_ = extractFilename(in, "")
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "simple", input: "report.pdf", want: "report.pdf"},
		{name: "empty", input: "", want: ""},
		{name: "dot", input: ".", want: ""},
		{name: "dotdot", input: "..", want: ""},
		{name: "unix traversal", input: "../../secret.txt", want: "secret.txt"},
		{name: "windows traversal", input: `..\..\secret.txt`, want: "secret.txt"},
		{name: "absolute unix path", input: "/etc/passwd", want: "passwd"},
		{name: "whitespace trimmed", input: "  name.txt  ", want: "name.txt"},
		{
			name:  "too long is truncated",
			input: strings.Repeat("a", maxFilenameLength+50) + ".txt",
			want:  strings.Repeat("a", maxFilenameLength),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeWords_InvalidCharsetFallsBackWithoutPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decodeWords panicked: %v", r)
		}
	}()

	got := decodeWords("=?NOT-A-REAL-CHARSET?B?AAAA?=")
	if got == "" {
		t.Error("decodeWords returned empty string for undecodable input, want a fallback string")
	}
}
