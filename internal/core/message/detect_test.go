package message

import (
	"strings"
	"testing"
)

func TestDetectType(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "pdf",
			data: append([]byte("%PDF-1.4\n"), []byte("rest of pdf content")...),
			want: "application/pdf",
		},
		{
			name: "pe executable",
			data: []byte("MZ\x90\x00\x03\x00\x00\x00rest"),
			want: "application/vnd.microsoft.portable-executable",
		},
		{
			name: "elf",
			data: []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00},
			want: "application/x-elf",
		},
		{
			name: "mach-o 64-bit",
			data: []byte{0xfe, 0xed, 0xfa, 0xcf, 0x07, 0x00, 0x00, 0x01},
			want: "application/x-mach-binary",
		},
		{
			name: "mach-o universal",
			data: []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02},
			want: "application/x-mach-binary",
		},
		{
			name: "rar v1.5+",
			data: []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00, 0x01},
			want: "application/vnd.rar",
		},
		{
			name: "rar v5+",
			data: []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00},
			want: "application/vnd.rar",
		},
		{
			name: "7z",
			data: []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04},
			want: "application/x-7z-compressed",
		},
		{
			name: "gzip",
			data: []byte{0x1f, 0x8b, 0x08, 0x00},
			want: "application/gzip",
		},
		{
			name: "plain zip",
			data: []byte{'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 'r', 'a', 'n', 'd', 'o', 'm', '.', 't', 'x', 't'},
			want: "application/zip",
		},
		{
			name: "docx via word/ marker",
			data: buildZipLike("word/document.xml"),
			want: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		},
		{
			name: "xlsx via xl/ marker",
			data: buildZipLike("xl/workbook.xml"),
			want: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		},
		{
			name: "pptx via ppt/ marker",
			data: buildZipLike("ppt/presentation.xml"),
			want: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		},
		{
			name: "plain text falls back to stdlib sniffing",
			data: []byte("hello, this is plain text content"),
			want: "text/plain; charset=utf-8",
		},
		{
			name: "empty data",
			data: []byte{},
			want: "text/plain; charset=utf-8",
		},
		{
			name: "png still detected by stdlib",
			data: []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00},
			want: "image/png",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectType(tt.data)
			if got != tt.want {
				t.Errorf("DetectType(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestDetectType_TruncatesToSniffLen(t *testing.T) {
	data := make([]byte, sniffLen+1000)
	copy(data, []byte("%PDF-1.4\n"))
	if got := DetectType(data); got != "application/pdf" {
		t.Errorf("DetectType with oversized input = %q, want application/pdf", got)
	}
}

// TestDetectType_SVGIsNotImageWildcard is a regression latch, not a
// feature test: SVG (an XML document, potentially carrying
// <script>/event-handler active content) has no signature in this
// package's table today, so it falls through to
// http.DetectContentType and is reported as "text/xml; charset=utf-8"
// or "text/plain; charset=utf-8" -- never "image/*". This matters
// beyond DetectType itself: ADR-016's inline-asset protective
// downgrade (pipeline.protectInlineAssets) gates on
// strings.HasPrefix(att.DetectedType, "image/"), so if a future change
// ever added an SVG magic-byte signature reporting "image/svg+xml",
// that would silently let active-content SVG ride through the
// protective downgrade as an InlineAsset the same way a PNG/JPEG does.
// This test exists so that future change trips a failing assertion
// here forcing a deliberate decision, rather than silently changing
// ADR-016's threat surface.
func TestDetectType_SVGIsNotImageWildcard(t *testing.T) {
	svg := []byte(`<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	if got := DetectType(svg); strings.HasPrefix(got, "image/") {
		t.Errorf("DetectType(svg) = %q, want NOT image/* -- ADR-016's inline-asset protective downgrade gates on this prefix; an SVG signature must not be added here without revisiting that decision (active content risk)", got)
	}
}

func TestDetectType_NoRecursiveArchiveInspection(t *testing.T) {
	// SR-117-4: detection must not decompress archive members. A zip
	// signature with no recognizable office marker in its sniffed
	// prefix must be reported as generic zip, not as whatever the
	// (unread) compressed content contains.
	data := buildZipLike("some/other/path.bin")
	if got := DetectType(data); got != "application/zip" {
		t.Errorf("DetectType = %q, want application/zip (no archive inspection)", got)
	}
}

// buildZipLike constructs a minimal byte sequence resembling a ZIP
// local file header followed by an entry name, sufficient for
// detectOfficeOpenXML's marker search without being a valid ZIP file.
func buildZipLike(entryName string) []byte {
	header := []byte{'P', 'K', 0x03, 0x04}
	header = append(header, make([]byte, 26)...) // rest of local file header, unused by detection
	header = append(header, []byte(entryName)...)
	return header
}
