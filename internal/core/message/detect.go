package message

import (
	"bytes"
	"net/http"

	"github.com/302-digital/attachra/internal/core/spoolutil"
)

// signature is one entry in the magic-byte lookup table: a byte
// pattern to match at a given offset from the start of the content,
// and the MIME type to report when it matches.
type signature struct {
	mimeType string
	offset   int
	pattern  []byte
}

// officeAndArchiveSignatures augments http.DetectContentType with
// container/archive and executable formats it does not recognize as
// distinct types (it collapses them to generic types such as
// "application/zip" or "application/octet-stream"). Detection here is
// signature-only: no archive member is opened or decompressed
// (SR-117-4) — DOCX/XLSX are reported as their outer ZIP-based Office
// Open XML type without inspecting the ZIP's contents.
//
// Ordered most-specific-first: office documents are ZIP files with an
// extra internal marker, so they are checked ahead of the plain ZIP
// signature would otherwise win on the same prefix bytes; the shared
// zip-based check inspects deeper into the stream, which is still
// "no decompression", just reading further into the raw ZIP local
// file header bytes already available in the sniffed prefix.
var signatures = []signature{
	// PDF: "%PDF-"
	{mimeType: "application/pdf", offset: 0, pattern: []byte("%PDF-")},

	// PE (Windows executables/DLLs): "MZ"
	{mimeType: "application/vnd.microsoft.portable-executable", offset: 0, pattern: []byte("MZ")},

	// ELF (Linux executables/shared objects)
	{mimeType: "application/x-elf", offset: 0, pattern: []byte{0x7f, 'E', 'L', 'F'}},

	// Mach-O (macOS executables), 32-bit and 64-bit, both endiannesses.
	{mimeType: "application/x-mach-binary", offset: 0, pattern: []byte{0xfe, 0xed, 0xfa, 0xce}},
	{mimeType: "application/x-mach-binary", offset: 0, pattern: []byte{0xfe, 0xed, 0xfa, 0xcf}},
	{mimeType: "application/x-mach-binary", offset: 0, pattern: []byte{0xce, 0xfa, 0xed, 0xfe}},
	{mimeType: "application/x-mach-binary", offset: 0, pattern: []byte{0xcf, 0xfa, 0xed, 0xfe}},
	// Mach-O universal (fat) binary.
	{mimeType: "application/x-mach-binary", offset: 0, pattern: []byte{0xca, 0xfe, 0xba, 0xbe}},

	// RAR: "Rar!\x1a\x07\x00" (v1.5+) or "Rar!\x1a\x07\x01\x00" (v5+)
	{mimeType: "application/vnd.rar", offset: 0, pattern: []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}},
	{mimeType: "application/vnd.rar", offset: 0, pattern: []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}},

	// 7-Zip: "7z\xbc\xaf\x27\x1c"
	{mimeType: "application/x-7z-compressed", offset: 0, pattern: []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}},

	// gzip: "\x1f\x8b"
	{mimeType: "application/gzip", offset: 0, pattern: []byte{0x1f, 0x8b}},

	// Office Open XML (docx/xlsx/pptx) and legacy zip-based ODF are
	// all plain ZIP containers; without opening the archive we cannot
	// tell docx from a plain zip apart, so both are reported as the
	// generic Office Open XML type when the ZIP local-file-header's
	// first entry name suggests it, falling back to plain zip
	// otherwise. Detecting the internal entry name from the local
	// file header (bytes 30 onward) is still just reading the
	// already-sniffed prefix, not decompressing anything.
	{mimeType: "application/zip", offset: 0, pattern: []byte{'P', 'K', 0x03, 0x04}},
	{mimeType: "application/zip", offset: 0, pattern: []byte{'P', 'K', 0x05, 0x06}}, // empty archive
	{mimeType: "application/zip", offset: 0, pattern: []byte{'P', 'K', 0x07, 0x08}}, // spanned archive
}

// officeZipMarkers maps a substring found in the first ZIP local file
// header entry name to a more specific Office Open XML MIME type. This
// is a heuristic: it looks at the raw bytes already present in the
// sniffed prefix (the entry name that immediately follows a ZIP local
// file header), not at decompressed content.
var officeZipMarkers = []struct {
	marker   []byte
	mimeType string
}{
	{marker: []byte("word/"), mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	{marker: []byte("xl/"), mimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
	{marker: []byte("ppt/"), mimeType: "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
	{marker: []byte("[Content_Types].xml"), mimeType: "application/vnd.openxmlformats-officedocument"},
}

// DetectType determines the real content type of data from its
// leading bytes (magic bytes), independent of any declared
// Content-Type (SR-117-4). It bases its result on the stdlib
// http.DetectContentType and layers on additional signatures for
// common office, archive and executable formats that
// http.DetectContentType does not distinguish.
//
// Detection never inspects more than the leading spoolutil.SniffLen
// bytes and never decompresses or opens archive members: a ZIP-based
// office document is identified by the file name of its first ZIP
// entry as present verbatim in the raw sniffed bytes, not by
// extracting it. Callers should pass at least spoolutil.SniffLen bytes
// when available; fewer bytes are accepted and simply reduce detection
// accuracy.
func DetectType(data []byte) string {
	if len(data) > spoolutil.SniffLen {
		data = data[:spoolutil.SniffLen]
	}

	for _, sig := range signatures {
		if matchesAt(data, sig.offset, sig.pattern) {
			if sig.mimeType == "application/zip" {
				if specific, ok := detectOfficeOpenXML(data); ok {
					return specific
				}
			}
			return sig.mimeType
		}
	}

	return http.DetectContentType(data)
}

// matchesAt reports whether pattern occurs in data starting at
// offset.
func matchesAt(data []byte, offset int, pattern []byte) bool {
	if offset < 0 || offset+len(pattern) > len(data) {
		return false
	}
	return bytes.Equal(data[offset:offset+len(pattern)], pattern)
}

// detectOfficeOpenXML looks for a known Office Open XML internal path
// marker within the sniffed ZIP prefix to refine a generic
// "application/zip" detection into the specific docx/xlsx/pptx MIME
// type, without decompressing anything.
func detectOfficeOpenXML(data []byte) (string, bool) {
	for _, m := range officeZipMarkers {
		if bytes.Contains(data, m.marker) {
			return m.mimeType, true
		}
	}
	return "", false
}
