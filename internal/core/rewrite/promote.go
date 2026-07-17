package rewrite

import (
	"bytes"
	"fmt"
	"net/textproto"
)

// contentHeaderNames are the MIME body-description headers (in
// textproto.CanonicalMIMEHeaderKey form) that describe a single leaf
// part's body rather than a multipart envelope. When rewrite promotes a
// top-level single-part message into a multipart/mixed wrapper
// (rewriteTopLevelSinglePart), these are removed from the new top-level
// header block: they belong on the wrapped body part (or are dropped
// with it), never on the multipart envelope. Leaving a
// Content-Transfer-Encoding or Content-Disposition on the envelope would
// misdescribe the whole message (RFC 2045 §6.4: only 7bit/8bit/binary
// content-transfer-encodings are meaningful on a multipart; RFC 2183: a
// top-level Content-Disposition would mislabel the entire message).
// MIME-Version is regenerated as a fresh "1.0", so it is dropped here too
// to avoid a duplicate.
var contentHeaderNames = map[string]bool{
	"Content-Type":              true,
	"Content-Transfer-Encoding": true,
	"Content-Disposition":       true,
	"Content-Id":                true,
	"Content-Description":       true,
	"Content-Location":          true,
	"Mime-Version":              true,
}

// promoteHeaderBlock builds the top-level header block for the
// single-part-to-multipart promotion path: every original header that is
// not a per-part content header (contentHeaderNames) is preserved
// verbatim, then the synthesized "Content-Type: multipart/mixed",
// "MIME-Version: 1.0" and "X-Attachra-Processed" are appended, followed
// by the blank line that terminates the header block. The returned block
// is a valid RFC 5322 header block whose Content-Type is multipart/mixed
// (the ATR-291 fix: previously the promoted Content-Type was written by
// run() AFTER the terminating blank line, landing in the body).
//
// Preserving the original bytes of kept headers keeps them byte-identical
// for a verbatim consumer (a future SMTP proxy) and normalized-identical
// for the milter adapter's header reconciliation, which then sees exactly
// one changed header (Content-Type) and the dropped content headers as
// removed (ATR-290).
func promoteHeaderBlock(headerBytes []byte, boundary, processedID string) []byte {
	var out bytes.Buffer
	forEachHeaderField(headerBytes, func(name string, raw []byte) {
		if !contentHeaderNames[name] {
			out.Write(raw)
		}
	})

	fmt.Fprintf(&out, "Content-Type: multipart/mixed; boundary=%q\r\n", boundary)
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("X-Attachra-Processed: ")
	out.WriteString(sanitizeHeaderValue(fmt.Sprintf("version=%s; id=%s", ProcessedHeaderVersion, processedID)))
	out.WriteString("\r\n\r\n")
	return out.Bytes()
}

// contentHeaderLines returns just the per-part content headers
// (contentHeaderNames) from a raw header block, in their original order
// and exact bytes, with no terminating blank line (the caller adds it).
// It is the complement of promoteHeaderBlock's filter: the headers
// dropped from the promoted top-level block are exactly the ones that
// belong on the wrapped part carrying the (kept) original body.
func contentHeaderLines(headerBytes []byte) []byte {
	var out bytes.Buffer
	forEachHeaderField(headerBytes, func(name string, raw []byte) {
		if contentHeaderNames[name] {
			out.Write(raw)
		}
	})
	return out.Bytes()
}

// forEachHeaderField iterates the logical header fields in a raw RFC 5322
// header block (header lines plus the terminating blank line), invoking
// fn once per field with the field's canonical name and its exact raw
// bytes (the starting "Name: value" line plus any folded continuation
// lines, including trailing line endings). Iteration stops at the blank
// line that terminates the header block; that blank line is not passed to
// fn.
func forEachHeaderField(headerBytes []byte, fn func(canonicalName string, raw []byte)) {
	i, n := 0, len(headerBytes)
	for i < n {
		lineEnd := lineEndIndex(headerBytes, i)
		if isBlankLine(headerBytes[i:lineEnd]) {
			return
		}
		start := i
		i = lineEnd
		// Absorb folded continuation lines (RFC 5322 §2.2.3): a line
		// beginning with a space or tab continues the previous field.
		for i < n && (headerBytes[i] == ' ' || headerBytes[i] == '\t') {
			i = lineEndIndex(headerBytes, i)
		}
		fn(canonicalFieldName(headerBytes[start:i]), headerBytes[start:i])
	}
}

// lineEndIndex returns the index just past the '\n' terminating the line
// that starts at start, or len(b) if that line has no '\n' (the final,
// unterminated line of the buffer).
func lineEndIndex(b []byte, start int) int {
	if nl := bytes.IndexByte(b[start:], '\n'); nl >= 0 {
		return start + nl + 1
	}
	return len(b)
}

// canonicalFieldName extracts the field name (the bytes before the first
// colon) from a raw header field and returns its canonical form
// (textproto.CanonicalMIMEHeaderKey). A field with no colon (only
// possible in a malformed header block) yields "".
func canonicalFieldName(field []byte) string {
	colon := bytes.IndexByte(field, ':')
	if colon < 0 {
		return ""
	}
	return textproto.CanonicalMIMEHeaderKey(string(bytes.TrimRight(field[:colon], " \t")))
}
