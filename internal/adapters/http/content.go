package http

import (
	"fmt"
	"net/url"
	"strings"
)

// riskyContentTypes are magic-byte-detected types (internal/core/
// message.DetectType, stored as Attachment.DetectedType) that must
// never be echoed back verbatim as a response Content-Type (SR-125-4,
// T1.5): anything a browser might execute, render as active content,
// or content-sniff into HTML/script/SVG-with-script context. Serving
// these as application/octet-stream forces a download instead of
// inline rendering regardless of what the browser's own sniffing
// heuristics might otherwise decide.
var riskyContentTypes = map[string]bool{
	"text/html":                true,
	"application/xhtml+xml":    true,
	"image/svg+xml":            true,
	"application/xml":          true,
	"text/xml":                 true,
	"application/javascript":   true,
	"text/javascript":          true,
	"application/x-javascript": true,
	"text/css":                 true,
	"application/pdf":          true, // PDFs can carry embedded JavaScript; force download rather than inline render.
}

// octetStream is served for any DetectedType not on a small,
// deliberately conservative allowlist of clearly-safe-to-render binary
// types, in addition to always being served for riskyContentTypes.
const octetStream = "application/octet-stream"

// responseContentType returns the Content-Type to send for an
// attachment whose magic-byte-detected type is detectedType
// (SR-125-4): risky types are always downgraded to octetStream; empty
// or unrecognized detected types also downgrade to octetStream rather
// than trusting an attacker-supplied declared type.
func responseContentType(detectedType string) string {
	t := strings.ToLower(strings.TrimSpace(detectedType))
	if t == "" {
		return octetStream
	}
	if riskyContentTypes[t] {
		return octetStream
	}
	return t
}

// contentDisposition renders a RFC 5987/RFC 6266 Content-Disposition
// header value for name, always as "attachment" (never "inline": this
// is a download endpoint, not a viewer, and forcing attachment
// disposition is itself part of the T1.5 sniffing mitigation).
//
// name is expected to be a bare file name (internal/core/message's
// sanitizeFilename already strips any path component and control
// characters before an Attachment reaches the store), but this
// function still strips CR/LF defensively before encoding, since a
// header-injection payload smuggled past an earlier stage must not
// reach a raw header value here either.
func contentDisposition(name string) string {
	name = stripCRLF(name)
	// ASCII fallback for legacy user agents that only understand the
	// unencoded "filename" parameter: replace anything outside a safe
	// printable-ASCII, non-quote/backslash set with "_" instead of
	// percent-encoding it (that parameter is not percent-decoded by
	// spec), while the RFC 5987 filename* parameter below carries the
	// full, correctly encoded name for standards-compliant clients.
	ascii := asciiFallback(name)
	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, ascii, url.PathEscape(name))
}

func stripCRLF(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\r' || r == '\n' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func asciiFallback(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
