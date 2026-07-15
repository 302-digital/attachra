package message

import (
	"mime"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxFilenameLength bounds the sanitized attachment file name (in
// runes) to keep downstream storage/UI paths well-behaved (SR-117-5).
const maxFilenameLength = 255

// wordDecoder decodes RFC 2047 encoded-words (e.g. "=?UTF-8?B?...?=")
// found in header values that mime.ParseMediaType does not itself
// decode (ParseMediaType handles RFC 2231 percent-encoding and
// continuations, but not RFC 2047 encoded-word parameter values).
var wordDecoder = &mime.WordDecoder{}

// extractFilename derives the best available, decoded and sanitized
// file name for a part from its Content-Disposition and Content-Type
// header values. Both are full header values (e.g.
// `attachment; filename="x.pdf"`); either may be empty.
//
// It never panics on malformed input (SR-117-5): unparsable or
// undecodable parameters fall back to progressively simpler
// extraction, and a name that still cannot be recovered results in an
// empty string rather than an error, since a missing filename is not
// itself a parse failure of the message.
func extractFilename(contentDisposition, contentType string) string {
	if name := filenameFromHeader(contentDisposition); name != "" {
		return sanitizeFilename(name)
	}
	if name := filenameFromHeader(contentType); name != "" {
		return sanitizeFilename(name)
	}
	return ""
}

// filenameFromHeader extracts the "filename" parameter (falling back
// to "name", used by some legacy clients on Content-Type) from a
// raw header value, decoding RFC 2047 encoded-words if present.
// mime.ParseMediaType already resolves RFC 2231 (filename*, and
// filename*0/filename*1 continuations) into a single plain value.
func filenameFromHeader(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}

	_, params, err := mime.ParseMediaType(header)
	if err != nil {
		// ParseMediaType returns the best-effort params it could
		// recover alongside ErrInvalidMediaParameter; use them if
		// present instead of giving up entirely.
		if params == nil {
			return ""
		}
	}

	raw := params["filename"]
	if raw == "" {
		raw = params["name"]
	}
	if raw == "" {
		return ""
	}

	return decodeWords(raw)
}

// decodeWords decodes RFC 2047 encoded-words in s. On any decode
// error (unknown charset, truncated encoding, etc.) it returns the
// original string unmodified rather than panicking or propagating the
// error, since a best-effort raw name is preferable to no name.
func decodeWords(s string) string {
	decoded, err := wordDecoder.DecodeHeader(s)
	if err != nil || !utf8.ValidString(decoded) {
		if utf8.ValidString(s) {
			return s
		}
		return sanitizeInvalidUTF8(s)
	}
	return decoded
}

// sanitizeInvalidUTF8 replaces invalid UTF-8 byte sequences with the
// Unicode replacement character so downstream consumers never choke
// on a byte string that claims to be text but is not valid UTF-8.
func sanitizeInvalidUTF8(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		if r == utf8.RuneError {
			_, size := utf8.DecodeRuneInString(s[i:])
			if size == 1 {
				b.WriteRune(utf8.RuneError)
				continue
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sanitizeFilename hardens an attacker-controlled attachment name for
// safe use in logs, storage keys and UI (SR-117-5):
//   - strips any path components, keeping only the base name, so a
//     name like "../../etc/passwd" or "C:\\evil.exe" cannot escape a
//     destination directory purely via the displayed name;
//   - strips ASCII and Unicode control/line-separator characters that
//     could be used for terminal or log injection;
//   - trims surrounding whitespace and rejects "." / ".." as names;
//   - truncates to maxFilenameLength runes.
func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	// Normalize both Windows and Unix path separators before taking
	// the base name: filepath.Base on a non-Windows GOOS would not
	// otherwise strip a "\"-separated path.
	normalized := strings.ReplaceAll(name, "\\", "/")
	base := filepath.Base(normalized)
	if base == "." || base == "/" || base == ".." {
		return ""
	}

	base = stripControlRunes(base)
	base = strings.TrimSpace(base)
	if base == "" || base == "." || base == ".." {
		return ""
	}

	return truncateRunes(base, maxFilenameLength)
}

// lineOrParagraphSeparator reports whether r is the Unicode line
// separator (U+2028) or paragraph separator (U+2029). unicode.IsControl
// does not classify these as control characters, but they can still
// be abused to inject fake lines into logs or terminal output.
func lineOrParagraphSeparator(r rune) bool {
	return r == '\u2028' || r == '\u2029'
}

// stripControlRunes removes C0/C1 control characters and Unicode line
// or paragraph separators, replacing runs of them with nothing.
func stripControlRunes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsControl(r) || lineOrParagraphSeparator(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// truncateRunes returns s truncated to at most n runes, respecting
// rune boundaries so multi-byte UTF-8 characters are not split.
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}
