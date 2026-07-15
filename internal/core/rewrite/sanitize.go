package rewrite

import (
	"fmt"
	"net/url"
	"strings"
)

// sanitizeHeaderValue strips CR and LF from s (SR-118-1). Any value
// derived from the original message (a sender display name, a
// recipient address, an attachment file name, ...) must pass through
// this before being written into a new header value or the
// X-Attachra-Processed header, since the message itself is
// attacker-controlled input and an embedded CR/LF could otherwise
// inject additional header lines or body content (header/response
// splitting).
//
// Unlike internal/core/message's sanitizeFilename (which targets safe
// display/storage of a name), this function is intentionally narrow:
// it only removes the two bytes that make header injection possible,
// leaving the rest of the value (including other control characters)
// untouched, since callers may want to display the value as-is in the
// replacement block body rather than in a header.
func sanitizeHeaderValue(s string) string {
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

// encodeContentDispositionFilename renders name as an RFC 5987/RFC
// 6266 extended parameter value (SR-118-2): the charset token
// "UTF-8", an empty language tag, and the percent-encoded name,
// separated by single quotes — the right-hand side of a header
// parameter such as filename*=<result>, suitable for direct
// inclusion in a Content-Disposition (or Content-Type) header value.
// name is expected to already be a bare file name with no path
// component (internal/core/message's sanitizeFilename guarantees
// this for parsed attachments); this function does not itself strip
// path separators, since callers that need that guarantee already
// run names through message package sanitization before this stage.
//
// Not called from this package's own Rewrite path today: see the
// package doc comment ("SR-118-2 (RFC 5987) scope") for why — rewrite
// never emits a filename into a header, only into the replacement
// block's body text. It is kept here, tested, for the download
// endpoint (T-6.2.1) to reuse once it serves file bytes with a
// Content-Disposition header.
func encodeContentDispositionFilename(name string) string {
	name = sanitizeHeaderValue(name)
	return fmt.Sprintf("UTF-8''%s", url.PathEscape(name))
}
