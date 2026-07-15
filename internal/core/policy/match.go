package policy

import (
	"path"
	"strings"

	"github.com/302-digital/attachra/internal/core/message"
)

// glob is a compiled, case-insensitive glob pattern supporting `*`
// (any run of characters, including none) and `?` (exactly one
// character), matched against a whole string (not a path — `/` has no
// special meaning), per §2.3.1/§2.3.2 of the policy format spec.
//
// path.Match is reused as the matching engine since its glob dialect
// (`*`, `?`, `[...]`) is a superset of what the spec requires; `/` is
// not treated specially, since attachment names or email addresses
// are matched as flat strings, not paths.
type glob struct {
	pattern string
}

// compileGlob validates pattern syntax eagerly (at policy-load time)
// so a malformed glob is reported as a validation error (§3.5) rather
// than surfacing as a matching error on every message.
func compileGlob(pattern string) (glob, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return glob{}, err
	}
	return glob{pattern: strings.ToLower(pattern)}, nil
}

// match reports whether s matches the glob, case-insensitively.
func (g glob) match(s string) bool {
	ok, err := path.Match(g.pattern, strings.ToLower(s))
	if err != nil {
		// Unreachable in practice: compileGlob already validated the
		// pattern at policy-load time, so path.Match cannot fail here
		// with the same pattern.
		return false
	}
	return ok
}

// EnvelopeMeta is the transport-agnostic per-message data an
// AddressMatch needs: the envelope sender and a single envelope
// recipient under evaluation. See §3.6: matching uses the envelope
// (MAIL FROM / RCPT TO), not the message header From/To.
type EnvelopeMeta struct {
	// Sender is the envelope-from address (SMTP MAIL FROM).
	Sender string
	// Recipients lists the envelope-to addresses (SMTP RCPT TO). Each
	// is evaluated independently against `when.recipient` and
	// aggregated per §3.4 (worst-case across recipients).
	Recipients []string
}

// splitAddress splits an email address into its local-part and
// domain, lower-cased for case-insensitive comparison (§3.6). An
// address without an '@' returns an empty domain.
func splitAddress(addr string) (full, domain string) {
	full = strings.ToLower(strings.TrimSpace(addr))
	if i := strings.LastIndexByte(full, '@'); i >= 0 {
		domain = full[i+1:]
	}
	return full, domain
}

// matchAddress reports whether addr satisfies m. Fields within an
// AddressMatch are OR'd (§2.3.1): addr matches if it satisfies
// Address, OR Domain, OR Pattern (a value within a single field list
// is itself OR'd against the others in that list).
func matchAddress(m *AddressMatch, addr string) bool {
	if m == nil {
		return true
	}

	full, domain := splitAddress(addr)

	for _, want := range m.Address {
		if strings.ToLower(want) == full {
			return true
		}
	}
	for _, want := range m.Domain {
		if strings.ToLower(want) == domain {
			return true
		}
	}
	for _, pat := range m.Pattern {
		g, err := compileGlob(pat)
		if err != nil {
			continue // already reported at validation time
		}
		if g.match(full) {
			return true
		}
	}

	// An AddressMatch with every field empty (e.g. `sender: {}`)
	// matches nothing: there is no criterion to satisfy. This mirrors
	// "no OR terms are true".
	return false
}

// matchSize reports whether size (in bytes) falls within r. A nil
// bound on either side is unbounded on that side. Both bounds are
// inclusive (§2.3.2).
func matchSize(r *SizeRange, size int64) bool {
	if r == nil {
		return true
	}
	if r.Min != nil && size < r.Min.Bytes() {
		return false
	}
	if r.Max != nil && size > r.Max.Bytes() {
		return false
	}
	return true
}

// matchGlobList reports whether s matches at least one pattern in
// patterns (OR within the field, §2.3.2). An empty patterns list
// imposes no constraint (matches everything), consistent with the
// field being absent from the rule.
func matchGlobList(patterns []string, s string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pat := range patterns {
		g, err := compileGlob(pat)
		if err != nil {
			continue // already reported at validation time
		}
		if g.match(s) {
			return true
		}
	}
	return false
}

// extensionOf returns the filename's extension without the leading
// dot, lower-cased, matching Attachment filenames such as
// "invoice.PDF" -> "pdf". A filename with no dot (or ending in a dot)
// has an empty extension. Unicode file names are handled correctly
// since this only looks for the last '.' rune, independent of
// encoding.
func extensionOf(filename string) string {
	i := strings.LastIndexByte(filename, '.')
	if i < 0 || i == len(filename)-1 {
		return ""
	}
	return strings.ToLower(filename[i+1:])
}

// effectiveDisposition returns the effective disposition keyword
// (ADR-016) matched by AttachmentMatch.Disposition: "inline" when att
// is a presentation-inline asset (att.InlineAsset), "attachment"
// otherwise. This is deliberately independent of the raw
// message.Attachment.Disposition (Content-Disposition header) value —
// see AttachmentMatch.Disposition's doc comment for why matching the
// raw header would be a policy bypass.
func effectiveDisposition(att message.Attachment) string {
	if att.InlineAsset {
		return "inline"
	}
	return "attachment"
}

// matchDisposition reports whether att's effective disposition
// (ADR-016) satisfies one of the values in patterns (OR within the
// field, §2.3.2). An empty patterns list imposes no constraint.
// Comparison is an exact, case-insensitive match against the two
// recognized keywords ("inline", "attachment"), not a glob: the field
// is a closed enum, validated at policy-load time (validateAttachmentMatch).
func matchDisposition(patterns []string, att message.Attachment) bool {
	if len(patterns) == 0 {
		return true
	}
	want := effectiveDisposition(att)
	for _, p := range patterns {
		if strings.EqualFold(p, want) {
			return true
		}
	}
	return false
}

// matchAttachment reports whether att satisfies m. Fields within an
// AttachmentMatch are AND'd (§2.3.2): every present field must match.
func matchAttachment(m *AttachmentMatch, att message.Attachment) bool {
	if m == nil {
		return true
	}

	if !matchSize(m.Size, att.Size) {
		return false
	}
	if !matchGlobList(m.MimeType, att.DetectedType) {
		return false
	}
	if !matchGlobList(m.ClaimedMimeType, att.DeclaredType) {
		return false
	}
	if len(m.Extension) > 0 {
		ext := extensionOf(att.Filename)
		found := false
		for _, want := range m.Extension {
			if strings.ToLower(want) == ext {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if !matchGlobList(m.Filename, att.Filename) {
		return false
	}
	if !matchDisposition(m.Disposition, att) {
		return false
	}

	return true
}

// matchWhen reports whether w matches, given the current attachment,
// sender and a single recipient under evaluation. Sections present in
// w are AND'd (§2.3); a nil w (rule has no `when`) always matches
// (catch-all, §3.3).
func matchWhen(w *When, sender, recipient string, att message.Attachment) bool {
	if w == nil {
		return true
	}
	if w.Sender != nil && !matchAddress(w.Sender, sender) {
		return false
	}
	if w.Recipient != nil && !matchAddress(w.Recipient, recipient) {
		return false
	}
	if w.Attachment != nil && !matchAttachment(w.Attachment, att) {
		return false
	}
	return true
}
