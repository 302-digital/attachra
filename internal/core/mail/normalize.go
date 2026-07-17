// Package mail provides the single canonical form Attachra uses for
// every envelope address (SMTP MAIL FROM / RCPT TO) it stores or
// matches against. It has no adapter-specific dependencies (ADR-002):
// adapters call it when they first observe an address, and the Core
// store/query layer applies it again defensively at read time so the
// audit trail, message/link listings, and revoke-by-sender all agree
// on one form regardless of which layer produced or consumed the
// value (ATR-293).
package mail

import "strings"

// NormalizeAddress returns the canonical form Attachra stores and
// matches envelope addresses by: surrounding whitespace trimmed, one
// enclosing pair of SMTP reverse/forward-path angle brackets stripped
// (RFC 5321 §4.1.2 "MAIL FROM:<user@example.com>" — Postfix's
// {mail_addr}/{rcpt_addr} milter macros already deliver the address
// bracket-free, but the raw MAIL/RCPT command argument this adapter
// falls back to when a macro is unavailable still carries them; see
// internal/adapters/milter/backend.go), and the entire remaining
// string lower-cased.
//
// Local-part case (ATR-293, closing the ATR-258 review's N1 finding):
// RFC 5321 §2.4 technically leaves the local part case-sensitive, but
// in practice no MTA or mailbox provider Attachra targets honors that
// — Postfix, Exim, Gmail, and Microsoft 365 all deliver local-part
// case-insensitively. NormalizeAddress is used only for Attachra's own
// bookkeeping (audit records, message/link listings, revoke-by-sender
// lookups), never as a literal address handed back to an MTA for
// delivery, so lower-casing the whole address — not just the domain —
// is the safer default for a security-relevant lookup: an operator
// running `attachra link revoke --sender john@corp.com` must find a
// message recorded as `John@Corp.com`, since a missed match here
// leaves an attachment silently downloadable after the operator
// believes access was revoked. The reverse risk — folding together two
// mailboxes that a real MTA treats as distinct purely by local-part
// case — has no known real-world instance among the MTAs above.
//
// Plus-addressing (RFC 5233, e.g. "alice+newsletter@example.com") is
// preserved verbatim aside from case: providers that honor it (Gmail
// and many self-hosted setups) treat it as a distinct mailbox, and
// NormalizeAddress never strips or otherwise alters the "+..."
// segment.
//
// Internationalized (IDN/EAI, RFC 6531) domains are lower-cased as
// Unicode text (strings.ToLower is Unicode-aware) but are NOT
// converted to or from Punycode/ASCII-Compatible Encoding: an address
// presented once as "user@bücher.example" and once by its Punycode
// form "user@xn--bcher-kva.example" will NOT normalize to the same
// canonical string. This is a deliberate scope limit — Attachra's mail
// path does not otherwise handle EAI — not an oversight; a future EAI
// story should extend this function rather than duplicate its
// decision here.
//
// An address that is empty, or becomes empty after
// trimming/bracket-stripping (e.g. the null bounce sender
// "MAIL FROM:<>"), normalizes to "".
func NormalizeAddress(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 && s[0] == '<' && s[len(s)-1] == '>' {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return strings.ToLower(s)
}
