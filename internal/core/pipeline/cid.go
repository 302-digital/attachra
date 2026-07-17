package pipeline

// Phase 2 of ADR-016 (ATR-307): verify that a presentation-inline asset
// is really referenced via a `cid:` URL (RFC 2392) from a text/html part
// of the same multipart/related container before the pipeline's
// protective downgrade (protectInlineAssets) spares it from a broad
// `replace` policy. Phase 1 protected any Content-ID part inside
// multipart/related on the structural signal alone, which left a
// documented residual (threat-model T2.8): a small detected-image with a
// Content-ID that no HTML actually embeds was protected for nothing.
//
// The verification is done in the pipeline, not the message parser,
// because it needs the text/html body content, which the parser
// deliberately never buffers (it hands each leaf body to a callback and
// stays allocation-free with respect to part content — the streaming
// invariant). The pipeline already spools every leaf part's decoded
// content into a bounded *spool for later upload/rewrite, so the HTML is
// already captured; scanning it here reuses that spool rather than
// re-reading the message.
//
// Container scoping uses PartPath alone (no new parser field): an
// InlineAsset's immediate parent is, by ADR-016 decision 1, the
// multipart/related container, so the container's path is
// parentPath(asset.PartPath); any text/html part whose PartPath is a
// descendant of that path is inside the same related container
// (including an HTML nested one level deeper inside a
// multipart/alternative, the common Outlook shape).

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/302-digital/attachra/internal/core/message"
)

// maxHTMLCIDScanBytes bounds how many bytes of a SINGLE text/html part
// are scanned for `cid:` references in one call to scanCIDReferences —
// it is a per-part bound, not a message-level one (see
// maxAggregateHTMLScanBytes/maxAggregateCIDTokens for the budget that
// bounds the message as a whole; a message with several text/html
// parts can exhaust that aggregate budget well before any single part
// reaches this per-part bound). A part scanned up to (but not past)
// this bound is reported truncated by scanCIDReferences; the caller
// (cidReferenced) then treats every InlineAsset in that container as
// referenced — the fail-safe direction, matching ADR-016 phase-1
// behavior (never break a message we cannot fully verify), a documented
// residual rather than a regression.
//
// 1 MiB comfortably covers real inline-image HTML bodies (a signature or
// newsletter body referencing small logos is normally a few KiB to low
// hundreds of KiB) while bounding the CPU/latency a single oversized
// part can impose on the mail path.
const maxHTMLCIDScanBytes = 1 << 20 // 1 MiB

// maxAggregateHTMLScanBytes bounds the TOTAL number of text/html bytes
// scanned across every text/html part of one message (ATR-307 security
// review, B1). Without this cap, a sender could attach many separate
// text/html inline parts — each individually within
// maxHTMLCIDScanBytes, message.Limits.MaxParts (1000 by default) and
// MaxTotalSize (1 GiB by default) — and force collectHTMLCIDRefs to
// hold every part's token map in memory simultaneously (e.g. ~1000
// parts x up to 1 MiB of dense unique cid: tokens each), aggregating to
// several GiB of RAM for one message, multiplied across concurrent
// milter sessions: a mail-path memory-exhaustion DoS, violating
// the streaming invariant. Once this budget is spent, every remaining
// text/html part is left entirely unscanned (not even opened) and marked
// truncated, so its container falls back to the fail-safe "protect
// anyway, unverified" path rather than growing memory further.
//
// 4 MiB (four times maxHTMLCIDScanBytes) covers even an unusually
// html-heavy legitimate message (several distinct inline bodies, e.g. a
// multipart/alternative with more than one html representation) while
// keeping worst-case aggregate scan memory for one message-processing
// call small and predictable.
const maxAggregateHTMLScanBytes = 4 << 20 // 4 MiB

// maxAggregateCIDTokens bounds the TOTAL number of distinct `cid:`
// tokens accumulated across every scanned text/html part of one message
// (ATR-307 security review, B1 companion). This closes the case where
// the aggregate BYTE budget alone is insufficient: many small,
// cheap-to-scan text/html parts can each be stuffed with many short,
// distinct cid: tokens, so scanned bytes stay well under
// maxAggregateHTMLScanBytes while the number of map[string]struct{}
// entries retained (and the resulting memory) still grows with the
// number of parts. Once the token budget is spent, the current (and
// every further) text/html part is left unscanned/its tokens discarded
// and marked truncated, matching the byte-budget's fail-safe shape.
//
// 65536 is far beyond any legitimate message (a real inline-image html
// body embeds at most a handful of logos/signature images) while
// keeping the worst-case aggregate token-map memory for one message in
// the low tens of MiB.
const maxAggregateCIDTokens = 65536

// maxCIDTokenLen bounds how many bytes are collected for a single
// candidate `cid:` token, so a body with no delimiter after `cid:`
// cannot make the scanner accumulate an unbounded token. RFC 5322 caps a
// header (hence a msg-id / Content-ID) well under this; 998 is that line
// length limit and a safe, generous ceiling.
const maxCIDTokenLen = 998

// htmlCIDRefs holds the `cid:` tokens referenced by one text/html part,
// keyed for membership tests, along with the part's PartPath (for
// container scoping) and whether its scan was truncated/unreadable (for
// the fail-safe path).
type htmlCIDRefs struct {
	partPath  string
	cids      map[string]struct{}
	truncated bool
}

// hasInlineCandidate reports whether atts contains at least one part
// that could possibly qualify for the ADR-016 protective downgrade:
// att.InlineAsset (the structural Content-ID + multipart/related
// signal) AND att.Size <= inlineMaxSize (the cheapest checks available
// without needing DetectedType or the policy decision — both already
// computed by the time this is called).
//
// This gates the (potentially expensive) collectHTMLCIDRefs call
// (ATR-307 security review, B2): an ordinary message — including a
// perfectly normal html email with no inline Content-ID assets at all —
// never pays for a spool re-read or a cid: scan of its own html body.
// The condition intentionally mirrors protectInlineAssets' own
// InlineAsset+size gate (not its DetectedType/image-prefix check, which
// needs per-attachment magic-byte sniffing already done but is checked
// there): any attachment that would reach protectInlineAssets' call to
// cidReferenced must first pass this same two-part test, so a false
// "no candidate" here is impossible — see protectInlineAssets, which
// checks the identical two conditions before ever consulting htmls.
func hasInlineCandidate(atts []message.Attachment, inlineMaxSize int64) bool {
	for _, att := range atts {
		if att.InlineAsset && att.Size <= inlineMaxSize {
			return true
		}
	}
	return false
}

// collectHTMLCIDRefs scans every text/html body part's spooled content
// for `cid:` references, returning one htmlCIDRefs per such part. atts
// and bodies are the index-aligned slices parseMessage produced. Callers
// should gate this call behind hasInlineCandidate (B2): scanning every
// html part of a message with no inline-asset candidate at all buys
// nothing.
//
// Only parts declared text/html AND classified DispositionInline are
// scanned: those are the rendered message bodies a MUA resolves `cid:`
// URLs from (the structural text/html body, or an inline text/html
// alternative). A text/html part sent as a genuine downloadable
// attachment (DispositionAttachment) is never rendered inline, so its
// content grants no inline-asset protection.
//
// A spool read failure never aborts message processing (the
// mail-must-never-be-lost invariant): it is logged and recorded as a
// truncated entry, so the
// affected container falls back to phase-1 protection (fail-safe)
// instead of turning a transient I/O error into a lost or rejected
// message.
//
// Two message-level budgets (ATR-307 security review, B1) bound the
// aggregate cost across every text/html part of the message, on top of
// the existing per-part maxHTMLCIDScanBytes cap: remainingScanBudget
// (maxAggregateHTMLScanBytes total bytes read) and remainingTokenBudget
// (maxAggregateCIDTokens total distinct tokens retained). Once either is
// exhausted, every further text/html part is left entirely unscanned —
// not even opened — and recorded truncated, so collectHTMLCIDRefs's
// total work and total retained memory for one message are both O(one
// bounded constant), independent of how many text/html parts the
// message contains (the streaming invariant).
func (p *AttachmentProcessor) collectHTMLCIDRefs(atts []message.Attachment, bodies []*spool) []htmlCIDRefs {
	var out []htmlCIDRefs

	remainingScanBudget := int64(maxAggregateHTMLScanBytes)
	remainingTokenBudget := maxAggregateCIDTokens

	for i, att := range atts {
		if att.DeclaredType != "text/html" || att.Disposition != message.DispositionInline {
			continue
		}

		if remainingScanBudget <= 0 || remainingTokenBudget <= 0 {
			// The aggregate budget is already spent: leave this (and
			// every subsequent) text/html part unscanned rather than
			// reading or retaining anything more for it.
			out = append(out, htmlCIDRefs{partPath: att.PartPath, truncated: true})
			continue
		}

		r, err := bodies[i].Reader()
		if err != nil {
			p.logger().Warn("pipeline: cid scan: open html body spool",
				"part", att.PartPath, "error", err.Error())
			out = append(out, htmlCIDRefs{partPath: att.PartPath, truncated: true})
			continue
		}

		partLimit := int64(maxHTMLCIDScanBytes)
		if remainingScanBudget < partLimit {
			// The remaining aggregate budget is smaller than the normal
			// per-part cap: shrink this scan to fit it exactly, so the
			// aggregate byte budget is a hard ceiling regardless of how
			// the per-part reads are distributed.
			partLimit = remainingScanBudget
		}

		cids, scanned, truncated, err := scanCIDReferences(r, partLimit)
		if err != nil {
			p.logger().Warn("pipeline: cid scan: read html body",
				"part", att.PartPath, "error", err.Error())
			out = append(out, htmlCIDRefs{partPath: att.PartPath, truncated: true})
			continue
		}
		remainingScanBudget -= scanned
		// A part scan shrunk to fit the remaining aggregate byte budget
		// (partLimit < maxHTMLCIDScanBytes) can be "truncated" purely
		// because of that shrink, even though the part itself would have
		// fit within the normal per-part cap — this is intentional: the
		// aggregate budget being spent must always resolve to fail-safe
		// for the affected container, exactly like an oversized single
		// part would.

		if len(cids) > remainingTokenBudget {
			// This part alone would exceed the remaining aggregate token
			// budget: discard its tokens (never let the aggregate token
			// count grow past the budget) and record it truncated;
			// exhaust the token budget outright so every later html part
			// also takes the unscanned branch above.
			out = append(out, htmlCIDRefs{partPath: att.PartPath, truncated: true})
			remainingTokenBudget = 0
			continue
		}
		remainingTokenBudget -= len(cids)

		out = append(out, htmlCIDRefs{partPath: att.PartPath, cids: cids, truncated: truncated})
	}
	return out
}

// cidReferenced reports whether contentID is referenced by any text/html
// part within the multipart/related container at containerPath.
//
// It returns failsafe=true (and referenced=true) when it cannot make a
// confident negative determination: either containerPath is empty
// (defensive — an InlineAsset always has a container per ADR-016
// decision 1), or a relevant HTML part's scan was truncated/unreadable.
// In those cases the caller protects the asset anyway (phase-1 behavior),
// and failsafe lets the caller record that the cid: reference could not
// be verified (audit detail "inline_protected_unverified"). A confident
// match returns referenced=true, failsafe=false; a confident miss
// returns referenced=false.
func cidReferenced(htmls []htmlCIDRefs, containerPath, contentID string) (referenced, failsafe bool) {
	if containerPath == "" {
		return true, true
	}

	incomplete := false
	for _, h := range htmls {
		if !isWithinContainer(h.partPath, containerPath) {
			continue
		}
		if h.truncated {
			incomplete = true
		}
		if _, ok := h.cids[contentID]; ok {
			return true, false
		}
	}

	if incomplete {
		return true, true
	}
	return false, false
}

// isWithinContainer reports whether the part at partPath is a descendant
// of the container at containerPath, using message.Parse's dotted
// PartPath convention: "0.1" is a child of "0". A trailing dot guards
// against a numeric prefix false match (e.g. "1" must not match "10.2").
func isWithinContainer(partPath, containerPath string) bool {
	return strings.HasPrefix(partPath, containerPath+".")
}

// parentPath returns the PartPath of partPath's immediate parent
// container, i.e. partPath with its last dotted segment removed, or ""
// if partPath has no parent (a top-level part). For an InlineAsset this
// is, by ADR-016 decision 1, the multipart/related container's path.
func parentPath(partPath string) string {
	if idx := strings.LastIndexByte(partPath, '.'); idx >= 0 {
		return partPath[:idx]
	}
	return ""
}

// scanCIDReferences reads up to limit bytes from r and returns the set of
// `cid:` tokens it references, along with scanned, the exact number of
// bytes actually counted toward limit (min(len(r's content), limit)) —
// callers use scanned to debit a message-level aggregate budget
// (collectHTMLCIDRefs's remainingScanBudget). The third return is true
// when r held more than limit bytes (the scan was truncated); callers
// treat a truncated scan as a fail-safe "cannot verify" rather than an
// authoritative result. Reading is bounded: at most limit(+1) bytes are
// ever pulled from r, so a single call costs O(limit) work and memory
// (the streaming invariant; collectHTMLCIDRefs additionally bounds the
// sum of limit across every call within one message).
func scanCIDReferences(r io.Reader, limit int64) (refs map[string]struct{}, scanned int64, truncated bool, err error) {
	// Read one byte past the limit to distinguish "exactly at the limit"
	// from "there was more" (truncation).
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, 0, false, fmt.Errorf("pipeline: scan cid references: %w", err)
	}
	truncated = int64(len(data)) > limit
	if truncated {
		data = data[:limit]
	}
	return extractCIDTokens(data), int64(len(data)), truncated, nil
}

// extractCIDTokens scans data for `cid:` URL references (case-insensitive
// scheme, RFC 2392) and returns the set of normalized Content-IDs they
// point at, ready for equality comparison against
// message.Attachment.ContentID (which message.normalizeContentID has
// already stripped of angle brackets).
//
// This is a deliberately lightweight token scan, not an HTML parse: the
// only goal is to learn which Content-IDs the body embeds, and a full
// DOM parse would buy nothing but cost and dependencies. Precision:
//   - False positives (a `cid:` string that is not a live reference,
//     e.g. inside a comment) only ever cause an asset to be protected
//     (not replaced) — the fail-safe direction, and never worse than
//     ADR-016 phase 1. A leading scheme-character guard still rejects the
//     obvious non-references (e.g. the "cid:" inside "acid:").
//   - False negatives (a real reference the scan misses) would replace a
//     genuine inline asset. To avoid breaking mail, the token charset is
//     permissive (it stops only at unambiguous URL delimiters) and
//     percent-encoding is decoded.
func extractCIDTokens(data []byte) map[string]struct{} {
	refs := make(map[string]struct{})
	n := len(data)
	for i := 0; i+4 <= n; i++ {
		if lowerASCII(data[i]) != 'c' || lowerASCII(data[i+1]) != 'i' ||
			lowerASCII(data[i+2]) != 'd' || data[i+3] != ':' {
			continue
		}
		// Reject a "cid:" that is the tail of a longer scheme-like token
		// (e.g. "acid:"): a real URI scheme starts at a boundary.
		if i > 0 && isSchemeChar(data[i-1]) {
			continue
		}

		start := i + 4
		j := start
		for j < n && j-start < maxCIDTokenLen && isCIDTokenByte(data[j]) {
			j++
		}
		if id := normalizeScannedCID(data[start:j]); id != "" {
			refs[id] = struct{}{}
		}
		i = j - 1 // resume scanning after the consumed token
	}
	return refs
}

// normalizeScannedCID trims a scanned `cid:` token, percent-decodes it
// (RFC 2392 cid: URLs are URL-encoded; the referenced Content-ID is the
// decoded form) and defensively strips any angle brackets, so the result
// is directly comparable to message.normalizeContentID's output.
func normalizeScannedCID(tok []byte) string {
	s := strings.TrimSpace(string(tok))
	if s == "" {
		return ""
	}
	if strings.IndexByte(s, '%') >= 0 {
		// PathUnescape (unlike QueryUnescape) leaves '+' untouched, which
		// is correct for an opaque cid: URL. On a malformed escape, keep
		// the raw token rather than dropping the reference.
		if dec, err := url.PathUnescape(s); err == nil {
			s = dec
		}
	}
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return strings.TrimSpace(s)
}

// lowerASCII lower-cases an ASCII letter, leaving every other byte
// unchanged (used for the case-insensitive scheme match).
func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// isSchemeChar reports whether b may appear in a URI scheme name
// (RFC 3986 §3.1: ALPHA / DIGIT / "+" / "-" / "."). Used to require a
// scheme boundary before a matched "cid:".
func isSchemeChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '+' || b == '-' || b == '.':
		return true
	default:
		return false
	}
}

// isCIDTokenByte reports whether b belongs to a `cid:` URL's opaque body
// as it appears in HTML markup. The token ends at any unambiguous
// delimiter — the quote characters an attribute value is wrapped in,
// whitespace, angle brackets, and the parentheses of a CSS url(...) — so
// the scan stays permissive about the msg-id charset (letters, digits
// and addr-spec specials like '@', '.', '_', '-') to avoid missing a
// real reference, while still terminating cleanly.
func isCIDTokenByte(b byte) bool {
	switch b {
	case '"', '\'', '<', '>', '(', ')', '`':
		return false
	case ' ', '\t', '\r', '\n', '\f', '\v':
		return false
	}
	// Anything else in the printable ASCII range is treated as part of
	// the token; control bytes and the DEL/high range end it.
	return b > 0x20 && b < 0x7f
}
