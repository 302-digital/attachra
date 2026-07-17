package pipeline

// Internal unit tests for the ADR-016 phase-2 cid: reference scanner
// (ATR-307). End-to-end behavior through AttachmentProcessor.Process is
// covered by the package-external tests in inline_test.go; these pin the
// lower-level building blocks (token extraction, the streaming scan
// bound, container scoping and the fail-safe resolver) that are hard to
// exercise precisely — especially the scan-limit truncation — through a
// full MIME fixture.

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/policy"
)

func TestExtractCIDTokens(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			name: "double quoted",
			html: `<img src="cid:logo123">`,
			want: []string{"logo123"},
		},
		{
			name: "single quoted",
			html: `<img src='cid:logo123'>`,
			want: []string{"logo123"},
		},
		{
			name: "unquoted",
			html: `<img src=cid:logo123>`,
			want: []string{"logo123"},
		},
		{
			name: "css url",
			html: `<div style="background:url(cid:bg-9)"></div>`,
			want: []string{"bg-9"},
		},
		{
			name: "uppercase scheme",
			html: `<img src="CID:Logo123">`,
			want: []string{"Logo123"},
		},
		{
			name: "content-id with at and dots",
			html: `<img src="cid:logo.123@mail.example.com">`,
			want: []string{"logo.123@mail.example.com"},
		},
		{
			name: "multiple references",
			html: `<img src="cid:a"><img src="cid:b"><img src='cid:a'>`,
			want: []string{"a", "b"},
		},
		{
			name: "percent encoded",
			html: `<img src="cid:logo%40example.com">`,
			want: []string{"logo@example.com"},
		},
		{
			name: "boundary guard rejects acid",
			html: `<p>acid:not-a-reference</p>`,
			want: nil,
		},
		{
			name: "no reference",
			html: `<html><body>Hello, no images here.</body></html>`,
			want: nil,
		},
		{
			name: "case sensitive local part preserved",
			html: `<img src="cid:LOGO">`,
			want: []string{"LOGO"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCIDTokens([]byte(tt.html))
			if len(got) != len(tt.want) {
				t.Fatalf("extractCIDTokens(%q) = %v, want %v", tt.html, keys(got), tt.want)
			}
			for _, w := range tt.want {
				if _, ok := got[w]; !ok {
					t.Errorf("extractCIDTokens(%q) missing %q; got %v", tt.html, w, keys(got))
				}
			}
		})
	}
}

func TestScanCIDReferences_WithinLimit(t *testing.T) {
	html := `<img src="cid:logo123">`
	refs, scanned, truncated, err := scanCIDReferences(strings.NewReader(html), 1<<20)
	if err != nil {
		t.Fatalf("scanCIDReferences() error = %v, want nil", err)
	}
	if truncated {
		t.Error("truncated = true, want false (content fits within the limit)")
	}
	if scanned != int64(len(html)) {
		t.Errorf("scanned = %d, want %d (the whole content)", scanned, len(html))
	}
	if _, ok := refs["logo123"]; !ok {
		t.Errorf("refs = %v, want to contain logo123", keys(refs))
	}
}

func TestScanCIDReferences_TruncatedIsFailSafe(t *testing.T) {
	// The cid: reference sits past a deliberately tiny scan limit, so the
	// scanner must report truncated=true and NOT surface the reference:
	// the caller then treats the container as "cannot verify" and
	// protects it (fail-safe), never mistaking the un-scanned reference
	// for a confirmed miss.
	var b strings.Builder
	b.WriteString("<html><body>")
	b.WriteString(strings.Repeat("x", 200))
	b.WriteString(`<img src="cid:logo123">`)
	b.WriteString("</body></html>")

	refs, scanned, truncated, err := scanCIDReferences(strings.NewReader(b.String()), 64)
	if err != nil {
		t.Fatalf("scanCIDReferences() error = %v, want nil", err)
	}
	if !truncated {
		t.Fatal("truncated = false, want true (content exceeds the scan limit)")
	}
	if scanned != 64 {
		t.Errorf("scanned = %d, want 64 (exactly the limit, on truncation)", scanned)
	}
	if _, ok := refs["logo123"]; ok {
		t.Error("refs contains logo123, want it unseen (it lies beyond the scan limit)")
	}
}

func TestScanCIDReferences_ExactlyAtLimitNotTruncated(t *testing.T) {
	html := `<img src="cid:a">` // 17 bytes
	refs, scanned, truncated, err := scanCIDReferences(strings.NewReader(html), int64(len(html)))
	if err != nil {
		t.Fatalf("scanCIDReferences() error = %v, want nil", err)
	}
	if truncated {
		t.Error("truncated = true, want false (content length equals the limit exactly)")
	}
	if scanned != int64(len(html)) {
		t.Errorf("scanned = %d, want %d", scanned, len(html))
	}
	if _, ok := refs["a"]; !ok {
		t.Errorf("refs = %v, want to contain a", keys(refs))
	}
}

func TestCIDReferenced(t *testing.T) {
	// A related container at "0.1" with an HTML body at "0.1.1" (nested
	// one level deeper, e.g. inside a multipart/alternative at "0.1.x")
	// referencing cid:logo, and a second, unrelated HTML in a different
	// container at "0.2.1".
	htmls := []htmlCIDRefs{
		{partPath: "0.1.1", cids: map[string]struct{}{"logo": {}}},
		{partPath: "0.2.1", cids: map[string]struct{}{"other": {}}},
	}

	tests := []struct {
		name          string
		containerPath string
		contentID     string
		wantRef       bool
		wantFailsafe  bool
	}{
		{"referenced in same container", "0.1", "logo", true, false},
		{"not referenced anywhere", "0.1", "missing", false, false},
		{"referenced only by other container is a miss", "0.1", "other", false, false},
		{"empty container path is defensive fail-safe", "", "logo", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, fs := cidReferenced(htmls, tt.containerPath, tt.contentID)
			if ref != tt.wantRef || fs != tt.wantFailsafe {
				t.Errorf("cidReferenced(_, %q, %q) = (%v, %v), want (%v, %v)",
					tt.containerPath, tt.contentID, ref, fs, tt.wantRef, tt.wantFailsafe)
			}
		})
	}
}

func TestCIDReferenced_TruncatedContainerIsFailSafe(t *testing.T) {
	// A truncated HTML in the same container: even though its (partial)
	// cid set does not contain the id, the container is "incomplete", so
	// the resolver must return a fail-safe positive rather than a miss.
	htmls := []htmlCIDRefs{
		{partPath: "0.1.1", cids: map[string]struct{}{}, truncated: true},
	}
	ref, fs := cidReferenced(htmls, "0.1", "logo")
	if !ref || !fs {
		t.Errorf("cidReferenced with truncated container = (%v, %v), want (true, true)", ref, fs)
	}

	// A confirmed match still wins over the fail-safe path (returns a
	// verified positive, not the unverified one) when the id is present
	// despite truncation.
	htmls = []htmlCIDRefs{
		{partPath: "0.1.1", cids: map[string]struct{}{"logo": {}}, truncated: true},
	}
	ref, fs = cidReferenced(htmls, "0.1", "logo")
	if !ref || fs {
		t.Errorf("cidReferenced with truncated-but-matching container = (%v, %v), want (true, false)", ref, fs)
	}
}

func TestParentPathAndContainer(t *testing.T) {
	if got := parentPath("0.1.2"); got != "0.1" {
		t.Errorf("parentPath(0.1.2) = %q, want 0.1", got)
	}
	if got := parentPath("0.2"); got != "0" {
		t.Errorf("parentPath(0.2) = %q, want 0", got)
	}
	if got := parentPath("0"); got != "" {
		t.Errorf("parentPath(0) = %q, want empty", got)
	}

	if !isWithinContainer("0.1.1", "0.1") {
		t.Error("isWithinContainer(0.1.1, 0.1) = false, want true")
	}
	if !isWithinContainer("0.2", "0") {
		t.Error("isWithinContainer(0.2, 0) = false, want true")
	}
	// Numeric-prefix guard: "10.1" is not inside container "1".
	if isWithinContainer("10.1", "1") {
		t.Error("isWithinContainer(10.1, 1) = true, want false (numeric prefix must not match)")
	}
	// A container is not within itself.
	if isWithinContainer("0.1", "0.1") {
		t.Error("isWithinContainer(0.1, 0.1) = true, want false")
	}
}

// TestMessageActionRankIsExhaustive is the ATR-307 review-note latch: it
// pins the closed set of policy.Action values messageActionRank (and the
// rewriteInput/aggregateMessageAction machinery built on it) enumerate.
// A fourth policy.Action would aggregate as rank 0 (weaker than pass) —
// a correctness hole — unless it is added to messageActionRank; this test
// forces that update to be deliberate by failing on any count mismatch.
func TestMessageActionRankIsExhaustive(t *testing.T) {
	// The known, closed set of policy actions (docs/architecture/
	// policy-format-v1.md §2.4). Update this list AND messageActionRank
	// together if policy.Action ever gains a value.
	known := []policy.Action{policy.ActionPass, policy.ActionReplace, policy.ActionBlock}

	if len(messageActionRank) != len(known) {
		t.Fatalf("messageActionRank has %d entries, want %d — a policy.Action was likely added without ranking it here",
			len(messageActionRank), len(known))
	}
	for _, a := range known {
		if messageActionRank[a] == 0 {
			t.Errorf("messageActionRank[%q] = 0, want a positive rank", a)
		}
	}
	// The ordering contract aggregateMessageAction relies on.
	ordered := messageActionRank[policy.ActionPass] < messageActionRank[policy.ActionReplace] &&
		messageActionRank[policy.ActionReplace] < messageActionRank[policy.ActionBlock]
	if !ordered {
		t.Errorf("messageActionRank ordering broken: pass=%d replace=%d block=%d",
			messageActionRank[policy.ActionPass], messageActionRank[policy.ActionReplace], messageActionRank[policy.ActionBlock])
	}
}

// keys returns the keys of a set, for readable test failure messages.
func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// htmlWithToken returns exactly size bytes: a `cid:` reference to token
// followed by 'x' padding, for constructing text/html fixtures of a
// precise, predictable length (needed to pin the aggregate scan-byte
// budget exactly).
func htmlWithToken(t *testing.T, size int, token string) string {
	t.Helper()
	prefix := fmt.Sprintf(`<img src="cid:%s">`, token)
	if len(prefix) > size {
		t.Fatalf("htmlWithToken: size %d too small for prefix %q", size, prefix)
	}
	return prefix + strings.Repeat("x", size-len(prefix))
}

// nilSpoolPanics is a *spool left nil so that a call to its Reader
// method (a pointer-receiver method dereferencing s.mem) panics. Tests
// use this as a hard proof that collectHTMLCIDRefs never even attempts
// to open a part's spool once the aggregate scan budget is exhausted —
// a positive assertion ("this was never touched") that a plain
// after-the-fact result check cannot provide.
var nilSpoolPanics *spool

// TestCollectHTMLCIDRefs_AggregateByteBudgetStopsScan is the internal
// (ATR-307 security review, B1 blocker) unit test for the aggregate
// scan-BYTE budget: four text/html parts of exactly maxHTMLCIDScanBytes
// (1 MiB) each consume the entire maxAggregateHTMLScanBytes (4 MiB)
// budget; a fifth text/html part must then be left completely unscanned
// — its backing *spool is left nil, so any attempt to read it panics
// the test, proving collectHTMLCIDRefs's early-exit check actually
// fires before any I/O on that part.
func TestCollectHTMLCIDRefs_AggregateByteBudgetStopsScan(t *testing.T) {
	p := &AttachmentProcessor{}

	const partSize = maxHTMLCIDScanBytes // matches the per-part cap exactly
	const parts = maxAggregateHTMLScanBytes / partSize

	atts := make([]message.Attachment, parts+1)
	bodies := make([]*spool, parts+1)

	for i := 0; i < parts; i++ {
		partPath := "0." + strconv.Itoa(i+1)
		token := "token" + strconv.Itoa(i)
		s, err := spoolReader(strings.NewReader(htmlWithToken(t, partSize, token)), "")
		if err != nil {
			t.Fatalf("spoolReader() error = %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })

		atts[i] = message.Attachment{PartPath: partPath, DeclaredType: "text/html", Disposition: message.DispositionInline}
		bodies[i] = s
	}

	// The budget-exceeding part: nil spool proves it is never read.
	atts[parts] = message.Attachment{PartPath: "0." + strconv.Itoa(parts+1), DeclaredType: "text/html", Disposition: message.DispositionInline}
	bodies[parts] = nilSpoolPanics

	got := p.collectHTMLCIDRefs(atts, bodies)
	if len(got) != parts+1 {
		t.Fatalf("collectHTMLCIDRefs returned %d entries, want %d", len(got), parts+1)
	}

	for i := 0; i < parts; i++ {
		if got[i].truncated {
			t.Errorf("part %d truncated = true, want false (exactly at the per-part/aggregate boundary, fully scanned)", i)
		}
		token := "token" + strconv.Itoa(i)
		if _, ok := got[i].cids[token]; !ok {
			t.Errorf("part %d cids = %v, want to contain %q", i, keys(got[i].cids), token)
		}
	}

	last := got[parts]
	if !last.truncated {
		t.Error("the budget-exceeding part's truncated = false, want true (aggregate scan budget exhausted before it)")
	}
	if len(last.cids) != 0 {
		t.Errorf("the budget-exceeding part's cids = %v, want none (never scanned)", keys(last.cids))
	}
}

// TestCollectHTMLCIDRefs_AggregateTokenBudgetStopsScan is the internal
// (ATR-307 security review, B1 companion) unit test for the aggregate
// scan-TOKEN budget: a single, well-under-the-byte-cap text/html part
// carries more distinct cid: tokens than maxAggregateCIDTokens, so its
// tokens are discarded and it is marked truncated; a second, unrelated
// text/html part must then be left completely unscanned (nil spool
// proves it) even though the aggregate BYTE budget still has room —
// pinning that the token budget is an independent, additional
// constraint, not merely a side effect of the byte budget.
func TestCollectHTMLCIDRefs_AggregateTokenBudgetStopsScan(t *testing.T) {
	p := &AttachmentProcessor{}

	const tokenCount = maxAggregateCIDTokens + 4000
	var b strings.Builder
	for i := 0; i < tokenCount; i++ {
		b.WriteString("cid:")
		b.WriteString(strconv.Itoa(i))
		b.WriteByte(' ')
	}
	if int64(b.Len()) >= maxHTMLCIDScanBytes {
		t.Fatalf("test content is %d bytes, want well under the %d-byte per-part scan cap — tighten tokenCount", b.Len(), maxHTMLCIDScanBytes)
	}

	s0, err := spoolReader(strings.NewReader(b.String()), "")
	if err != nil {
		t.Fatalf("spoolReader() error = %v", err)
	}
	t.Cleanup(func() { _ = s0.Close() })

	atts := []message.Attachment{
		{PartPath: "0.1", DeclaredType: "text/html", Disposition: message.DispositionInline},
		{PartPath: "0.2", DeclaredType: "text/html", Disposition: message.DispositionInline},
	}
	bodies := []*spool{s0, nilSpoolPanics}

	got := p.collectHTMLCIDRefs(atts, bodies)
	if len(got) != 2 {
		t.Fatalf("collectHTMLCIDRefs returned %d entries, want 2", len(got))
	}

	if !got[0].truncated {
		t.Error("part 1 truncated = false, want true (its own token count alone exceeds the aggregate token budget)")
	}
	if len(got[0].cids) != 0 {
		t.Errorf("part 1 cids = %v, want none (discarded once the aggregate token budget was exceeded)", keys(got[0].cids))
	}
	if !got[1].truncated {
		t.Error("part 2 truncated = false, want true (aggregate token budget already exhausted by part 1)")
	}
}

// TestHasInlineCandidate pins the B2 gate predicate directly: it must
// be true iff atts contains at least one part that is both InlineAsset
// and within the size clamp, mirroring protectInlineAssets' own first
// two checks exactly (so the gate can never under-trigger relative to
// what protectInlineAssets would actually need htmls for).
func TestHasInlineCandidate(t *testing.T) {
	tests := []struct {
		name          string
		atts          []message.Attachment
		inlineMaxSize int64
		want          bool
	}{
		{
			name: "no parts at all",
			atts: nil,
			want: false,
		},
		{
			name: "no InlineAsset parts",
			atts: []message.Attachment{
				{PartPath: "0.1", InlineAsset: false, Size: 10},
				{PartPath: "0.2", InlineAsset: false, Size: 20},
			},
			inlineMaxSize: 1 << 20,
			want:          false,
		},
		{
			name: "InlineAsset within size clamp",
			atts: []message.Attachment{
				{PartPath: "0.1", InlineAsset: true, Size: 100},
			},
			inlineMaxSize: 1000,
			want:          true,
		},
		{
			name: "InlineAsset but oversized",
			atts: []message.Attachment{
				{PartPath: "0.1", InlineAsset: true, Size: 2000},
			},
			inlineMaxSize: 1000,
			want:          false,
		},
		{
			name: "mixed: one oversized InlineAsset, one within clamp",
			atts: []message.Attachment{
				{PartPath: "0.1", InlineAsset: true, Size: 2000},
				{PartPath: "0.2", InlineAsset: true, Size: 100},
			},
			inlineMaxSize: 1000,
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasInlineCandidate(tt.atts, tt.inlineMaxSize); got != tt.want {
				t.Errorf("hasInlineCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}
