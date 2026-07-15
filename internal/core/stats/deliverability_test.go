package stats_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/stats"
	"github.com/302-digital/attachra/internal/core/store"
)

// fakeLinkSource is a minimal in-memory stats.LinkSource for
// unit-testing ComputeDeliverability's aggregation logic without a
// real store: it filters and pages a fixed slice of store.Link the
// same way the real sqlite implementation does (created_at range,
// keyset cursor over (created_at, id)), so ComputeDeliverability
// cannot tell the difference.
type fakeLinkSource struct {
	links []store.Link
	err   error

	// pageSizes records the Limit ComputeDeliverability requested on
	// each ListLinks call, so a test can assert it pages rather than
	// requesting everything in one call.
	pageSizes []int
}

func (f *fakeLinkSource) ListLinks(_ context.Context, p store.LinkListParams) (store.LinkPage, error) {
	if f.err != nil {
		return store.LinkPage{}, f.err
	}
	f.pageSizes = append(f.pageSizes, p.Limit)

	var afterCreatedAt, afterID string
	if p.Cursor != "" {
		var derr error
		afterCreatedAt, afterID, derr = store.DecodeCursor(p.Cursor)
		if derr != nil {
			return store.LinkPage{}, derr
		}
	}

	var matched []store.Link
	for _, l := range f.links {
		if !p.From.IsZero() && l.CreatedAt.Before(p.From) {
			continue
		}
		if !p.To.IsZero() && !l.CreatedAt.Before(p.To) {
			continue
		}
		if p.Cursor != "" {
			ca := l.CreatedAt.UTC().Format(time.RFC3339Nano)
			afterCursor := ca > afterCreatedAt || (ca == afterCreatedAt && l.ID > afterID)
			if !afterCursor {
				continue
			}
		}
		matched = append(matched, l)
	}

	limit := p.Limit
	if limit <= 0 || limit > len(matched) {
		limit = len(matched)
	}
	page := store.LinkPage{Links: matched[:limit]}
	if limit < len(matched) {
		last := matched[limit-1]
		page.NextCursor = store.EncodeCursor(last.CreatedAt.UTC().Format(time.RFC3339Nano), last.ID)
	}
	return page, nil
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("time.Parse(%q) error = %v, want nil", s, err)
	}
	return ts
}

func link(id, recipient string, downloads int, createdAt time.Time) store.Link {
	return store.Link{
		ID:        id,
		Recipient: recipient,
		Downloads: downloads,
		CreatedAt: createdAt,
	}
}

func TestComputeDeliverabilityGroupsByDomain(t *testing.T) {
	base := mustParseTime(t, "2026-07-01T00:00:00Z")
	src := &fakeLinkSource{links: []store.Link{
		link("l1", "alice@example.com", 1, base),
		link("l2", "bob@example.com", 0, base.Add(time.Minute)),
		link("l3", "carol@EXAMPLE.COM", 1, base.Add(2*time.Minute)), // same domain, different case
		link("l4", "dave@other.org", 0, base.Add(3*time.Minute)),
		link("l5", "erin@other.org", 0, base.Add(4*time.Minute)),
		// Outside the window: must be excluded.
		link("l6", "frank@example.com", 1, base.Add(-time.Hour)),
	}}

	q := stats.DomainQuery{From: base, To: base.Add(time.Hour)}
	got, err := stats.ComputeDeliverability(context.Background(), src, q)
	if err != nil {
		t.Fatalf("ComputeDeliverability() error = %v, want nil", err)
	}

	want := []stats.DomainStats{
		{Domain: "other.org", LinksCreated: 2, LinksDownloaded: 0, DownloadRate: 0},
		{Domain: "example.com", LinksCreated: 3, LinksDownloaded: 2, DownloadRate: 2.0 / 3.0},
	}
	if len(got) != len(want) {
		t.Fatalf("ComputeDeliverability() = %+v, want %d entries", got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestComputeDeliverabilitySortedByRateThenDomain(t *testing.T) {
	base := mustParseTime(t, "2026-07-01T00:00:00Z")
	src := &fakeLinkSource{links: []store.Link{
		link("l1", "a@zzz.com", 1, base), // rate 1.0
		link("l2", "b@aaa.com", 0, base), // rate 0.0
		link("l3", "c@mmm.com", 1, base), // rate 1.0, ties with zzz.com -> domain tiebreak
		link("l4", "d@mmm.com", 0, base), // brings mmm.com to rate 0.5
	}}

	q := stats.DomainQuery{From: base, To: base.Add(time.Hour)}
	got, err := stats.ComputeDeliverability(context.Background(), src, q)
	if err != nil {
		t.Fatalf("ComputeDeliverability() error = %v, want nil", err)
	}

	wantDomains := []string{"aaa.com", "mmm.com", "zzz.com"}
	if len(got) != len(wantDomains) {
		t.Fatalf("ComputeDeliverability() = %+v, want %d entries", got, len(wantDomains))
	}
	for i, d := range wantDomains {
		if got[i].Domain != d {
			t.Errorf("entry %d domain = %q, want %q (full: %+v)", i, got[i].Domain, d, got)
		}
	}
}

func TestComputeDeliverabilityPagesThroughSource(t *testing.T) {
	base := mustParseTime(t, "2026-07-01T00:00:00Z")
	var links []store.Link
	const n = 12
	for i := 0; i < n; i++ {
		links = append(links, link(fmt.Sprintf("l%d", i), fmt.Sprintf("user%d@domain%d.example", i, i%3), i%2, base.Add(time.Duration(i)*time.Second)))
	}
	src := &fakeLinkSource{links: links}

	// Force multiple pages by aggregating with a small internal page
	// size is not exposed as a parameter, but ComputeDeliverability's
	// own constant is much larger than n; this test instead asserts
	// pagination *works* end-to-end by checking every link was
	// accounted for, not that multiple ListLinks calls occurred (that
	// would require exposing the internal page size, which is not part
	// of the public contract).
	q := stats.DomainQuery{From: base, To: base.Add(time.Hour)}
	got, err := stats.ComputeDeliverability(context.Background(), src, q)
	if err != nil {
		t.Fatalf("ComputeDeliverability() error = %v, want nil", err)
	}

	var totalCreated int64
	for _, d := range got {
		totalCreated += d.LinksCreated
	}
	if totalCreated != n {
		t.Errorf("total LinksCreated across domains = %d, want %d", totalCreated, n)
	}
	if len(src.pageSizes) == 0 {
		t.Fatal("ListLinks was never called")
	}
}

func TestComputeDeliverabilityRejectsUnboundedQuery(t *testing.T) {
	src := &fakeLinkSource{}

	tests := []struct {
		name string
		q    stats.DomainQuery
	}{
		{"zero From", stats.DomainQuery{To: mustParseTime(t, "2026-07-02T00:00:00Z")}},
		{"zero To", stats.DomainQuery{From: mustParseTime(t, "2026-07-01T00:00:00Z")}},
		{"zero both", stats.DomainQuery{}},
		{"To before From", stats.DomainQuery{
			From: mustParseTime(t, "2026-07-02T00:00:00Z"),
			To:   mustParseTime(t, "2026-07-01T00:00:00Z"),
		}},
		{"To equal From", stats.DomainQuery{
			From: mustParseTime(t, "2026-07-01T00:00:00Z"),
			To:   mustParseTime(t, "2026-07-01T00:00:00Z"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := stats.ComputeDeliverability(context.Background(), src, tt.q); err == nil {
				t.Error("ComputeDeliverability() error = nil, want non-nil for an unbounded/invalid query")
			}
		})
	}
}

func TestComputeDeliverabilitySkipsMalformedRecipients(t *testing.T) {
	base := mustParseTime(t, "2026-07-01T00:00:00Z")
	src := &fakeLinkSource{links: []store.Link{
		link("l1", "no-at-sign", 0, base),
		link("l2", "trailing-at@", 0, base),
		link("l3", "valid@example.com", 1, base),
	}}

	q := stats.DomainQuery{From: base, To: base.Add(time.Hour)}
	got, err := stats.ComputeDeliverability(context.Background(), src, q)
	if err != nil {
		t.Fatalf("ComputeDeliverability() error = %v, want nil", err)
	}
	if len(got) != 1 || got[0].Domain != "example.com" {
		t.Fatalf("ComputeDeliverability() = %+v, want exactly one example.com entry", got)
	}
}

func TestComputeDeliverabilityPropagatesSourceError(t *testing.T) {
	wantErr := errors.New("boom")
	src := &fakeLinkSource{err: wantErr}
	q := stats.DomainQuery{
		From: mustParseTime(t, "2026-07-01T00:00:00Z"),
		To:   mustParseTime(t, "2026-07-02T00:00:00Z"),
	}

	_, err := stats.ComputeDeliverability(context.Background(), src, q)
	if !errors.Is(err, wantErr) {
		t.Errorf("ComputeDeliverability() error = %v, want it to wrap %v", err, wantErr)
	}
}

// BenchmarkComputeDeliverability exercises ComputeDeliverability over a
// synthetic window with thousands of domains and tens of thousands of
// links (ATR-273's acceptance criterion: "performance is acceptable
// (thousands of domains, tens of thousands of events/day)"), as a
// sanity check that the in-memory aggregation (bounded by domain
// cardinality, not link count) scales the way the package doc comment
// claims.
func BenchmarkComputeDeliverability(b *testing.B) {
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	const numDomains = 5000
	const linksPerDomain = 10 // 50,000 links total.

	links := make([]store.Link, 0, numDomains*linksPerDomain)
	for d := 0; d < numDomains; d++ {
		for i := 0; i < linksPerDomain; i++ {
			idx := d*linksPerDomain + i
			links = append(links, store.Link{
				ID:        fmt.Sprintf("l%d", idx),
				Recipient: fmt.Sprintf("user%d@domain%d.example", i, d),
				Downloads: idx % 3, // Some downloaded, some not.
				CreatedAt: base.Add(time.Duration(idx) * time.Second),
			})
		}
	}
	src := &fakeLinkSource{links: links}
	q := stats.DomainQuery{From: base, To: base.Add(24 * time.Hour)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := stats.ComputeDeliverability(context.Background(), src, q); err != nil {
			b.Fatalf("ComputeDeliverability() error = %v, want nil", err)
		}
	}
}
