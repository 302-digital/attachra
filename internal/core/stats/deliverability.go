package stats

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
)

// domainScanPageSize is the internal batch size ComputeDeliverability
// requests from LinkSource.ListLinks while paging through a window's
// links. It bounds this function's own memory use to one page of raw
// Link rows at a time (the streaming invariant) — the per-domain
// running totals it accumulates across pages are bounded only by the
// number of distinct recipient domains in the window (ATR-273:
// "thousands of domains"), never by the number of links themselves. This is
// deliberately larger than the API-facing default page size
// (api/openapi.yaml Limit default 50): that parameter bounds the
// *response* ComputeDeliverability's caller returns to a client, not
// the internal scan this function performs to build it.
const domainScanPageSize = 500

// DomainQuery bounds one deliverability-by-domain aggregation
// (US-8.1/T-8.1.6, ATR-231/ATR-273/ATR-274) to an explicit, mandatory
// time window, mirroring Query's own "no unbounded scan" requirement:
// an unbounded query would take time proportional to the entire link
// table's history.
type DomainQuery struct {
	// From is the inclusive lower bound on Link.CreatedAt.
	From time.Time
	// To is the exclusive upper bound on Link.CreatedAt.
	To time.Time
}

// validate returns an error if q is not a well-formed, bounded query.
func (q DomainQuery) validate() error {
	if q.From.IsZero() || q.To.IsZero() {
		return fmt.Errorf("stats: domain query: From and To must both be set")
	}
	if !q.To.After(q.From) {
		return fmt.Errorf("stats: domain query: To (%s) must be after From (%s)", q.To, q.From)
	}
	return nil
}

// DomainStats is aggregated link creation/download counts for one
// recipient domain within a DomainQuery window (ATR-231/273/274): an
// anomalously low DownloadRate for a domain is an early signal of a
// deliverability or spam-filtering problem specific to that domain's
// mail infrastructure.
type DomainStats struct {
	// Domain is the recipient domain (the part of the address after
	// '@'), lower-cased for stable grouping regardless of how the
	// original address was cased.
	Domain string

	// LinksCreated is the number of links created for recipients at
	// this domain in the window.
	LinksCreated int64

	// LinksDownloaded is the number of those links with at least one
	// recorded download (store.Link.Downloads > 0) — a count of links,
	// not of individual download events.
	LinksDownloaded int64

	// DownloadRate is LinksDownloaded / LinksCreated. Always in [0, 1]
	// since LinksDownloaded never exceeds LinksCreated by construction.
	DownloadRate float64
}

// LinkSource is the narrow slice of store.MetadataStore
// ComputeDeliverability needs (ADR-002: this package depends only on
// this interface, never a concrete store or driver package — mirroring
// how Compute depends only on audit.Reader). store.MetadataStore
// satisfies it, so callers pass their existing MetadataStore value
// directly.
type LinkSource interface {
	ListLinks(ctx context.Context, p store.LinkListParams) (store.LinkPage, error)
}

// ComputeDeliverability aggregates every Link created in q's window,
// grouped by recipient domain (ATR-273: extending T-7.2.2's aggregated
// statistics with a recipient-domain slice). It pages through src via
// LinkSource.ListLinks internally (domainScanPageSize rows at a time),
// so no more than one page of raw Link rows is held in memory at once
// (the streaming invariant); the returned aggregate itself is bounded by
// the number of distinct domains observed, not by the number of links.
//
// The result is sorted ascending by DownloadRate, ties broken by
// ascending Domain, for deterministic output — matching
// api/openapi.yaml's GET /stats/deliverability default sort (worst
// download rate first, so a problem domain surfaces on page one). A
// caller wanting descending order reverses the returned slice; this
// function itself is presentation-order-agnostic beyond providing one
// deterministic canonical order to reverse.
func ComputeDeliverability(ctx context.Context, src LinkSource, q DomainQuery) ([]DomainStats, error) {
	if err := q.validate(); err != nil {
		return nil, err
	}

	type acc struct{ created, downloaded int64 }
	byDomain := make(map[string]*acc)

	cursor := ""
	for {
		page, err := src.ListLinks(ctx, store.LinkListParams{
			Limit:  domainScanPageSize,
			Cursor: cursor,
			From:   q.From,
			To:     q.To,
		})
		if err != nil {
			return nil, fmt.Errorf("stats: compute deliverability: %w", err)
		}

		for _, l := range page.Links {
			domain, ok := recipientDomain(l.Recipient)
			if !ok {
				// A malformed recipient with no '@' or an empty domain
				// part should not happen (link.Engine validates the
				// recipient before creating a Link), but this
				// aggregation defensively skips it rather than
				// crediting it to an empty-string "domain" bucket.
				continue
			}
			a := byDomain[domain]
			if a == nil {
				a = &acc{}
				byDomain[domain] = a
			}
			a.created++
			if l.Downloads > 0 {
				a.downloaded++
			}
		}

		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	out := make([]DomainStats, 0, len(byDomain))
	for domain, a := range byDomain {
		out = append(out, DomainStats{
			Domain:          domain,
			LinksCreated:    a.created,
			LinksDownloaded: a.downloaded,
			DownloadRate:    float64(a.downloaded) / float64(a.created),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DownloadRate != out[j].DownloadRate {
			return out[i].DownloadRate < out[j].DownloadRate
		}
		return out[i].Domain < out[j].Domain
	})
	return out, nil
}

// recipientDomain returns the lower-cased domain part of recipient
// (the text after the last '@'), and false if recipient has no '@' or
// an empty domain part.
func recipientDomain(recipient string) (string, bool) {
	i := strings.LastIndexByte(recipient, '@')
	if i < 0 || i == len(recipient)-1 {
		return "", false
	}
	return strings.ToLower(recipient[i+1:]), true
}
