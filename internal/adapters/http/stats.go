package http

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/302-digital/attachra/internal/core/stats"
	"github.com/302-digital/attachra/internal/core/store"
)

// dailyCountDTO mirrors api/openapi.yaml schema DailyCount.
type dailyCountDTO struct {
	Day   string `json:"day"`
	Count int64  `json:"count"`
}

// labeledCountDTO mirrors api/openapi.yaml schema LabeledCount.
type labeledCountDTO struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// statsSummaryDTO mirrors api/openapi.yaml schema StatsSummary (GET
// /stats/summary).
type statsSummaryDTO struct {
	From            string            `json:"from"`
	To              string            `json:"to"`
	MessagesByDay   []dailyCountDTO   `json:"messages_by_day"`
	ActionBreakdown []labeledCountDTO `json:"action_breakdown"`
	PolicyBreakdown []labeledCountDTO `json:"policy_breakdown"`
	Downloads       int64             `json:"downloads"`
	Errors          int64             `json:"errors"`
}

// toStatsSummaryDTO maps a stats.Summary to its wire shape, formatting
// timestamps as RFC3339Nano UTC and never returning a nil slice for
// any of the three breakdown fields (all "required" in the schema),
// even for an empty window.
func toStatsSummaryDTO(s stats.Summary) statsSummaryDTO {
	dto := statsSummaryDTO{
		From:            s.Query.From.UTC().Format(time.RFC3339Nano),
		To:              s.Query.To.UTC().Format(time.RFC3339Nano),
		MessagesByDay:   make([]dailyCountDTO, 0, len(s.MessagesByDay)),
		ActionBreakdown: make([]labeledCountDTO, 0, len(s.ActionBreakdown)),
		PolicyBreakdown: make([]labeledCountDTO, 0, len(s.PolicyBreakdown)),
		Downloads:       s.Downloads,
		Errors:          s.Errors,
	}
	for _, d := range s.MessagesByDay {
		dto.MessagesByDay = append(dto.MessagesByDay, dailyCountDTO{Day: d.Day, Count: d.Count})
	}
	for _, a := range s.ActionBreakdown {
		dto.ActionBreakdown = append(dto.ActionBreakdown, labeledCountDTO{Label: a.Label, Count: a.Count})
	}
	for _, p := range s.PolicyBreakdown {
		dto.PolicyBreakdown = append(dto.PolicyBreakdown, labeledCountDTO{Label: p.Label, Count: p.Count})
	}
	return dto
}

// deliverabilityEntryDTO mirrors api/openapi.yaml schema
// DeliverabilityEntry.
type deliverabilityEntryDTO struct {
	Domain          string  `json:"domain"`
	LinksCreated    int64   `json:"links_created"`
	LinksDownloaded int64   `json:"links_downloaded"`
	DownloadRate    float64 `json:"download_rate"`
}

// deliverabilityListDTO is the paginated list envelope (schema
// DeliverabilityList + PageMeta).
type deliverabilityListDTO struct {
	Data       []deliverabilityEntryDTO `json:"data"`
	NextCursor *string                  `json:"next_cursor"`
}

func toDeliverabilityEntryDTO(d stats.DomainStats) deliverabilityEntryDTO {
	return deliverabilityEntryDTO{
		Domain:          d.Domain,
		LinksCreated:    d.LinksCreated,
		LinksDownloaded: d.LinksDownloaded,
		DownloadRate:    d.DownloadRate,
	}
}

// handleStatsSummary implements GET /api/v1/stats/summary (admin,
// viewer): mirrors stats.Compute over a mandatory, explicit time
// window (api/openapi.yaml: `from`/`to` both required).
func (h *APIHandler) handleStatsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w, "GET")
		return
	}
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}

	from, ok := parseRequiredTimeParam(w, r, h.logger, "from")
	if !ok {
		return
	}
	to, ok := parseRequiredTimeParam(w, r, h.logger, "to")
	if !ok {
		return
	}
	if !to.After(from) {
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "\"to\" must be after \"from\"")
		return
	}

	summary, err := stats.Compute(r.Context(), h.auditReader, stats.Query{From: from, To: to})
	if err != nil {
		h.logger.Error("api: compute stats summary failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}
	writeAPIJSON(w, h.logger, http.StatusOK, toStatsSummaryDTO(summary))
}

// handleStatsDeliverability implements GET /api/v1/stats/deliverability
// (admin, viewer): link download-rate statistics broken down by
// recipient domain (ATR-231/ATR-274), sorted by download_rate (only
// supported sort key in v1) and paginated.
func (h *APIHandler) handleStatsDeliverability(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w, "GET")
		return
	}
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}

	limit, ok := parseLimit(w, r, h.logger)
	if !ok {
		return
	}
	if limit <= 0 {
		limit = defaultDeliverabilityPageSize
	}

	q := r.URL.Query()

	if sortKey := q.Get("sort"); sortKey != "" && sortKey != "download_rate" {
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid value for query parameter \"sort\"")
		return
	}

	desc := false
	switch order := q.Get("order"); order {
	case "", "asc":
		// Canonical ascending order — the default (worst-performing
		// domains first).
	case "desc":
		desc = true
	default:
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid value for query parameter \"order\"")
		return
	}

	from, ok := parseRequiredTimeParam(w, r, h.logger, "from")
	if !ok {
		return
	}
	to, ok := parseRequiredTimeParam(w, r, h.logger, "to")
	if !ok {
		return
	}
	if !to.After(from) {
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "\"to\" must be after \"from\"")
		return
	}

	entries, err := stats.ComputeDeliverability(r.Context(), h.metadata, stats.DomainQuery{From: from, To: to})
	if err != nil {
		h.logger.Error("api: compute deliverability stats failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}
	if desc {
		// ComputeDeliverability's canonical order is ascending by
		// (download_rate, domain); reversing it for descending order
		// necessarily also reverses the domain tie-break, which is
		// unspecified behavior either way (api/openapi.yaml only
		// documents the primary sort key).
		for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
			entries[i], entries[j] = entries[j], entries[i]
		}
	}

	start := 0
	if cursor := q.Get("cursor"); cursor != "" {
		domain, derr := decodeDomainCursor(cursor)
		if derr != nil {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid cursor")
			return
		}
		idx := indexOfDomain(entries, domain)
		if idx < 0 {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid cursor")
			return
		}
		start = idx + 1
	}

	end := start + limit
	if end > len(entries) {
		end = len(entries)
	}
	if start > len(entries) {
		start = len(entries)
	}
	page := entries[start:end]

	dto := deliverabilityListDTO{Data: make([]deliverabilityEntryDTO, 0, len(page))}
	for _, e := range page {
		dto.Data = append(dto.Data, toDeliverabilityEntryDTO(e))
	}
	if end < len(entries) {
		c := encodeDomainCursor(entries[end-1].Domain)
		dto.NextCursor = &c
	}
	writeAPIJSON(w, h.logger, http.StatusOK, dto)
}

// defaultDeliverabilityPageSize mirrors the API contract's shared
// Limit parameter default (api/openapi.yaml: 50); the maximum (200) is
// already enforced by parseLimit.
const defaultDeliverabilityPageSize = 50

// indexOfDomain returns the index of the entry whose Domain equals
// domain, or -1 if none matches.
func indexOfDomain(entries []stats.DomainStats, domain string) int {
	for i, e := range entries {
		if e.Domain == domain {
			return i
		}
	}
	return -1
}

// encodeDomainCursor/decodeDomainCursor implement GET
// /stats/deliverability's opaque pagination cursor: the domain name of
// the last entry returned on a page. Unlike every store-backed list
// endpoint (links, api-tokens, audit), this resource's data is a
// freshly recomputed in-memory aggregate on every request rather than
// a directly-paginated table, so a keyset cursor over the aggregate's
// own sort key (domain, which is unique per entry within one response)
// is the natural analogue: resuming "after domain X" only requires
// finding X in the freshly recomputed, identically-sorted result and
// continuing from there. A cursor naming a domain no longer present in
// the recomputed result (e.g. because the window's data changed
// between two calls) is reported as an invalid cursor (400) rather
// than silently resuming from the wrong position.
func encodeDomainCursor(domain string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(domain))
}

func decodeDomainCursor(cursor string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", fmt.Errorf("http: decode domain cursor: %w", err)
	}
	domain := string(raw)
	if domain == "" {
		return "", fmt.Errorf("http: decode domain cursor: empty domain")
	}
	return domain, nil
}

// parseRequiredTimeParam is parseTimeParam's stricter counterpart for
// query parameters the OpenAPI contract marks `required: true` (GET
// /stats/summary and GET /stats/deliverability's `from`/`to`): an
// absent value is itself a 400, not a valid "no bound" zero time.
func parseRequiredTimeParam(w http.ResponseWriter, r *http.Request, logger *slog.Logger, name string) (time.Time, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		writeAPIError(w, logger, http.StatusBadRequest, errCodeBadRequest, fmt.Sprintf("missing required query parameter %q", name))
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		writeAPIError(w, logger, http.StatusBadRequest, errCodeBadRequest, fmt.Sprintf("invalid value for query parameter %q", name))
		return time.Time{}, false
	}
	return t, true
}
