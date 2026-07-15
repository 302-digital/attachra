package http_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// statsSummaryWireDTO mirrors api/openapi.yaml's StatsSummary schema
// for decoding test responses.
type statsSummaryWireDTO struct {
	From          string `json:"from"`
	To            string `json:"to"`
	MessagesByDay []struct {
		Day   string `json:"day"`
		Count int64  `json:"count"`
	} `json:"messages_by_day"`
	ActionBreakdown []struct {
		Label string `json:"label"`
		Count int64  `json:"count"`
	} `json:"action_breakdown"`
	PolicyBreakdown []struct {
		Label string `json:"label"`
		Count int64  `json:"count"`
	} `json:"policy_breakdown"`
	Downloads int64 `json:"downloads"`
	Errors    int64 `json:"errors"`
}

type deliverabilityEntryWireDTO struct {
	Domain          string  `json:"domain"`
	LinksCreated    int64   `json:"links_created"`
	LinksDownloaded int64   `json:"links_downloaded"`
	DownloadRate    float64 `json:"download_rate"`
}

type deliverabilityListWireDTO struct {
	Data       []deliverabilityEntryWireDTO `json:"data"`
	NextCursor *string                      `json:"next_cursor"`
}

func decodeStatsSummary(t *testing.T, resp *http.Response) statsSummaryWireDTO {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var dto statsSummaryWireDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		t.Fatalf("decode stats summary: %v", err)
	}
	return dto
}

func decodeDeliverabilityList(t *testing.T, resp *http.Response) deliverabilityListWireDTO {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var dto deliverabilityListWireDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		t.Fatalf("decode deliverability list: %v", err)
	}
	return dto
}

// TestStatsSummaryRoleEnforcement covers GET /stats/summary's
// x-required-role set: admin/viewer may read, auditor may not
// (ADR-015: auditor is scoped to the audit log only).
func TestStatsSummaryRoleEnforcement(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	_, viewerSecret := seedToken(t, st, "viewer", store.RoleViewer)
	_, auditorSecret := seedToken(t, st, "auditor", store.RoleAuditor)

	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	path := fmt.Sprintf("/api/v1/stats/summary?from=%s&to=%s", from, to)

	for _, tc := range []struct {
		name       string
		secret     string
		wantStatus int
	}{
		{"admin", adminSecret, http.StatusOK},
		{"viewer", viewerSecret, http.StatusOK},
		{"auditor", auditorSecret, http.StatusForbidden},
	} {
		resp := do(t, ts, http.MethodGet, path, tc.secret, "")
		if resp.StatusCode != tc.wantStatus {
			t.Errorf("%s: status = %d, want %d", tc.name, resp.StatusCode, tc.wantStatus)
		}
		_ = resp.Body.Close()
	}
}

// TestStatsSummaryRequiresWindow asserts `from`/`to` are mandatory
// (api/openapi.yaml: both `required: true`) and that an inverted
// window is rejected.
func TestStatsSummaryRequiresWindow(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	now := time.Now().UTC()
	from := now.Add(-time.Hour).Format(time.RFC3339)
	to := now.Add(time.Hour).Format(time.RFC3339)

	for _, tc := range []struct {
		name string
		path string
	}{
		{"missing both", "/api/v1/stats/summary"},
		{"missing to", "/api/v1/stats/summary?from=" + from},
		{"missing from", "/api/v1/stats/summary?to=" + to},
		{"malformed from", "/api/v1/stats/summary?from=not-a-time&to=" + to},
		{"to before from", fmt.Sprintf("/api/v1/stats/summary?from=%s&to=%s", to, from)},
	} {
		resp := do(t, ts, http.MethodGet, tc.path, adminSecret, "")
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", tc.name, resp.StatusCode)
		}
		if code := decodeError(t, resp); code != "bad_request" {
			t.Errorf("%s: error code = %q, want bad_request", tc.name, code)
		}
	}
}

// TestStatsSummaryAggregates seeds a few audit events directly and
// asserts GET /stats/summary reflects stats.Compute's aggregation
// (mirrors internal/core/stats' own unit tests, but end to end through
// the HTTP layer).
func TestStatsSummaryAggregates(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	ctx := context.Background()

	now := time.Now().UTC()
	mustRecord := func(typ audit.Type, details map[string]any) {
		t.Helper()
		if _, err := st.Record(ctx, audit.Event{Type: typ, Timestamp: now, Actor: "test", Details: details}); err != nil {
			t.Fatalf("Record(%q) error = %v, want nil", typ, err)
		}
	}
	mustRecord(audit.TypeMessageProcessed, nil)
	mustRecord(audit.TypeMessageProcessed, nil)
	mustRecord(audit.TypeDownload, map[string]any{"action": "download"})
	mustRecord(audit.TypeError, nil)

	from := now.Add(-time.Hour).Format(time.RFC3339)
	to := now.Add(time.Hour).Format(time.RFC3339)
	resp := do(t, ts, http.MethodGet, fmt.Sprintf("/api/v1/stats/summary?from=%s&to=%s", from, to), adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	dto := decodeStatsSummary(t, resp)

	if len(dto.MessagesByDay) != 1 || dto.MessagesByDay[0].Count != 2 {
		t.Errorf("MessagesByDay = %+v, want one day with count 2", dto.MessagesByDay)
	}
	if dto.Downloads != 1 {
		t.Errorf("Downloads = %d, want 1", dto.Downloads)
	}
	if dto.Errors != 1 {
		t.Errorf("Errors = %d, want 1", dto.Errors)
	}
}

// TestStatsDeliverabilityRoleEnforcement covers GET
// /stats/deliverability's x-required-role set: admin/viewer may read;
// auditor may not (ATR-274: deliverability is not an audit resource,
// ADR-015).
func TestStatsDeliverabilityRoleEnforcement(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	_, viewerSecret := seedToken(t, st, "viewer", store.RoleViewer)
	_, auditorSecret := seedToken(t, st, "auditor", store.RoleAuditor)

	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	path := fmt.Sprintf("/api/v1/stats/deliverability?from=%s&to=%s", from, to)

	for _, tc := range []struct {
		name       string
		secret     string
		wantStatus int
	}{
		{"admin", adminSecret, http.StatusOK},
		{"viewer", viewerSecret, http.StatusOK},
		{"auditor", auditorSecret, http.StatusForbidden},
	} {
		resp := do(t, ts, http.MethodGet, path, tc.secret, "")
		if resp.StatusCode != tc.wantStatus {
			t.Errorf("%s: status = %d, want %d", tc.name, resp.StatusCode, tc.wantStatus)
		}
		_ = resp.Body.Close()
	}
}

// TestStatsDeliverabilityRequiresWindow mirrors
// TestStatsSummaryRequiresWindow for the deliverability endpoint.
func TestStatsDeliverabilityRequiresWindow(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	resp := do(t, ts, http.MethodGet, "/api/v1/stats/deliverability", adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing window: status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestStatsDeliverabilityGroupsSortsAndPaginates seeds links across
// several recipient domains with varying download outcomes, then
// asserts the endpoint groups by domain, sorts ascending by
// download_rate by default (worst first), honors order=desc, and
// paginates via cursor/limit.
func TestStatsDeliverabilityGroupsSortsAndPaginates(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	// aaa.com: 2 links, 0 downloaded -> rate 0.0
	seedLink(t, st, "msg-1", "link-aaa-1", "a@aaa.com")
	seedLink(t, st, "msg-1", "link-aaa-2", "b@aaa.com")

	// bbb.com: 2 links, 1 downloaded -> rate 0.5
	seedLink(t, st, "msg-2", "link-bbb-1", "a@bbb.com")
	seedLink(t, st, "msg-2", "link-bbb-2", "b@bbb.com")
	registerTestDownload(t, st, "link-bbb-1")

	// ccc.com: 1 link, 1 downloaded -> rate 1.0
	seedLink(t, st, "msg-3", "link-ccc-1", "a@ccc.com")
	registerTestDownload(t, st, "link-ccc-1")

	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	// Default order: ascending by download_rate.
	resp := do(t, ts, http.MethodGet, fmt.Sprintf("/api/v1/stats/deliverability?from=%s&to=%s", from, to), adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	dto := decodeDeliverabilityList(t, resp)
	if len(dto.Data) != 3 {
		t.Fatalf("Data = %+v, want 3 domains", dto.Data)
	}
	wantOrder := []string{"aaa.com", "bbb.com", "ccc.com"}
	for i, domain := range wantOrder {
		if dto.Data[i].Domain != domain {
			t.Errorf("entry %d domain = %q, want %q (full: %+v)", i, dto.Data[i].Domain, domain, dto.Data)
		}
	}
	if dto.Data[0].LinksCreated != 2 || dto.Data[0].LinksDownloaded != 0 || dto.Data[0].DownloadRate != 0 {
		t.Errorf("aaa.com entry = %+v, want created=2 downloaded=0 rate=0", dto.Data[0])
	}
	if dto.Data[2].LinksCreated != 1 || dto.Data[2].LinksDownloaded != 1 || dto.Data[2].DownloadRate != 1 {
		t.Errorf("ccc.com entry = %+v, want created=1 downloaded=1 rate=1", dto.Data[2])
	}

	// order=desc reverses the result.
	resp = do(t, ts, http.MethodGet, fmt.Sprintf("/api/v1/stats/deliverability?from=%s&to=%s&order=desc", from, to), adminSecret, "")
	dtoDesc := decodeDeliverabilityList(t, resp)
	if len(dtoDesc.Data) != 3 || dtoDesc.Data[0].Domain != "ccc.com" || dtoDesc.Data[2].Domain != "aaa.com" {
		t.Errorf("order=desc Data = %+v, want reversed order", dtoDesc.Data)
	}

	// Pagination: limit=1 pages through all three domains via cursor.
	var seen []string
	cursor := ""
	for i := 0; i < 5; i++ {
		path := fmt.Sprintf("/api/v1/stats/deliverability?from=%s&to=%s&limit=1", from, to)
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		resp := do(t, ts, http.MethodGet, path, adminSecret, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("paginated request: status = %d, want 200", resp.StatusCode)
		}
		page := decodeDeliverabilityList(t, resp)
		if len(page.Data) != 1 {
			t.Fatalf("page %d Data = %+v, want exactly 1 entry", i, page.Data)
		}
		seen = append(seen, page.Data[0].Domain)
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if len(seen) != 3 {
		t.Fatalf("paginated through %d entries, want 3: %v", len(seen), seen)
	}
	for i, domain := range wantOrder {
		if seen[i] != domain {
			t.Errorf("paginated entry %d = %q, want %q", i, seen[i], domain)
		}
	}
}

// TestStatsDeliverabilityInvalidCursor asserts a bogus cursor is a
// clean 400, not a 500 or a silently-wrong page.
func TestStatsDeliverabilityInvalidCursor(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	seedLink(t, st, "msg-cursor", "link-cursor", "a@example.com")

	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	resp := do(t, ts, http.MethodGet, fmt.Sprintf("/api/v1/stats/deliverability?from=%s&to=%s&cursor=not-a-real-cursor", from, to), adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "bad_request" {
		t.Errorf("error code = %q, want bad_request", code)
	}
}

// registerTestDownload increments the Downloads counter of the link
// created by seedLink(..., linkID, ...) via the same TokenHash scheme
// seedLink uses ("hash-"+linkID), simulating a successful download for
// deliverability aggregation tests.
func registerTestDownload(t *testing.T, st *sqlite.Store, linkID string) {
	t.Helper()
	if _, err := st.RegisterDownload(context.Background(), "hash-"+linkID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("RegisterDownload(%q) error = %v, want nil", linkID, err)
	}
}
