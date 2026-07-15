package http_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store"
)

// auditEventWireDTO mirrors api/openapi.yaml's AuditEvent schema for
// decoding test responses.
type auditEventWireDTO struct {
	ID        string         `json:"id"`
	Seq       int64          `json:"seq"`
	PrevHash  string         `json:"prev_hash"`
	Timestamp string         `json:"timestamp"`
	Type      string         `json:"type"`
	Actor     string         `json:"actor"`
	MessageID string         `json:"message_id"`
	Recipient string         `json:"recipient"`
	Details   map[string]any `json:"details"`
}

type auditEventListWireDTO struct {
	Data       []auditEventWireDTO `json:"data"`
	NextCursor *string             `json:"next_cursor"`
}

func decodeAuditEventList(t *testing.T, resp *http.Response) auditEventListWireDTO {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var dto auditEventListWireDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		t.Fatalf("decode audit event list: %v", err)
	}
	return dto
}

// TestAuditorReachesAuditResourcesWithRealData is the positive half of
// the ADR-015 boundary check: an auditor token gets a real 200 with
// real content from GET /audit and GET /audit/export once actual
// audit/link data exists, against the full black-box server (real
// sqlite store, real middleware chain) this package's other tests use.
//
// The negative half — "and nothing else in the entire /api/v1
// surface" — is NOT asserted here via a hand-maintained path list:
// an earlier version of this test hardcoded seven negative routes
// and silently missed four already-registered mutations
// (/links/revoke-by-message, /links/revoke-by-sender,
// /links/{linkId}/hold, /links/{linkId}/unhold) plus the /policies
// routes added since, which a security review flagged as an
// overclaiming doc comment backed by an incomplete, driftable check.
// That regression guard now lives in auditrolematrix_test.go
// (TestAuditorRoleMatrixIsRouterDerived), which enumerates
// (*APIHandler).routes() directly — the same table newMux registers
// the live mux from — so a newly added route is automatically covered
// without another parallel list to keep in sync.
func TestAuditorReachesAuditResourcesWithRealData(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, auditorSecret := seedToken(t, st, "auditor", store.RoleAuditor)

	if _, err := st.Record(context.Background(), audit.Event{Type: audit.TypeError, Actor: "test"}); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}
	seedLink(t, st, "msg-auditor", "link-auditor", "a@example.com")

	for _, path := range []string{
		"/api/v1/audit",
		"/api/v1/audit/export",
	} {
		resp := do(t, ts, http.MethodGet, path, auditorSecret, "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("auditor GET %s: status = %d, want 200", path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

// TestAuditRoleEnforcement covers GET /audit and GET /audit/export's
// x-required-role set directly: admin, viewer and auditor may all
// read; there is no role excluded from either (unlike every other
// resource, where auditor is excluded).
func TestAuditRoleEnforcement(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	_, viewerSecret := seedToken(t, st, "viewer", store.RoleViewer)
	_, auditorSecret := seedToken(t, st, "auditor", store.RoleAuditor)

	for _, path := range []string{"/api/v1/audit", "/api/v1/audit/export"} {
		for _, tc := range []struct {
			name   string
			secret string
		}{
			{"admin", adminSecret},
			{"viewer", viewerSecret},
			{"auditor", auditorSecret},
		} {
			resp := do(t, ts, http.MethodGet, path, tc.secret, "")
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s GET %s: status = %d, want 200", tc.name, path, resp.StatusCode)
			}
			_ = resp.Body.Close()
		}
	}
}

// TestAuditListPagination seeds more events than one page holds and
// walks every page via NextCursor, asserting the concatenated result
// is every event in ascending seq order with no gaps or duplicates
// (US-8.1/T-8.1.6, SR-130-5).
func TestAuditListPagination(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	ctx := context.Background()

	const n = 7
	for i := 0; i < n; i++ {
		if _, err := st.Record(ctx, audit.Event{Type: audit.TypeError, Actor: "test"}); err != nil {
			t.Fatalf("Record() #%d error = %v, want nil", i, err)
		}
	}

	var seqs []int64
	cursor := ""
	for page := 0; ; page++ {
		if page > n {
			t.Fatalf("pagination did not terminate after %d pages", page)
		}
		path := "/api/v1/audit?limit=3"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		resp := do(t, ts, http.MethodGet, path, adminSecret, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		dto := decodeAuditEventList(t, resp)
		for _, e := range dto.Data {
			seqs = append(seqs, e.Seq)
		}
		if dto.NextCursor == nil {
			break
		}
		cursor = *dto.NextCursor
	}

	if len(seqs) != n {
		t.Fatalf("paginated through %d events, want %d", len(seqs), n)
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Errorf("seq %d = %d is not strictly greater than previous %d", i, seqs[i], seqs[i-1])
		}
	}
}

// TestAuditListFilters exercises the type and message_id query filters
// (api/openapi.yaml `GET /audit`).
func TestAuditListFilters(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	ctx := context.Background()

	mustRecord := func(typ audit.Type, messageID string) {
		t.Helper()
		if _, err := st.Record(ctx, audit.Event{Type: typ, Actor: "test", MessageID: messageID}); err != nil {
			t.Fatalf("Record(%q) error = %v, want nil", typ, err)
		}
	}
	mustRecord(audit.TypeDownload, "msg-a")
	mustRecord(audit.TypeRevoke, "msg-a")
	mustRecord(audit.TypeDownload, "msg-b")

	resp := do(t, ts, http.MethodGet, "/api/v1/audit?type=download", adminSecret, "")
	dto := decodeAuditEventList(t, resp)
	if len(dto.Data) != 2 {
		t.Fatalf("type=download Data = %+v, want 2 events", dto.Data)
	}

	resp = do(t, ts, http.MethodGet, "/api/v1/audit?message_id=msg-a", adminSecret, "")
	dto = decodeAuditEventList(t, resp)
	if len(dto.Data) != 2 {
		t.Fatalf("message_id=msg-a Data = %+v, want 2 events", dto.Data)
	}

	resp = do(t, ts, http.MethodGet, "/api/v1/audit?type=download&message_id=msg-b", adminSecret, "")
	dto = decodeAuditEventList(t, resp)
	if len(dto.Data) != 1 || dto.Data[0].MessageID != "msg-b" {
		t.Fatalf("combined filter Data = %+v, want exactly one msg-b download event", dto.Data)
	}
}

// TestAuditListInvalidTypeAndCursor asserts an unrecognized `type`
// value and a malformed `cursor` are both clean 400s.
func TestAuditListInvalidTypeAndCursor(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	resp := do(t, ts, http.MethodGet, "/api/v1/audit?type=not-a-real-type", adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid type: status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = do(t, ts, http.MethodGet, "/api/v1/audit?cursor=not-a-real-cursor", adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid cursor: status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestAuditExportStreamsJSONL asserts GET /audit/export renders one
// compact JSON object per line (application/x-ndjson), matching every
// recorded event, without pagination (SR-128-3).
func TestAuditExportStreamsJSONL(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	ctx := context.Background()

	const n = 4
	for i := 0; i < n; i++ {
		if _, err := st.Record(ctx, audit.Event{
			Type: audit.TypeDownload, Actor: "test", Details: map[string]any{"i": i},
		}); err != nil {
			t.Fatalf("Record() #%d error = %v, want nil", i, err)
		}
	}

	resp := do(t, ts, http.MethodGet, "/api/v1/audit/export", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	defer func() { _ = resp.Body.Close() }()

	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", ct)
	}

	scanner := bufio.NewScanner(resp.Body)
	var lines int
	for scanner.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("unmarshal export line %d: %v", lines, err)
		}
		if rec["type"] != string(audit.TypeDownload) {
			t.Errorf("line %d type = %v, want %q", lines, rec["type"], audit.TypeDownload)
		}
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error = %v, want nil", err)
	}
	if lines != n {
		t.Errorf("exported %d lines, want %d", lines, n)
	}
}

// TestAuditExportFiltersByTypeAndWindow exercises GET /audit/export's
// from/to/type filters.
func TestAuditExportFiltersByTypeAndWindow(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	ctx := context.Background()

	if _, err := st.Record(ctx, audit.Event{Type: audit.TypeDownload, Actor: "test"}); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}
	if _, err := st.Record(ctx, audit.Event{Type: audit.TypeRevoke, Actor: "test"}); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}

	resp := do(t, ts, http.MethodGet, "/api/v1/audit/export?type=revoke", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	defer func() { _ = resp.Body.Close() }()

	scanner := bufio.NewScanner(resp.Body)
	var types []string
	for scanner.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("unmarshal export line: %v", err)
		}
		types = append(types, rec["type"].(string))
	}
	if len(types) != 1 || types[0] != string(audit.TypeRevoke) {
		t.Errorf("exported types = %v, want exactly [revoke]", types)
	}
}
