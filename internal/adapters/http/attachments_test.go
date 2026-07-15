package http_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// attachmentWireDTO mirrors api/openapi.yaml's Attachment schema for
// decoding test responses. storage_key is deliberately absent from the
// schema (and asserted absent from the raw body below), so it has no
// field here.
type attachmentWireDTO struct {
	ID           string  `json:"id"`
	MessageID    string  `json:"message_id"`
	PartRef      string  `json:"part_ref"`
	Filename     string  `json:"filename"`
	DeclaredType string  `json:"declared_type"`
	DetectedType string  `json:"detected_type"`
	Size         int64   `json:"size"`
	RetainUntil  *string `json:"retain_until"`
	CreatedAt    string  `json:"created_at"`
}

type attachmentListWireDTO struct {
	Data       []attachmentWireDTO `json:"data"`
	NextCursor *string             `json:"next_cursor"`
}

// seedAttachment creates a Message + one Attachment directly against
// st (there is no HTTP endpoint that creates an attachment — that only
// happens via the milter pipeline), for tests that only need to
// read an existing attachment.
func seedAttachment(t *testing.T, st *sqlite.Store, messageID, attachmentID, filename, mimeType string, size int64) {
	t.Helper()
	ctx := context.Background()

	if err := st.CreateMessage(ctx, store.NewMessageParams{
		ID:      messageID,
		QueueID: "queue-" + messageID,
		Sender:  "sender@example.com",
	}); err != nil {
		// A message may already exist when seeding a second attachment
		// for the same message; that is expected and not a test failure.
		if _, getErr := st.GetMessage(ctx, messageID); getErr != nil {
			t.Fatalf("CreateMessage(%q) error = %v, want nil", messageID, err)
		}
	}

	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID:           attachmentID,
		MessageID:    messageID,
		PartRef:      "1",
		Filename:     filename,
		DeclaredType: mimeType,
		DetectedType: mimeType,
		Size:         size,
		StorageKey:   "ab/" + attachmentID,
	}); err != nil {
		t.Fatalf("CreateAttachment(%q) error = %v, want nil", attachmentID, err)
	}
}

// TestAttachmentsRoleEnforcement covers GET /attachments and GET
// /attachments/{attachmentId}'s x-required-role set (SR-130-3,
// api/openapi.yaml): admin/viewer may read, auditor may not
// (ADR-015), and an unauthenticated caller gets 401.
func TestAttachmentsRoleEnforcement(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	_, viewerSecret := seedToken(t, st, "viewer", store.RoleViewer)
	_, auditorSecret := seedToken(t, st, "auditor", store.RoleAuditor)

	seedAttachment(t, st, "msg-role", "att-role", "report.pdf", "application/pdf", 1024)

	for _, tc := range []struct {
		method, path, secret string
		wantStatus           int
	}{
		{http.MethodGet, "/api/v1/attachments", adminSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/attachments", viewerSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/attachments", auditorSecret, http.StatusForbidden},
		{http.MethodGet, "/api/v1/attachments/att-role", adminSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/attachments/att-role", viewerSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/attachments/att-role", auditorSecret, http.StatusForbidden},
	} {
		resp := do(t, ts, tc.method, tc.path, tc.secret, "")
		if resp.StatusCode != tc.wantStatus {
			t.Errorf("%s %s: status = %d, want %d", tc.method, tc.path, resp.StatusCode, tc.wantStatus)
		}
		_ = resp.Body.Close()
	}

	for _, path := range []string{"/api/v1/attachments", "/api/v1/attachments/att-role"} {
		resp := do(t, ts, http.MethodGet, path, "", "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s unauthenticated: status = %d, want 401", path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	resp := do(t, ts, http.MethodPost, "/api/v1/attachments", adminSecret, "{}")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /attachments: status = %d, want 405 (no mutation defined on this resource)", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestAttachmentsGetByID covers GET /attachments/{attachmentId}: a
// successful response never carries storage_key (SR-121-3), and an
// unknown ID is 404.
func TestAttachmentsGetByID(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	seedAttachment(t, st, "msg-get", "att-get", "invoice.pdf", "application/pdf", 2048)

	resp := do(t, ts, http.MethodGet, "/api/v1/attachments/att-get", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET attachment: status = %d, want 200", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read GET attachment body: %v", err)
	}
	if strings.Contains(string(bodyBytes), "storage_key") {
		t.Errorf("GET attachment body contains storage_key, want it omitted entirely (SR-121-3): %s", bodyBytes)
	}

	var got attachmentWireDTO
	if err := json.Unmarshal(bodyBytes, &got); err != nil {
		t.Fatalf("decode GET attachment body: %v", err)
	}
	if got.ID != "att-get" || got.MessageID != "msg-get" || got.Filename != "invoice.pdf" {
		t.Errorf("GET attachment = %+v, want id=att-get message_id=msg-get filename=invoice.pdf", got)
	}
	if got.Size != 2048 {
		t.Errorf("GET attachment size = %d, want 2048", got.Size)
	}
	// seedAttachment does not set RetainUntil, so a freshly created
	// attachment must render the legacy sentinel as JSON null.
	if got.RetainUntil != nil {
		t.Errorf("GET attachment retain_until = %v, want null for an attachment with no retention set", *got.RetainUntil)
	}

	resp = do(t, ts, http.MethodGet, "/api/v1/attachments/does-not-exist", adminSecret, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET missing attachment: status = %d, want 404", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "not_found" {
		t.Errorf("GET missing attachment: error code = %q, want not_found", code)
	}
}

// TestAttachmentsListPaginationAndFilters covers GET /attachments: the
// message_id, filename glob, mime_type glob and min_size/max_size
// filters, and cursor pagination (SR-130-5) that visits every matching
// row exactly once across pages.
func TestAttachmentsListPaginationAndFilters(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	seedAttachment(t, st, "msg-list", "att-list-invoice", "invoice.pdf", "application/pdf", 1000)
	seedAttachment(t, st, "msg-list", "att-list-report", "report.PDF", "application/pdf", 5000)
	seedAttachment(t, st, "msg-list", "att-list-image", "photo.png", "image/png", 200000)
	seedAttachment(t, st, "msg-list-other", "att-list-other", "invoice.pdf", "application/pdf", 1000)

	// message_id filter.
	resp := do(t, ts, http.MethodGet, "/api/v1/attachments?message_id=msg-list", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list by message_id: status = %d, want 200", resp.StatusCode)
	}
	var page attachmentListWireDTO
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	_ = resp.Body.Close()
	if len(page.Data) != 3 {
		t.Fatalf("list by message_id: got %d attachments, want 3: %+v", len(page.Data), page.Data)
	}

	// filename glob filter, case-insensitive.
	resp = do(t, ts, http.MethodGet, "/api/v1/attachments?message_id=msg-list&filename=*.pdf", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list by filename: status = %d, want 200", resp.StatusCode)
	}
	page = attachmentListWireDTO{}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	_ = resp.Body.Close()
	if len(page.Data) != 2 {
		t.Errorf("list by filename=*.pdf (case-insensitive) got %d attachments, want 2: %+v", len(page.Data), page.Data)
	}

	// mime_type glob filter.
	resp = do(t, ts, http.MethodGet, "/api/v1/attachments?message_id=msg-list&mime_type=image%2F*", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list by mime_type: status = %d, want 200", resp.StatusCode)
	}
	page = attachmentListWireDTO{}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	_ = resp.Body.Close()
	if len(page.Data) != 1 || page.Data[0].ID != "att-list-image" {
		t.Errorf("list by mime_type=image/* = %+v, want exactly att-list-image", page.Data)
	}

	// min_size/max_size bounds.
	resp = do(t, ts, http.MethodGet, "/api/v1/attachments?message_id=msg-list&min_size=1000&max_size=5000", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list by size range: status = %d, want 200", resp.StatusCode)
	}
	page = attachmentListWireDTO{}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	_ = resp.Body.Close()
	if len(page.Data) != 2 {
		t.Errorf("list by size 1000..5000 got %d attachments, want 2: %+v", len(page.Data), page.Data)
	}

	// invalid min_size is a 400.
	resp = do(t, ts, http.MethodGet, "/api/v1/attachments?min_size=-1", adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("list with invalid min_size: status = %d, want 400", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "bad_request" {
		t.Errorf("list with invalid min_size: error code = %q, want bad_request", code)
	}

	// Pagination: page through msg-list's 3 attachments one at a time
	// and confirm every one is seen exactly once.
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 10; i++ {
		path := "/api/v1/attachments?message_id=msg-list&limit=1"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		resp := do(t, ts, http.MethodGet, path, adminSecret, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("paginated list page %d: status = %d, want 200", i, resp.StatusCode)
		}
		var p attachmentListWireDTO
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			t.Fatalf("decode paginated list: %v", err)
		}
		_ = resp.Body.Close()
		if len(p.Data) != 1 {
			t.Fatalf("paginated list page %d: got %d attachments, want 1", i, len(p.Data))
		}
		if seen[p.Data[0].ID] {
			t.Fatalf("paginated list: repeated attachment %q", p.Data[0].ID)
		}
		seen[p.Data[0].ID] = true
		if p.NextCursor == nil || *p.NextCursor == "" {
			break
		}
		cursor = *p.NextCursor
	}
	if len(seen) != 3 {
		t.Errorf("paginated list saw %d distinct attachments, want 3: %+v", len(seen), seen)
	}

	// invalid cursor is a 400, not a 500.
	resp = do(t, ts, http.MethodGet, "/api/v1/attachments?cursor=not-a-real-cursor", adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("list with invalid cursor: status = %d, want 400", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "bad_request" {
		t.Errorf("list with invalid cursor: error code = %q, want bad_request", code)
	}
}
