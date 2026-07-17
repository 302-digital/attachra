package http_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// messageWireDTO mirrors api/openapi.yaml's Message schema for decoding
// test responses.
type messageWireDTO struct {
	ID              string   `json:"id"`
	QueueID         string   `json:"queue_id"`
	Sender          string   `json:"sender"`
	CreatedAt       string   `json:"created_at"`
	Recipients      []string `json:"recipients"`
	AttachmentCount int      `json:"attachment_count"`
	Status          *string  `json:"status"`
}

type messageListWireDTO struct {
	Data       []messageWireDTO `json:"data"`
	NextCursor *string          `json:"next_cursor"`
}

// seedMessageWithLink creates a Message with the given Sender, one
// Attachment and one Link to recipient, mirroring links_test.go's
// seedLink but returning the message/attachment IDs too (messages.go's
// tests need to add several attachments/links per message).
func seedMessageWithLink(t *testing.T, st *sqlite.Store, messageID, sender, recipient string) (attachmentID string) {
	t.Helper()
	ctx := context.Background()

	if err := st.CreateMessage(ctx, store.NewMessageParams{
		ID:      messageID,
		QueueID: "queue-" + messageID,
		Sender:  sender,
	}); err != nil {
		t.Fatalf("CreateMessage(%q) error = %v, want nil", messageID, err)
	}

	attachmentID = messageID + "-att"
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID:           attachmentID,
		MessageID:    messageID,
		PartRef:      "1",
		Filename:     "report.pdf",
		DeclaredType: "application/pdf",
		DetectedType: "application/pdf",
		Size:         1024,
		StorageKey:   "ab/" + messageID,
	}); err != nil {
		t.Fatalf("CreateAttachment(%q) error = %v, want nil", attachmentID, err)
	}

	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           messageID + "-link",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    recipient,
		TokenHash:    "hash-" + messageID,
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano),
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink(%q) error = %v, want nil", messageID, err)
	}

	return attachmentID
}

// TestMessagesRoleEnforcement covers GET /messages and GET
// /messages/{messageId}'s x-required-role set (SR-130-3,
// api/openapi.yaml): admin/viewer may read, auditor may not (ADR-015),
// and an unauthenticated caller gets 401.
func TestMessagesRoleEnforcement(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	_, viewerSecret := seedToken(t, st, "viewer", store.RoleViewer)
	_, auditorSecret := seedToken(t, st, "auditor", store.RoleAuditor)

	seedMessageWithLink(t, st, "msg-role", "sender@example.com", "recipient@example.com")

	for _, tc := range []struct {
		method, path, secret string
		wantStatus           int
	}{
		{http.MethodGet, "/api/v1/messages", adminSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/messages", viewerSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/messages", auditorSecret, http.StatusForbidden},
		{http.MethodGet, "/api/v1/messages/msg-role", adminSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/messages/msg-role", viewerSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/messages/msg-role", auditorSecret, http.StatusForbidden},
	} {
		resp := do(t, ts, tc.method, tc.path, tc.secret, "")
		if resp.StatusCode != tc.wantStatus {
			t.Errorf("%s %s: status = %d, want %d", tc.method, tc.path, resp.StatusCode, tc.wantStatus)
		}
		_ = resp.Body.Close()
	}

	for _, path := range []string{"/api/v1/messages", "/api/v1/messages/msg-role"} {
		resp := do(t, ts, http.MethodGet, path, "", "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s unauthenticated: status = %d, want 401", path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	// This resource has no mutation at all: POST is not a registered
	// method, so it answers 405, not 404 or 200.
	resp := do(t, ts, http.MethodPost, "/api/v1/messages", adminSecret, "{}")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /messages: status = %d, want 405 (no mutation defined on this resource)", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestMessagesGetByID covers GET /messages/{messageId}: the response
// aggregates recipients/attachment_count from this message's Link/
// Attachment rows and never carries storage_key or token_hash, and an
// unknown ID is 404.
func TestMessagesGetByID(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	seedMessageWithLink(t, st, "msg-get", "sender@example.com", "recipient@example.com")

	resp := do(t, ts, http.MethodGet, "/api/v1/messages/msg-get", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET message: status = %d, want 200", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read GET message body: %v", err)
	}
	if strings.Contains(string(bodyBytes), "storage_key") || strings.Contains(string(bodyBytes), "token_hash") {
		t.Errorf("GET message body leaks storage_key/token_hash, want neither present (SR-121-3, the token-hygiene invariant): %s", bodyBytes)
	}

	var got messageWireDTO
	if err := json.Unmarshal(bodyBytes, &got); err != nil {
		t.Fatalf("decode GET message body: %v", err)
	}
	if got.ID != "msg-get" || got.Sender != "sender@example.com" {
		t.Errorf("GET message = %+v, want id=msg-get sender=sender@example.com", got)
	}
	if got.AttachmentCount != 1 {
		t.Errorf("GET message attachment_count = %d, want 1", got.AttachmentCount)
	}
	if len(got.Recipients) != 1 || got.Recipients[0] != "recipient@example.com" {
		t.Errorf("GET message recipients = %+v, want exactly [recipient@example.com]", got.Recipients)
	}
	// seedMessageWithLink writes via CreateMessage directly (no Status),
	// so this message carries the legacy/unknown sentinel and must
	// render as JSON null, not an empty string.
	if got.Status != nil {
		t.Errorf("GET message status = %v, want null for a message with no persisted status", *got.Status)
	}

	resp = do(t, ts, http.MethodGet, "/api/v1/messages/does-not-exist", adminSecret, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET missing message: status = %d, want 404", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "not_found" {
		t.Errorf("GET missing message: error code = %q, want not_found", code)
	}
}

// TestMessagesListPaginationAndFilters covers GET /messages: the
// sender, recipient and status filters, and cursor pagination
// (SR-130-5) that visits every matching row exactly once across
// pages.
func TestMessagesListPaginationAndFilters(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	const sender = "list-sender@example.com"

	seedMessageWithLink(t, st, "msg-list-1", sender, "list-recipient-a@example.com")
	seedMessageWithLink(t, st, "msg-list-2", sender, "list-recipient-b@example.com")
	seedMessageWithLink(t, st, "msg-list-other", "other-sender@example.com", "list-recipient-c@example.com")

	// sender filter, case-insensitive.
	resp := do(t, ts, http.MethodGet, "/api/v1/messages?sender=LIST-SENDER%40EXAMPLE.COM", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list by sender: status = %d, want 200", resp.StatusCode)
	}
	var page messageListWireDTO
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	_ = resp.Body.Close()
	if len(page.Data) != 2 {
		t.Fatalf("list by sender: got %d messages, want 2: %+v", len(page.Data), page.Data)
	}

	// recipient filter.
	resp = do(t, ts, http.MethodGet, "/api/v1/messages?recipient=list-recipient-a%40example.com", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list by recipient: status = %d, want 200", resp.StatusCode)
	}
	page = messageListWireDTO{}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	_ = resp.Body.Close()
	if len(page.Data) != 1 || page.Data[0].ID != "msg-list-1" {
		t.Errorf("list by recipient = %+v, want exactly msg-list-1", page.Data)
	}

	// invalid status is a 400.
	resp = do(t, ts, http.MethodGet, "/api/v1/messages?status=not-a-status", adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("list with invalid status: status = %d, want 400", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "bad_request" {
		t.Errorf("list with invalid status: error code = %q, want bad_request", code)
	}

	// Pagination: page through sender's 2 messages one at a time and
	// confirm every one is seen exactly once.
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 10; i++ {
		path := "/api/v1/messages?sender=" + sender + "&limit=1"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		resp := do(t, ts, http.MethodGet, path, adminSecret, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("paginated list page %d: status = %d, want 200", i, resp.StatusCode)
		}
		var p messageListWireDTO
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			t.Fatalf("decode paginated list: %v", err)
		}
		_ = resp.Body.Close()
		if len(p.Data) != 1 {
			t.Fatalf("paginated list page %d: got %d messages, want 1", i, len(p.Data))
		}
		if seen[p.Data[0].ID] {
			t.Fatalf("paginated list: repeated message %q", p.Data[0].ID)
		}
		seen[p.Data[0].ID] = true
		if p.NextCursor == nil || *p.NextCursor == "" {
			break
		}
		cursor = *p.NextCursor
	}
	if len(seen) != 2 {
		t.Errorf("paginated list saw %d distinct messages, want 2: %+v", len(seen), seen)
	}

	// invalid cursor is a 400, not a 500.
	resp = do(t, ts, http.MethodGet, "/api/v1/messages?cursor=not-a-real-cursor", adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("list with invalid cursor: status = %d, want 400", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "bad_request" {
		t.Errorf("list with invalid cursor: error code = %q, want bad_request", code)
	}
}
