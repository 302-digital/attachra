package http_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// linkWireDTO mirrors api/openapi.yaml's Link schema for decoding test
// responses. token_hash is deliberately absent from the schema (and
// asserted absent from the raw body below), so it has no field here.
type linkWireDTO struct {
	ID           string  `json:"id"`
	MessageID    string  `json:"message_id"`
	AttachmentID string  `json:"attachment_id"`
	Recipient    string  `json:"recipient"`
	ExpiresAt    string  `json:"expires_at"`
	MaxDownloads int     `json:"max_downloads"`
	Downloads    int     `json:"downloads"`
	Status       string  `json:"status"`
	Hold         bool    `json:"hold"`
	HoldSetBy    *string `json:"hold_set_by"`
	HoldSetAt    *string `json:"hold_set_at"`
	CreatedAt    string  `json:"created_at"`
}

type linkListWireDTO struct {
	Data       []linkWireDTO `json:"data"`
	NextCursor *string       `json:"next_cursor"`
}

// seedLink creates a Message + one Attachment + one Link directly
// against st (there is no HTTP endpoint that creates a link — that
// only happens via the milter pipeline/link.Engine.CreateLinks), for
// tests that only need to read/mutate an existing link.
func seedLink(t *testing.T, st *sqlite.Store, messageID, linkID, recipient string) {
	t.Helper()
	ctx := context.Background()

	if err := st.CreateMessage(ctx, store.NewMessageParams{
		ID:      messageID,
		QueueID: "queue-" + messageID,
		Sender:  "sender@example.com",
	}); err != nil {
		// A message may already exist when seeding a second link for the
		// same message; that is expected and not a test failure.
		if _, getErr := st.GetMessage(ctx, messageID); getErr != nil {
			t.Fatalf("CreateMessage(%q) error = %v, want nil", messageID, err)
		}
	}

	attachmentID := linkID + "-att"
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID:           attachmentID,
		MessageID:    messageID,
		PartRef:      "1",
		Filename:     "report.pdf",
		DeclaredType: "application/pdf",
		DetectedType: "application/pdf",
		Size:         1024,
		StorageKey:   "ab/" + linkID,
	}); err != nil {
		t.Fatalf("CreateAttachment(%q) error = %v, want nil", attachmentID, err)
	}

	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           linkID,
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    recipient,
		TokenHash:    "hash-" + linkID,
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano),
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink(%q) error = %v, want nil", linkID, err)
	}
}

// decodeLink reads resp's body as a single linkWireDTO.
func decodeLink(t *testing.T, resp *http.Response) linkWireDTO {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var l linkWireDTO
	if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
		t.Fatalf("decode link: %v", err)
	}
	return l
}

// TestLinksRoleEnforcement covers every /links operation's
// x-required-role set (SR-130-3, api/openapi.yaml): admin/viewer may
// read (list/get), auditor may access neither (ADR-015: auditor is
// scoped to the audit log only), and every mutation (revoke, hold,
// unhold, the two cascades) is admin-only, with viewer and auditor
// both forbidden.
func TestLinksRoleEnforcement(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	_, viewerSecret := seedToken(t, st, "viewer", store.RoleViewer)
	_, auditorSecret := seedToken(t, st, "auditor", store.RoleAuditor)

	seedLink(t, st, "msg-role", "link-role", "recipient@example.com")

	// Reads: admin and viewer may list/get; auditor may not.
	for _, tc := range []struct {
		method, path, secret string
		wantStatus           int
	}{
		{http.MethodGet, "/api/v1/links", adminSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/links", viewerSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/links", auditorSecret, http.StatusForbidden},
		{http.MethodGet, "/api/v1/links/link-role", adminSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/links/link-role", viewerSecret, http.StatusOK},
		{http.MethodGet, "/api/v1/links/link-role", auditorSecret, http.StatusForbidden},
	} {
		resp := do(t, ts, tc.method, tc.path, tc.secret, "")
		if resp.StatusCode != tc.wantStatus {
			t.Errorf("%s %s (secret role test): status = %d, want %d", tc.method, tc.path, resp.StatusCode, tc.wantStatus)
		}
		_ = resp.Body.Close()
	}

	// Mutations: viewer and auditor are both forbidden; only admin may
	// proceed (proceeding itself is exercised by the more specific tests
	// below — here we only assert the 403 boundary for non-admins).
	mutations := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/v1/links/link-role/revoke", ""},
		{http.MethodPost, "/api/v1/links/link-role/hold", ""},
		{http.MethodPost, "/api/v1/links/link-role/unhold", ""},
		{http.MethodPost, "/api/v1/links/revoke-by-message", `{"message_id":"msg-role"}`},
		{http.MethodPost, "/api/v1/links/revoke-by-sender", `{"sender":"sender@example.com"}`},
	}
	for _, secret := range []string{viewerSecret, auditorSecret} {
		for _, m := range mutations {
			resp := do(t, ts, m.method, m.path, secret, m.body)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s %s as non-admin: status = %d, want 403", m.method, m.path, resp.StatusCode)
			}
			if code := decodeError(t, resp); code != "forbidden" {
				t.Errorf("%s %s as non-admin: error code = %q, want forbidden", m.method, m.path, code)
			}
		}
	}

	// No Authorization header at all: 401, not 403 or 404, on every route.
	for _, m := range append(mutations, struct{ method, path, body string }{http.MethodGet, "/api/v1/links", ""}) {
		resp := do(t, ts, m.method, m.path, "", m.body)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated: status = %d, want 401", m.method, m.path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

// TestLinksGetByID covers GET /links/{linkId}: a successful response
// never carries a token_hash field (CLAUDE.md invariant #5), and an
// unknown ID is 404.
func TestLinksGetByID(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	seedLink(t, st, "msg-get", "link-get", "recipient@example.com")

	resp := do(t, ts, http.MethodGet, "/api/v1/links/link-get", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET link: status = %d, want 200", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read GET link body: %v", err)
	}
	if strings.Contains(string(bodyBytes), "token_hash") {
		t.Errorf("GET link body contains token_hash, want it omitted entirely (CLAUDE.md invariant #5): %s", bodyBytes)
	}
	var got linkWireDTO
	if err := json.Unmarshal(bodyBytes, &got); err != nil {
		t.Fatalf("decode GET link body: %v", err)
	}
	if got.ID != "link-get" || got.MessageID != "msg-get" || got.Recipient != "recipient@example.com" {
		t.Errorf("GET link = %+v, want id=link-get message_id=msg-get recipient=recipient@example.com", got)
	}
	if got.Status != "active" || got.Hold {
		t.Errorf("GET link status/hold = %q/%v, want active/false for a freshly seeded link", got.Status, got.Hold)
	}

	resp = do(t, ts, http.MethodGet, "/api/v1/links/does-not-exist", adminSecret, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET missing link: status = %d, want 404", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "not_found" {
		t.Errorf("GET missing link: error code = %q, want not_found", code)
	}
}

// TestLinksRevokeSingle covers POST /links/{linkId}/revoke: a
// successful revoke returns the now-revoked link, an unknown ID is
// 404, and a held link is refused with 409 held (mirroring
// link.Engine.Revoke's ErrHeld, ATR-233/ATR-257).
func TestLinksRevokeSingle(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	seedLink(t, st, "msg-revoke", "link-revoke", "recipient@example.com")

	resp := do(t, ts, http.MethodPost, "/api/v1/links/link-revoke/revoke", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke link: status = %d, want 200", resp.StatusCode)
	}
	got := decodeLink(t, resp)
	if got.Status != "revoked" {
		t.Errorf("revoke link: status field = %q, want revoked", got.Status)
	}

	resp = do(t, ts, http.MethodPost, "/api/v1/links/does-not-exist/revoke", adminSecret, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoke missing link: status = %d, want 404", resp.StatusCode)
	}

	// A held link refuses revoke with 409 held.
	seedLink(t, st, "msg-revoke-held", "link-revoke-held", "recipient@example.com")
	if err := st.SetHold(context.Background(), "link-revoke-held", true, "compliance-officer", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}
	resp = do(t, ts, http.MethodPost, "/api/v1/links/link-revoke-held/revoke", adminSecret, "")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("revoke held link: status = %d, want 409", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "held" {
		t.Errorf("revoke held link: error code = %q, want held", code)
	}

	// The held link must still be active (refused, not partially applied).
	l, err := st.GetLinkByID(context.Background(), "link-revoke-held")
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if l.Status != store.LinkStatusActive {
		t.Errorf("held link Status after refused revoke = %q, want active", l.Status)
	}
}

// TestLinksHoldUnholdLifecycle covers POST /links/{linkId}/hold and
// /unhold (ATR-257): hold sets Hold/hold_set_by/hold_set_at and blocks
// a subsequent revoke; unhold clears it and lets revoke through.
func TestLinksHoldUnholdLifecycle(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	seedLink(t, st, "msg-hold", "link-hold", "recipient@example.com")

	resp := do(t, ts, http.MethodPost, "/api/v1/links/link-hold/hold", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("hold link: status = %d, want 200", resp.StatusCode)
	}
	held := decodeLink(t, resp)
	if !held.Hold {
		t.Errorf("hold link: hold field = false, want true")
	}
	if held.HoldSetBy == nil || *held.HoldSetBy == "" {
		t.Errorf("hold link: hold_set_by = %v, want a non-empty actor", held.HoldSetBy)
	}
	if held.HoldSetAt == nil || *held.HoldSetAt == "" {
		t.Errorf("hold link: hold_set_at = %v, want a timestamp", held.HoldSetAt)
	}

	// Revoke is refused while held.
	resp = do(t, ts, http.MethodPost, "/api/v1/links/link-hold/revoke", adminSecret, "")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("revoke while held: status = %d, want 409", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Unhold, then revoke succeeds.
	resp = do(t, ts, http.MethodPost, "/api/v1/links/link-hold/unhold", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unhold link: status = %d, want 200", resp.StatusCode)
	}
	unheld := decodeLink(t, resp)
	if unheld.Hold {
		t.Errorf("unhold link: hold field = true, want false")
	}

	resp = do(t, ts, http.MethodPost, "/api/v1/links/link-hold/revoke", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("revoke after unhold: status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Hold/unhold on an unknown link is 404.
	resp = do(t, ts, http.MethodPost, "/api/v1/links/does-not-exist/hold", adminSecret, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("hold missing link: status = %d, want 404", resp.StatusCode)
	}
}

// TestLinksRevokeByMessageCascade covers POST /links/revoke-by-message
// (mirrors link.Engine.RevokeMessage): a held link within the message
// is skipped and reported via the response's held count rather than
// failing the whole request (still 200), and an unknown message_id is
// 404.
func TestLinksRevokeByMessageCascade(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	seedLink(t, st, "msg-cascade", "link-cascade-1", "r1@example.com")
	seedLink(t, st, "msg-cascade", "link-cascade-2", "r2@example.com")
	if err := st.SetHold(context.Background(), "link-cascade-2", true, "compliance-officer", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	resp := do(t, ts, http.MethodPost, "/api/v1/links/revoke-by-message", adminSecret, `{"message_id":"msg-cascade"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke-by-message: status = %d, want 200", resp.StatusCode)
	}
	var result struct {
		Revoked int `json:"revoked"`
		Held    int `json:"held"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode revoke-by-message result: %v", err)
	}
	_ = resp.Body.Close()
	if result.Revoked != 1 {
		t.Errorf("revoke-by-message: revoked = %d, want 1", result.Revoked)
	}
	if result.Held != 1 {
		t.Errorf("revoke-by-message: held = %d, want 1", result.Held)
	}

	// The held link must still be active.
	l, err := st.GetLinkByID(context.Background(), "link-cascade-2")
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if l.Status != store.LinkStatusActive {
		t.Errorf("held link Status after partial cascade = %q, want active", l.Status)
	}

	resp = do(t, ts, http.MethodPost, "/api/v1/links/revoke-by-message", adminSecret, `{"message_id":"does-not-exist"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoke-by-message unknown message: status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = do(t, ts, http.MethodPost, "/api/v1/links/revoke-by-message", adminSecret, `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("revoke-by-message missing message_id: status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestLinksRevokeBySenderCascade covers POST /links/revoke-by-sender
// (mirrors link.Engine.RevokeSender, resolved via
// store.MetadataStore.ListMessagesBySender): revokes across every
// message from one sender, reports held_messages for any message that
// had a skipped held link, and treats an unknown sender as zero
// messages (200), not a 404.
func TestLinksRevokeBySenderCascade(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	const sender = "cascade-sender@example.com"

	seedLinkWithSender(t, st, "msg-sender-1", "link-sender-1", "r1@example.com", sender)
	seedLinkWithSender(t, st, "msg-sender-2", "link-sender-2", "r2@example.com", sender)
	if err := st.SetHold(context.Background(), "link-sender-2", true, "compliance-officer", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	resp := do(t, ts, http.MethodPost, "/api/v1/links/revoke-by-sender", adminSecret, fmt.Sprintf(`{"sender":%q}`, sender))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke-by-sender: status = %d, want 200", resp.StatusCode)
	}
	var result struct {
		Revoked      int `json:"revoked"`
		HeldMessages int `json:"held_messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode revoke-by-sender result: %v", err)
	}
	_ = resp.Body.Close()
	if result.Revoked != 1 {
		t.Errorf("revoke-by-sender: revoked = %d, want 1", result.Revoked)
	}
	if result.HeldMessages != 1 {
		t.Errorf("revoke-by-sender: held_messages = %d, want 1", result.HeldMessages)
	}

	// An unknown sender is not an error: zero messages, zero revoked.
	resp = do(t, ts, http.MethodPost, "/api/v1/links/revoke-by-sender", adminSecret, `{"sender":"no-such-sender@example.com"}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("revoke-by-sender unknown sender: status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = do(t, ts, http.MethodPost, "/api/v1/links/revoke-by-sender", adminSecret, `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("revoke-by-sender missing sender: status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// seedLinkWithSender is seedLink, but lets the caller control the
// message's Sender (seedLink always uses "sender@example.com"), for
// revoke-by-sender tests that need several messages sharing one
// sender.
func seedLinkWithSender(t *testing.T, st *sqlite.Store, messageID, linkID, recipient, sender string) {
	t.Helper()
	ctx := context.Background()

	if err := st.CreateMessage(ctx, store.NewMessageParams{
		ID:      messageID,
		QueueID: "queue-" + messageID,
		Sender:  sender,
	}); err != nil {
		t.Fatalf("CreateMessage(%q) error = %v, want nil", messageID, err)
	}

	attachmentID := linkID + "-att"
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID:           attachmentID,
		MessageID:    messageID,
		PartRef:      "1",
		Filename:     "report.pdf",
		DeclaredType: "application/pdf",
		DetectedType: "application/pdf",
		Size:         1024,
		StorageKey:   "ab/" + linkID,
	}); err != nil {
		t.Fatalf("CreateAttachment(%q) error = %v, want nil", attachmentID, err)
	}

	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           linkID,
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    recipient,
		TokenHash:    "hash-" + linkID,
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano),
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink(%q) error = %v, want nil", linkID, err)
	}
}

// TestLinksListPaginationAndFilters covers GET /links: the message_id,
// recipient and status filters, and cursor pagination (SR-130-5) that
// visits every matching row exactly once across pages.
func TestLinksListPaginationAndFilters(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	seedLink(t, st, "msg-list", "link-list-1", "recipient-a@example.com")
	seedLink(t, st, "msg-list", "link-list-2", "recipient-a@example.com")
	seedLink(t, st, "msg-list", "link-list-3", "recipient-b@example.com")
	seedLink(t, st, "msg-list-other", "link-list-other", "recipient-c@example.com")

	resp := do(t, ts, http.MethodPost, "/api/v1/links/link-list-1/revoke", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed revoke: status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// message_id filter.
	resp = do(t, ts, http.MethodGet, "/api/v1/links?message_id=msg-list", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list by message_id: status = %d, want 200", resp.StatusCode)
	}
	var page linkListWireDTO
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	_ = resp.Body.Close()
	if len(page.Data) != 3 {
		t.Fatalf("list by message_id: got %d links, want 3: %+v", len(page.Data), page.Data)
	}
	for _, l := range page.Data {
		if l.MessageID != "msg-list" {
			t.Errorf("list by message_id: unexpected link for message %q", l.MessageID)
		}
	}

	// recipient filter, case-insensitive.
	resp = do(t, ts, http.MethodGet, "/api/v1/links?message_id=msg-list&recipient=RECIPIENT-A%40EXAMPLE.COM", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list by recipient: status = %d, want 200", resp.StatusCode)
	}
	page = linkListWireDTO{}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	_ = resp.Body.Close()
	if len(page.Data) != 2 {
		t.Errorf("list by recipient: got %d links, want 2: %+v", len(page.Data), page.Data)
	}

	// status filter.
	resp = do(t, ts, http.MethodGet, "/api/v1/links?message_id=msg-list&status=revoked", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list by status: status = %d, want 200", resp.StatusCode)
	}
	page = linkListWireDTO{}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	_ = resp.Body.Close()
	if len(page.Data) != 1 || page.Data[0].ID != "link-list-1" {
		t.Errorf("list by status=revoked = %+v, want exactly link-list-1", page.Data)
	}

	// invalid status is a 400.
	resp = do(t, ts, http.MethodGet, "/api/v1/links?status=not-a-status", adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("list with invalid status: status = %d, want 400", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "bad_request" {
		t.Errorf("list with invalid status: error code = %q, want bad_request", code)
	}

	// Pagination: page through msg-list's 3 links one at a time and
	// confirm every one is seen exactly once.
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 10; i++ {
		path := "/api/v1/links?message_id=msg-list&limit=1"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		resp := do(t, ts, http.MethodGet, path, adminSecret, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("paginated list page %d: status = %d, want 200", i, resp.StatusCode)
		}
		var p linkListWireDTO
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			t.Fatalf("decode paginated list: %v", err)
		}
		_ = resp.Body.Close()
		if len(p.Data) != 1 {
			t.Fatalf("paginated list page %d: got %d links, want 1", i, len(p.Data))
		}
		if seen[p.Data[0].ID] {
			t.Fatalf("paginated list: repeated link %q", p.Data[0].ID)
		}
		seen[p.Data[0].ID] = true
		if p.NextCursor == nil || *p.NextCursor == "" {
			break
		}
		cursor = *p.NextCursor
	}
	if len(seen) != 3 {
		t.Errorf("paginated list saw %d distinct links, want 3: %+v", len(seen), seen)
	}

	// invalid limit is a 400.
	resp = do(t, ts, http.MethodGet, "/api/v1/links?limit=0", adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("list with invalid limit: status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// invalid cursor is a 400, not a 500.
	resp = do(t, ts, http.MethodGet, "/api/v1/links?cursor=not-a-real-cursor", adminSecret, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("list with invalid cursor: status = %d, want 400", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "bad_request" {
		t.Errorf("list with invalid cursor: error code = %q, want bad_request", code)
	}
}
