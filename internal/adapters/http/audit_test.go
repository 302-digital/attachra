package http_test

import (
	"context"
	"net/http/httptest"
	"testing"

	adapterhttp "github.com/302-digital/attachra/internal/adapters/http"
	"github.com/302-digital/attachra/internal/core/audit"
)

// collectAuditEvents drains every audit.Recorded event from env's
// underlying sqlite store (used as both MetadataStore and AuditSink in
// these tests, per newTestEnv).
func collectAuditEvents(t *testing.T, env *testEnv) []audit.Recorded {
	t.Helper()
	var got []audit.Recorded
	if err := env.store.StreamEvents(context.Background(), audit.Filter{}, func(r audit.Recorded) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	return got
}

// TestDownloadRecordsAuditEvent verifies a successful download (POST
// step 2) records a TypeDownload audit event carrying the message ID
// and no bearer token (US-7.1, ATR-190).
func TestDownloadRecordsAuditEvent(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	content := []byte("hello world, this is the attachment body")
	packageToken, linkID := env.seedMessage(t, "msg-audit-download", content, "report.pdf", "application/octet-stream")

	req := httptest.NewRequest("POST", downloadPath(packageToken, linkID), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("POST download status = %d, want 200", rr.Code)
	}

	got := collectAuditEvents(t, env)
	var found bool
	for _, e := range got {
		if e.Type != audit.TypeDownload {
			continue
		}
		if e.Details["action"] != "download" {
			continue
		}
		found = true
		if e.MessageID != "msg-audit-download" {
			t.Errorf("download event MessageID = %q, want %q", e.MessageID, "msg-audit-download")
		}
		if e.Actor == "" {
			t.Error("download event Actor is empty, want a non-empty adapter identity")
		}
		// The raw bearer token must never appear in the audit trail
		// (the token-hygiene invariant): only a short, non-reversible
		// reference is stored.
		if tokenRef, ok := e.Details["token_ref"].(string); !ok || tokenRef == packageToken {
			t.Errorf("download event Details[token_ref] = %v, want a short reference distinct from the raw token", e.Details["token_ref"])
		}
	}
	if !found {
		t.Fatalf("no TypeDownload/action=download event found among %d events: %+v", len(got), got)
	}
}

// TestPackagePageViewRecordsAuditEvent verifies GET /p/<token> records
// an audit event tagged package_page_view.
func TestPackagePageViewRecordsAuditEvent(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	content := []byte("hello world")
	packageToken, _ := env.seedMessage(t, "msg-audit-view", content, "report.pdf", "application/octet-stream")

	req := httptest.NewRequest("GET", packagePath(packageToken), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("GET package page status = %d, want 200", rr.Code)
	}

	got := collectAuditEvents(t, env)
	var found bool
	for _, e := range got {
		if e.Details["action"] == "package_page_view" {
			found = true
			if e.MessageID != "msg-audit-view" {
				t.Errorf("package_page_view event MessageID = %q, want %q", e.MessageID, "msg-audit-view")
			}
		}
	}
	if !found {
		t.Fatalf("no package_page_view event found among %d events: %+v", len(got), got)
	}
}

// TestNotFoundRecordsErrorAuditEvent verifies that a request against an
// unknown token is denied (generic 404, SR-125-5) but still recorded
// as a TypeError audit event, distinguishable internally from a
// successful outcome even though the HTTP response itself does not
// reveal which case occurred.
func TestNotFoundRecordsErrorAuditEvent(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})

	req := httptest.NewRequest("GET", packagePath("does-not-exist-token"), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 404 {
		t.Fatalf("GET unknown package token status = %d, want 404", rr.Code)
	}

	got := collectAuditEvents(t, env)
	var found bool
	for _, e := range got {
		if e.Type == audit.TypeError {
			found = true
			if e.Details["reason"] == "" || e.Details["reason"] == nil {
				t.Error("TypeError event Details[reason] is empty, want the internal denial reason")
			}
		}
	}
	if !found {
		t.Fatalf("no TypeError event found among %d events: %+v", len(got), got)
	}
}
