package link

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
)

// streamEvents drains every audit.Recorded event from st (the same
// *sqlite.Store used as both MetadataStore and AuditSink by
// newTestEngine).
func streamEvents(t *testing.T, ctx context.Context, st interface {
	StreamEvents(context.Context, audit.Filter, func(audit.Recorded) error) error
}) []audit.Recorded {
	t.Helper()
	var got []audit.Recorded
	if err := st.StreamEvents(ctx, audit.Filter{}, func(r audit.Recorded) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	return got
}

// TestEngineRevokeRecordsAuditEvent verifies a successful single-link
// Revoke records a TypeRevoke event attributed to the given actor
// (US-7.1, ATR-190).
func TestEngineRevokeRecordsAuditEvent(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-audit-revoke", QueueID: "Q-audit", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-audit", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var linkID, tok string
	for _, c := range created {
		if c.AttachmentID != "" {
			tok = c.Token
		}
	}
	l, err := e.Resolve(ctx, tok)
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	linkID = l.ID

	if err := e.Revoke(ctx, "compliance-officer", linkID); err != nil {
		t.Fatalf("Revoke() error = %v, want nil", err)
	}

	got := streamEvents(t, ctx, st)
	var found bool
	for _, ev := range got {
		if ev.Type != audit.TypeRevoke {
			continue
		}
		if ev.Details["link_id"] != linkID {
			continue
		}
		found = true
		if ev.Actor != "compliance-officer" {
			t.Errorf("revoke event Actor = %q, want %q", ev.Actor, "compliance-officer")
		}
		if ev.MessageID != "msg-audit-revoke" {
			t.Errorf("revoke event MessageID = %q, want %q", ev.MessageID, "msg-audit-revoke")
		}
		if ev.Details["ok"] != true {
			t.Errorf("revoke event Details[ok] = %v, want true", ev.Details["ok"])
		}
	}
	if !found {
		t.Fatalf("no TypeRevoke event found for link %q among %d events: %+v", linkID, len(got), got)
	}
}

// TestEngineRevokeHeldRecordsFailedAuditEvent verifies that a revoke
// refused because the link is under legal hold still records a
// TypeRevoke event (Details[ok]=false), so the refusal itself is part
// of the audit trail.
func TestEngineRevokeHeldRecordsFailedAuditEvent(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-audit-held", QueueID: "Q-held", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-held", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var tok string
	for _, c := range created {
		if c.AttachmentID != "" {
			tok = c.Token
		}
	}
	l, err := e.Resolve(ctx, tok)
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}

	if err := st.SetHold(ctx, l.ID, true, "officer@example.com", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	if err := e.Revoke(ctx, "attacker-or-operator", l.ID); !errors.Is(err, ErrHeld) {
		t.Fatalf("Revoke() on held link error = %v, want wrapping ErrHeld", err)
	}

	got := streamEvents(t, ctx, st)
	var found bool
	for _, ev := range got {
		if ev.Type == audit.TypeRevoke && ev.Details["link_id"] == l.ID {
			found = true
			if ev.Details["ok"] != false {
				t.Errorf("revoke event Details[ok] = %v, want false (refused due to hold)", ev.Details["ok"])
			}
			if ev.Details["reason"] == "" || ev.Details["reason"] == nil {
				t.Error("revoke event Details[reason] is empty, want the hold refusal reason")
			}
		}
	}
	if !found {
		t.Fatalf("no TypeRevoke event found for held link %q among %d events: %+v", l.ID, len(got), got)
	}
}

// TestEngineRevokeMessageRecordsSingleSummaryAuditEvent verifies
// RevokeMessage records exactly one TypeRevoke event summarizing the
// whole cascade, rather than one per link.
func TestEngineRevokeMessageRecordsSingleSummaryAuditEvent(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	if _, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-audit-cascade", QueueID: "Q-cascade", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-cascade", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r1@example.com", "r2@example.com"},
	}); err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	if _, _, err := e.RevokeMessage(ctx, "compliance-officer", "msg-audit-cascade"); err != nil {
		t.Fatalf("RevokeMessage() error = %v, want nil", err)
	}

	got := streamEvents(t, ctx, st)
	count := 0
	for _, ev := range got {
		if ev.Type == audit.TypeRevoke && ev.Details["scope"] == "message" {
			count++
			// Details round-trips through JSON (sqlite's audit_events.details
			// column), so numeric values decode as float64, not int.
			if ev.Details["revoked"] != float64(2) {
				t.Errorf("revoke event Details[revoked] = %v (%T), want 2", ev.Details["revoked"], ev.Details["revoked"])
			}
		}
	}
	if count != 1 {
		t.Errorf("got %d message-scope TypeRevoke events, want exactly 1", count)
	}
}

// TestEngineSetHoldRecordsAuditEvent verifies both directions of
// SetHold (setting and clearing a hold) record a TypeHold audit event
// attributed to the given actor (ATR-257).
func TestEngineSetHoldRecordsAuditEvent(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-audit-hold", QueueID: "Q-hold-audit", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-audit-hold", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var tok string
	for _, c := range created {
		if c.AttachmentID != "" {
			tok = c.Token
		}
	}
	l, err := e.Resolve(ctx, tok)
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}

	if err := e.SetHold(ctx, "compliance-officer", l.ID, true); err != nil {
		t.Fatalf("SetHold(true) error = %v, want nil", err)
	}
	if err := e.SetHold(ctx, "compliance-officer", l.ID, false); err != nil {
		t.Fatalf("SetHold(false) error = %v, want nil", err)
	}

	got := streamEvents(t, ctx, st)
	var sawSet, sawClear bool
	for _, ev := range got {
		if ev.Type != audit.TypeHold || ev.Details["link_id"] != l.ID {
			continue
		}
		if ev.Actor != "compliance-officer" {
			t.Errorf("hold event Actor = %q, want %q", ev.Actor, "compliance-officer")
		}
		if ev.MessageID != "msg-audit-hold" {
			t.Errorf("hold event MessageID = %q, want %q", ev.MessageID, "msg-audit-hold")
		}
		if ev.Details["ok"] != true {
			t.Errorf("hold event Details[ok] = %v, want true", ev.Details["ok"])
		}
		switch ev.Details["hold"] {
		case true:
			sawSet = true
		case false:
			sawClear = true
		}
	}
	if !sawSet {
		t.Error("no TypeHold event with Details[hold]=true found")
	}
	if !sawClear {
		t.Error("no TypeHold event with Details[hold]=false found")
	}
}

// TestEnginePurgeMessageRecordsAuditEvent verifies a successful
// PurgeMessage (ATR-239) records a TypeCompensation event attributed to
// the given actor, with Details[ok]=true.
func TestEnginePurgeMessageRecordsAuditEvent(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	if _, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-audit-purge", QueueID: "Q-purge-audit", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-audit-purge", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
	}); err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	if err := e.PurgeMessage(ctx, "milter", "msg-audit-purge"); err != nil {
		t.Fatalf("PurgeMessage() error = %v, want nil", err)
	}

	got := streamEvents(t, ctx, st)
	var found bool
	for _, ev := range got {
		if ev.Type != audit.TypeCompensation || ev.MessageID != "msg-audit-purge" {
			continue
		}
		found = true
		if ev.Actor != "milter" {
			t.Errorf("compensation event Actor = %q, want %q", ev.Actor, "milter")
		}
		if ev.Details["ok"] != true {
			t.Errorf("compensation event Details[ok] = %v, want true", ev.Details["ok"])
		}
	}
	if !found {
		t.Fatal("no TypeCompensation event found for msg-audit-purge")
	}
}

// TestEnginePurgeMessageHeldRecordsFailedAuditEvent verifies a
// PurgeMessage refused because a link is under legal hold still records
// a TypeCompensation event (Details[ok]=false) and leaves every row
// (message, attachment, links) untouched.
func TestEnginePurgeMessageHeldRecordsFailedAuditEvent(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-audit-purge-held", QueueID: "Q-purge-held", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-purge-held", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var tok string
	for _, c := range created {
		if c.AttachmentID != "" {
			tok = c.Token
		}
	}
	l, err := e.Resolve(ctx, tok)
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	if err := st.SetHold(ctx, l.ID, true, "officer@example.com", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	if err := e.PurgeMessage(ctx, "milter", "msg-audit-purge-held"); !errors.Is(err, ErrHeld) {
		t.Fatalf("PurgeMessage() on message with a held link error = %v, want wrapping ErrHeld", err)
	}

	// The message, attachment and link must all survive: a refused
	// PurgeMessage is a no-op, never a partial prune.
	if _, err := st.GetMessage(ctx, "msg-audit-purge-held"); err != nil {
		t.Errorf("GetMessage() after refused purge error = %v, want nil (message must survive)", err)
	}
	if _, err := e.Resolve(ctx, tok); err != nil {
		t.Errorf("Resolve() after refused purge error = %v, want nil (link must remain active)", err)
	}

	got := streamEvents(t, ctx, st)
	var found bool
	for _, ev := range got {
		if ev.Type == audit.TypeCompensation && ev.MessageID == "msg-audit-purge-held" {
			found = true
			if ev.Details["ok"] != false {
				t.Errorf("compensation event Details[ok] = %v, want false (refused due to hold)", ev.Details["ok"])
			}
			if ev.Details["reason"] == "" || ev.Details["reason"] == nil {
				t.Error("compensation event Details[reason] is empty, want the hold refusal reason")
			}
		}
	}
	if !found {
		t.Fatal("no TypeCompensation event found for msg-audit-purge-held")
	}
}

// TestEnginePurgeMessageNotFoundIsIdempotent verifies PurgeMessage
// against an already-gone (or never-created) message returns a wrapped
// ErrNotFound rather than panicking, so a pipeline caller retrying
// after an earlier successful compensation (or racing a duplicate
// compensation attempt) never crashes.
func TestEnginePurgeMessageNotFoundIsIdempotent(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	if err := e.PurgeMessage(ctx, "milter", "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PurgeMessage() on unknown message error = %v, want wrapping ErrNotFound", err)
	}

	got := streamEvents(t, ctx, st)
	var found bool
	for _, ev := range got {
		if ev.Type == audit.TypeCompensation && ev.MessageID == "does-not-exist" {
			found = true
			if ev.Details["ok"] != false {
				t.Errorf("compensation event Details[ok] = %v, want false", ev.Details["ok"])
			}
		}
	}
	if !found {
		t.Fatal("no TypeCompensation event found for the unknown message id")
	}
}

// TestEngineSetHoldUnknownLinkRecordsFailedAuditEvent verifies SetHold
// against a nonexistent link still records a TypeHold event with
// Details[ok]=false, and returns a wrapped ErrNotFound.
func TestEngineSetHoldUnknownLinkRecordsFailedAuditEvent(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	if err := e.SetHold(ctx, "compliance-officer", "does-not-exist", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetHold() on unknown link error = %v, want wrapping ErrNotFound", err)
	}

	got := streamEvents(t, ctx, st)
	var found bool
	for _, ev := range got {
		if ev.Type == audit.TypeHold && ev.Details["link_id"] == "does-not-exist" {
			found = true
			if ev.Details["ok"] != false {
				t.Errorf("hold event Details[ok] = %v, want false", ev.Details["ok"])
			}
		}
	}
	if !found {
		t.Fatal("no TypeHold event found for the unknown link id")
	}
}
