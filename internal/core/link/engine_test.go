package link

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// newTestEngine opens a fresh sqlite-backed Engine for a test,
// registering cleanup. Package link is only allowed to depend on
// internal/core/store (the interface) at runtime; using the sqlite
// implementation directly here is a test-only, same-module dependency
// (internal/core/store/sqlite is still core, not an adapter) that lets
// these tests exercise the real guarded-UPDATE/transaction behavior
// instead of a hand-rolled fake that could drift from it.
func newTestEngine(t *testing.T, d Defaults) (*Engine, *sqlite.Store) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "engine-test.db")
	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	e, err := NewEngine(st, d, st, nil)
	if err != nil {
		t.Fatalf("NewEngine() error = %v, want nil", err)
	}
	return e, st
}

// newTestEngineWithLogger is newTestEngine plus a caller-supplied
// logger, for tests asserting on log output (ATR-294's retention-clamp
// warning).
func newTestEngineWithLogger(t *testing.T, d Defaults, logger *slog.Logger) (*Engine, *sqlite.Store) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "engine-test-logger.db")
	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	e, err := NewEngine(st, d, st, logger)
	if err != nil {
		t.Fatalf("NewEngine() error = %v, want nil", err)
	}
	return e, st
}

func defaultTestDefaults() Defaults {
	return Defaults{
		TTL:          72 * time.Hour,
		MaxDownloads: 0,
		TokenBytes:   MinTokenBytes,
	}
}

func TestEngineCreateLinksAndResolve(t *testing.T) {
	e, _ := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message: MessageInput{ID: "msg-1", QueueID: "Q1", Sender: "sender@example.com"},
		Attachments: []AttachmentInput{
			{ID: "att-1", PartRef: "2", Filename: "a.pdf", DeclaredType: "application/pdf", DetectedType: "application/pdf", Size: 100, StorageKey: "ab/1"},
			{ID: "att-2", PartRef: "3", Filename: "b.pdf", DeclaredType: "application/pdf", DetectedType: "application/pdf", Size: 200, StorageKey: "ab/2"},
		},
		Recipients: []string{"r1@example.com", "r2@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	// 2 attachments x 2 recipients = 4 file links, + 1 package token per
	// recipient (2) = 6 total CreatedLink entries.
	if len(created) != 6 {
		t.Fatalf("len(created) = %d, want 6", len(created))
	}

	fileLinks := 0
	packageLinks := 0
	for _, c := range created {
		if c.AttachmentID == "" {
			packageLinks++
			if _, err := e.ResolvePackage(ctx, c.Token); err != nil {
				t.Errorf("ResolvePackage(%q) error = %v, want nil", c.Token, err)
			}
			continue
		}
		fileLinks++
		l, err := e.Resolve(ctx, c.Token)
		if err != nil {
			t.Fatalf("Resolve(%q) error = %v, want nil", c.Token, err)
		}
		if l.AttachmentID != c.AttachmentID {
			t.Errorf("Resolve().AttachmentID = %q, want %q", l.AttachmentID, c.AttachmentID)
		}
		if l.Recipient != c.Recipient {
			t.Errorf("Resolve().Recipient = %q, want %q", l.Recipient, c.Recipient)
		}
	}
	if fileLinks != 4 {
		t.Errorf("fileLinks = %d, want 4", fileLinks)
	}
	if packageLinks != 2 {
		t.Errorf("packageLinks = %d, want 2", packageLinks)
	}

	filesR1, err := e.ListPackageFiles(ctx, "msg-1", "r1@example.com")
	if err != nil {
		t.Fatalf("ListPackageFiles() error = %v, want nil", err)
	}
	if len(filesR1) != 2 {
		t.Errorf("ListPackageFiles(msg-1, r1) returned %d links, want 2", len(filesR1))
	}
	for _, l := range filesR1 {
		if l.Recipient != "r1@example.com" {
			t.Errorf("ListPackageFiles(msg-1, r1) returned a Link for recipient %q, want only r1@example.com", l.Recipient)
		}
	}

	filesR2, err := e.ListPackageFiles(ctx, "msg-1", "r2@example.com")
	if err != nil {
		t.Fatalf("ListPackageFiles() error = %v, want nil", err)
	}
	if len(filesR2) != 2 {
		t.Errorf("ListPackageFiles(msg-1, r2) returned %d links, want 2", len(filesR2))
	}

	filesUnknown, err := e.ListPackageFiles(ctx, "msg-1", "nobody@example.com")
	if err != nil {
		t.Fatalf("ListPackageFiles() error = %v, want nil", err)
	}
	if len(filesUnknown) != 0 {
		t.Errorf("ListPackageFiles(msg-1, nobody) returned %d links, want 0", len(filesUnknown))
	}
}

func TestEngineCreateLinksAppliesPolicyParams(t *testing.T) {
	e, _ := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	ttl := policy.Duration(2 * time.Hour)
	maxDL := 5
	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-params", QueueID: "Q2", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-p", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
		Params:      policy.ActionParams{TTL: &ttl, MaxDownloads: &maxDL},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var fileLink *CreatedLink
	for i := range created {
		if created[i].AttachmentID != "" {
			fileLink = &created[i]
		}
	}
	if fileLink == nil {
		t.Fatalf("no file link found among created links")
	}
	if fileLink.MaxDownloads != maxDL {
		t.Errorf("MaxDownloads = %d, want %d (from policy params, overriding Defaults)", fileLink.MaxDownloads, maxDL)
	}

	wantExpiry := time.Now().Add(2 * time.Hour)
	if diff := fileLink.ExpiresAt.Sub(wantExpiry); diff > time.Minute || diff < -time.Minute {
		t.Errorf("ExpiresAt = %v, want approximately %v (2h TTL from policy params)", fileLink.ExpiresAt, wantExpiry)
	}
}

// TestEngineCreateLinksPersistsRetainUntil covers T-5.3.1/ATR-178:
// CreateLinks must write a storage RetainUntil into every created
// Attachment row, derived from the policy's `then.retention` when set,
// clamped to never be shorter than the resolved TTL.
func TestEngineCreateLinksPersistsRetainUntil(t *testing.T) {
	d := Defaults{TTL: 24 * time.Hour, MaxDownloads: 0, TokenBytes: MinTokenBytes, Retention: 30 * 24 * time.Hour}
	e, st := newTestEngine(t, d)
	ctx := context.Background()

	if _, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-retain", QueueID: "Q-retain", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-retain", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
	}); err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	got, err := st.GetAttachment(ctx, "att-retain")
	if err != nil {
		t.Fatalf("GetAttachment() error = %v, want nil", err)
	}
	if got.RetainUntil.IsZero() {
		t.Fatalf("GetAttachment().RetainUntil is zero, want the global default retention (30d) applied")
	}

	wantRetainUntil := time.Now().Add(30 * 24 * time.Hour)
	if diff := got.RetainUntil.Sub(wantRetainUntil); diff > time.Minute || diff < -time.Minute {
		t.Errorf("RetainUntil = %v, want approximately %v (30d default retention)", got.RetainUntil, wantRetainUntil)
	}
}

// TestEngineCreateLinksClampsRetainUntilToTTL covers the "retention >=
// ttl" invariant end to end: a policy retention shorter than its own
// ttl must not produce a RetainUntil earlier than the link's ExpiresAt.
func TestEngineCreateLinksClampsRetainUntilToTTL(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	ttl := policy.Duration(48 * time.Hour)
	retention := policy.Duration(1 * time.Hour) // Deliberately shorter than ttl.
	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-retain-clamp", QueueID: "Q-retain-clamp", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-retain-clamp", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
		Params:      policy.ActionParams{TTL: &ttl, Retention: &retention},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var fileLink *CreatedLink
	for i := range created {
		if created[i].AttachmentID != "" {
			fileLink = &created[i]
		}
	}
	if fileLink == nil {
		t.Fatalf("no file link found among created links")
	}

	got, err := st.GetAttachment(ctx, "att-retain-clamp")
	if err != nil {
		t.Fatalf("GetAttachment() error = %v, want nil", err)
	}
	if got.RetainUntil.Before(fileLink.ExpiresAt) {
		t.Errorf("RetainUntil = %v is before link ExpiresAt = %v; retention must never be shorter than ttl", got.RetainUntil, fileLink.ExpiresAt)
	}
}

// TestEngineCreateLinksLogsRetentionClampWarning covers ATR-294: when
// resolveParams raises retention to match ttl because a genuinely
// shorter retention was requested (mirroring
// TestEngineCreateLinksClampsRetainUntilToTTL's own params), the clamp
// must be observable via a warning log carrying the message ID and
// both the requested and effective retention values — not just via the
// RetainUntil value written to storage, which by itself gives no
// signal that anything diverged from what the policy asked for.
func TestEngineCreateLinksLogsRetentionClampWarning(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	e, _ := newTestEngineWithLogger(t, defaultTestDefaults(), logger)
	ctx := context.Background()

	ttl := policy.Duration(48 * time.Hour)
	retention := policy.Duration(1 * time.Hour) // Deliberately shorter than ttl.
	if _, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-clamp-log", QueueID: "Q-clamp-log", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-clamp-log", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
		Params:      policy.ActionParams{TTL: &ttl, Retention: &retention},
	}); err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	logOutput := logBuf.String()
	for _, want := range []string{"retention raised to match ttl", "msg-clamp-log", "requested_retention", "effective_retention"} {
		if !strings.Contains(logOutput, want) {
			t.Errorf("log output = %q, want it to contain %q", logOutput, want)
		}
	}
}

// TestEngineCreateLinksNoWarningWhenRetentionNotClamped is the
// negative counterpart of TestEngineCreateLinksLogsRetentionClampWarning:
// when the policy leaves retention entirely unset (the designed
// default-to-ttl fallback, not a surprising override — see
// resolvedParams.retentionClamped's own doc comment) or explicitly sets
// a retention already >= ttl, no clamp warning is logged.
func TestEngineCreateLinksNoWarningWhenRetentionNotClamped(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	e, _ := newTestEngineWithLogger(t, defaultTestDefaults(), logger)
	ctx := context.Background()

	if _, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-no-clamp-log", QueueID: "Q-no-clamp-log", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-no-clamp-log", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
		// Params left zero-value: no ttl/retention override at all.
	}); err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	if logOutput := logBuf.String(); strings.Contains(logOutput, "retention raised to match ttl") {
		t.Errorf("log output = %q, want no retention-clamp warning when retention was never explicitly set", logOutput)
	}
}

// TestEngineCreateLinksDedupesRetentionClampWarning covers the
// dedup layer added to ATR-294's clamp warning: a permanently
// misconfigured policy/config combination (the same ttl/retention pair
// clamping on every message that matches it) must only log the warning
// once per Engine lifetime for that exact (ttl, requestedRetention)
// combination — not once per message, which would flood the log at
// production mail volume — while a genuinely different clamp situation
// (a different ttl or a different requested retention) still gets its
// own, separate warning.
func TestEngineCreateLinksDedupesRetentionClampWarning(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	e, _ := newTestEngineWithLogger(t, defaultTestDefaults(), logger)
	ctx := context.Background()

	createOne := func(msgID string, ttl, retention time.Duration) {
		t.Helper()
		ttlD := policy.Duration(ttl)
		retD := policy.Duration(retention)
		if _, err := e.CreateLinks(ctx, CreateLinksParams{
			Message:     MessageInput{ID: msgID, QueueID: "Q-" + msgID, Sender: "s@example.com"},
			Attachments: []AttachmentInput{{ID: "att-" + msgID, PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
			Recipients:  []string{"r@example.com"},
			Params:      policy.ActionParams{TTL: &ttlD, Retention: &retD},
		}); err != nil {
			t.Fatalf("CreateLinks(%q) error = %v, want nil", msgID, err)
		}
	}

	// Same clamp situation (48h ttl, 1h requested retention) fires
	// three times across three different messages — only the first
	// should be logged.
	createOne("msg-dedup-1", 48*time.Hour, time.Hour)
	createOne("msg-dedup-2", 48*time.Hour, time.Hour)
	createOne("msg-dedup-3", 48*time.Hour, time.Hour)

	// A distinct clamp situation (different ttl) must still log its own
	// warning, dedup is per-key, not a global "log once ever" latch.
	createOne("msg-dedup-distinct", 72*time.Hour, time.Hour)

	logOutput := logBuf.String()
	gotWarnings := strings.Count(logOutput, "retention raised to match ttl")
	if gotWarnings != 2 {
		t.Errorf("retention-clamp warning logged %d time(s), want 2 (one per distinct (ttl, requested_retention) key); log output = %q", gotWarnings, logOutput)
	}
	if !strings.Contains(logOutput, "msg-dedup-1") {
		t.Errorf("log output = %q, want the first message_id (msg-dedup-1) for the repeated clamp key", logOutput)
	}
	if strings.Contains(logOutput, "msg-dedup-2") || strings.Contains(logOutput, "msg-dedup-3") {
		t.Errorf("log output = %q, want no entry for the deduped repeat messages (msg-dedup-2/3)", logOutput)
	}
	if !strings.Contains(logOutput, "msg-dedup-distinct") {
		t.Errorf("log output = %q, want an entry for the distinct clamp key (msg-dedup-distinct)", logOutput)
	}
}

func TestEngineCreateLinksFallsBackToDefaults(t *testing.T) {
	d := Defaults{TTL: time.Hour, MaxDownloads: 7, TokenBytes: MinTokenBytes}
	e, _ := newTestEngine(t, d)
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-defaults", QueueID: "Q3", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-d", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
		// Params left zero-value: policy specified no ttl/max_downloads override.
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	for _, c := range created {
		if c.AttachmentID == "" {
			continue
		}
		if c.MaxDownloads != 7 {
			t.Errorf("MaxDownloads = %d, want 7 (from Defaults)", c.MaxDownloads)
		}
	}
}

func TestEngineResolveUnknownTokenIsGenericNotFound(t *testing.T) {
	e, _ := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	if _, err := e.Resolve(ctx, "this-token-was-never-issued"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Resolve() error = %v, want wrapping ErrNotFound", err)
	}
}

func TestEngineResolveExpiredTokenIsGenericNotFound(t *testing.T) {
	e, _ := newTestEngine(t, Defaults{TTL: time.Nanosecond, MaxDownloads: 0, TokenBytes: MinTokenBytes})
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-expired", QueueID: "Q4", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-e", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	time.Sleep(time.Millisecond)

	var fileToken string
	for _, c := range created {
		if c.AttachmentID != "" {
			fileToken = c.Token
		}
	}

	if _, err := e.Resolve(ctx, fileToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("Resolve() on expired link error = %v, want wrapping ErrNotFound", err)
	}
}

func TestEngineRevokeCascade(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-revoke", QueueID: "Q5", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-r1", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k1"}},
		Recipients:  []string{"r1@example.com", "r2@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	revoked, held, err := e.RevokeMessage(ctx, "test-actor", "msg-revoke")
	if err != nil {
		t.Fatalf("RevokeMessage() error = %v, want nil", err)
	}
	if revoked != 2 {
		t.Errorf("revoked = %d, want 2", revoked)
	}
	if held != 0 {
		t.Errorf("held = %d, want 0", held)
	}

	for _, c := range created {
		if c.AttachmentID == "" {
			continue
		}
		if _, err := e.Resolve(ctx, c.Token); !errors.Is(err, ErrNotFound) {
			t.Errorf("Resolve() after cascade revoke error = %v, want wrapping ErrNotFound", err)
		}
	}

	links, err := st.ListLinksByMessage(ctx, "msg-revoke")
	if err != nil {
		t.Fatalf("ListLinksByMessage() error = %v, want nil", err)
	}
	for _, l := range links {
		if l.Status != store.LinkStatusRevoked {
			t.Errorf("link %q status = %q, want %q", l.ID, l.Status, store.LinkStatusRevoked)
		}
	}
}

func TestEngineRevokeSingleHeldLinkRefused(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-hold", QueueID: "Q6", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-h", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
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

	if err := e.Revoke(ctx, "test-actor", l.ID); !errors.Is(err, ErrHeld) {
		t.Errorf("Revoke() on held link error = %v, want wrapping ErrHeld", err)
	}

	// The link must still resolve: revoke was refused, not partially applied.
	if _, err := e.Resolve(ctx, tok); err != nil {
		t.Errorf("Resolve() after refused revoke error = %v, want nil (link must remain active)", err)
	}
}

func TestEngineRevokeMessageSkipsHeldAndReportsErrHeld(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-hold-cascade", QueueID: "Q7", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-hc", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r1@example.com", "r2@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var firstToken string
	for _, c := range created {
		if c.AttachmentID != "" {
			firstToken = c.Token
			break
		}
	}
	l, err := e.Resolve(ctx, firstToken)
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	if err := st.SetHold(ctx, l.ID, true, "officer@example.com", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	revoked, held, err := e.RevokeMessage(ctx, "test-actor", "msg-hold-cascade")
	if !errors.Is(err, ErrHeld) {
		t.Errorf("RevokeMessage() error = %v, want wrapping ErrHeld", err)
	}
	if revoked != 1 {
		t.Errorf("revoked = %d, want 1 (the non-held link)", revoked)
	}
	if held != 1 {
		t.Errorf("held = %d, want 1 (the held link)", held)
	}

	// The held link must still resolve.
	if _, err := e.Resolve(ctx, firstToken); err != nil {
		t.Errorf("Resolve() on held link after partial cascade error = %v, want nil", err)
	}
}

func TestEngineRegisterDownloadEnforcesLimit(t *testing.T) {
	maxDL := 2
	e, _ := newTestEngine(t, Defaults{TTL: time.Hour, MaxDownloads: maxDL, TokenBytes: MinTokenBytes})
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-dl", QueueID: "Q8", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-dl", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
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

	for i := 0; i < maxDL; i++ {
		if _, err := e.RegisterDownload(ctx, tok); err != nil {
			t.Fatalf("RegisterDownload() call %d error = %v, want nil", i+1, err)
		}
	}
	if _, err := e.RegisterDownload(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Errorf("RegisterDownload() beyond limit error = %v, want wrapping ErrNotFound", err)
	}
}

func TestEngineRegisterPackageDownloadHappyPath(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-pkg-dl", QueueID: "Q9", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-pkg-dl", PartRef: "1", Filename: "f.bin", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var packageToken string
	for _, c := range created {
		if c.AttachmentID == "" {
			packageToken = c.Token
		}
	}
	if packageToken == "" {
		t.Fatal("CreateLinks() did not return a package token")
	}

	links, err := st.ListLinksByMessage(ctx, "msg-pkg-dl")
	if err != nil || len(links) != 1 {
		t.Fatalf("ListLinksByMessage() = %+v, err = %v", links, err)
	}
	linkID := links[0].ID

	got, err := e.RegisterPackageDownload(ctx, packageToken, linkID)
	if err != nil {
		t.Fatalf("RegisterPackageDownload() error = %v, want nil", err)
	}
	if got.ID != linkID {
		t.Errorf("RegisterPackageDownload().ID = %q, want %q", got.ID, linkID)
	}
	if got.Downloads != 1 {
		t.Errorf("RegisterPackageDownload().Downloads = %d, want 1", got.Downloads)
	}
}

func TestEngineRegisterPackageDownloadRejectsUnknownPackageToken(t *testing.T) {
	e, _ := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	if _, err := e.RegisterPackageDownload(ctx, "does-not-exist", "does-not-matter"); !errors.Is(err, ErrNotFound) {
		t.Errorf("RegisterPackageDownload() with unknown package token error = %v, want wrapping ErrNotFound", err)
	}
}

// TestEngineRegisterPackageDownloadRejectsCrossMessageLinkID is the key
// authorization test for the package-page step-2 design (see engine.go's
// RegisterPackageDownload doc comment): a valid package token for
// message A must not be usable to charge a Link that belongs to
// message B, even though that Link's ID is a real, existing row.
func TestEngineRegisterPackageDownloadRejectsCrossMessageLinkID(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	createdA, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-a", QueueID: "QA", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-a", PartRef: "1", Filename: "a.bin", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "ka"}},
		Recipients:  []string{"r@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() for message A error = %v, want nil", err)
	}
	var packageTokenA string
	for _, c := range createdA {
		if c.AttachmentID == "" {
			packageTokenA = c.Token
		}
	}

	if _, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-b", QueueID: "QB", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-b", PartRef: "1", Filename: "b.bin", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "kb"}},
		Recipients:  []string{"r@example.com"},
	}); err != nil {
		t.Fatalf("CreateLinks() for message B error = %v, want nil", err)
	}

	linksB, err := st.ListLinksByMessage(ctx, "msg-b")
	if err != nil || len(linksB) != 1 {
		t.Fatalf("ListLinksByMessage(msg-b) = %+v, err = %v", linksB, err)
	}
	linkIDB := linksB[0].ID

	// Message A's package token paired with message B's link ID must be
	// refused as if the link did not exist at all.
	if _, err := e.RegisterPackageDownload(ctx, packageTokenA, linkIDB); !errors.Is(err, ErrNotFound) {
		t.Errorf("RegisterPackageDownload(tokenA, linkIDB) error = %v, want wrapping ErrNotFound", err)
	}

	got, err := st.GetLinkByID(ctx, linkIDB)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Downloads != 0 {
		t.Errorf("cross-message link Downloads = %d, want 0 (must not be charged)", got.Downloads)
	}
}

// TestEngineRegisterPackageDownloadRejectsCrossRecipientLinkID is the
// ATR-237 regression test: two recipients of the *same* message each
// get their own Link row per attachment (CreateLinks' per-recipient
// loop), but only one recipient's package token actually ships in the
// milter-MVP's shared body (pipeline.packageURLFor picks
// env.Recipients[0]). That one valid package token must not be usable
// to charge the *other* recipient's Link row for the same message,
// even though both rows share the same MessageID and the linkID is a
// real, existing row — this is exactly the leak/shared-budget-drain
// ATR-237 closes.
func TestEngineRegisterPackageDownloadRejectsCrossRecipientLinkID(t *testing.T) {
	e, st := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-multi-rcpt", QueueID: "QM", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-multi", PartRef: "1", Filename: "f.bin", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "km"}},
		Recipients:  []string{"alice@example.com", "bob@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var packageTokenAlice string
	for _, c := range created {
		if c.AttachmentID == "" && c.Recipient == "alice@example.com" {
			packageTokenAlice = c.Token
		}
	}
	if packageTokenAlice == "" {
		t.Fatal("CreateLinks() did not return a package token for alice@example.com")
	}

	links, err := st.ListLinksByMessage(ctx, "msg-multi-rcpt")
	if err != nil || len(links) != 2 {
		t.Fatalf("ListLinksByMessage() = %+v, err = %v, want 2 links (one per recipient)", links, err)
	}
	var bobLinkID string
	for _, l := range links {
		if l.Recipient == "bob@example.com" {
			bobLinkID = l.ID
		}
	}
	if bobLinkID == "" {
		t.Fatal("did not find a Link row for bob@example.com")
	}

	// Alice's package token paired with Bob's link ID for the same
	// message must be refused as if the link did not exist at all.
	if _, err := e.RegisterPackageDownload(ctx, packageTokenAlice, bobLinkID); !errors.Is(err, ErrNotFound) {
		t.Errorf("RegisterPackageDownload(aliceToken, bobLinkID) error = %v, want wrapping ErrNotFound", err)
	}

	got, err := st.GetLinkByID(ctx, bobLinkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Downloads != 0 {
		t.Errorf("bob's link Downloads = %d, want 0 (must not be charged by alice's token)", got.Downloads)
	}
}

// TestEngineSetHoldBlocksRevoke verifies the public SetHold API (as
// opposed to the store.SetHold used directly by other tests in this
// file) both sets the Hold flag that blocks Revoke and, once cleared,
// lets Revoke proceed (ATR-257).
func TestEngineSetHoldBlocksRevoke(t *testing.T) {
	e, _ := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, CreateLinksParams{
		Message:     MessageInput{ID: "msg-sethold", QueueID: "Q10", Sender: "s@example.com"},
		Attachments: []AttachmentInput{{ID: "att-sethold", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
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

	if err := e.SetHold(ctx, "officer@example.com", l.ID, true); err != nil {
		t.Fatalf("SetHold(true) error = %v, want nil", err)
	}

	if err := e.Revoke(ctx, "test-actor", l.ID); !errors.Is(err, ErrHeld) {
		t.Errorf("Revoke() on held link error = %v, want wrapping ErrHeld", err)
	}

	if err := e.SetHold(ctx, "officer@example.com", l.ID, false); err != nil {
		t.Fatalf("SetHold(false) error = %v, want nil", err)
	}

	if err := e.Revoke(ctx, "test-actor", l.ID); err != nil {
		t.Errorf("Revoke() after hold cleared error = %v, want nil", err)
	}
}

// TestEngineSetHoldUnknownLink verifies SetHold on a link ID that does
// not exist returns a wrapped ErrNotFound.
func TestEngineSetHoldUnknownLink(t *testing.T) {
	e, _ := newTestEngine(t, defaultTestDefaults())
	ctx := context.Background()

	if err := e.SetHold(ctx, "test-actor", "does-not-exist", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetHold() on unknown link error = %v, want wrapping ErrNotFound", err)
	}
}

func TestNewEngineRejectsInvalidDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-defaults.db")
	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	defer func() { _ = st.Close() }()

	if _, err := NewEngine(st, Defaults{TTL: 0, MaxDownloads: 0, TokenBytes: MinTokenBytes}, st, nil); err == nil {
		t.Errorf("NewEngine() with zero TTL error = nil, want an error")
	}
	if _, err := NewEngine(st, Defaults{TTL: time.Hour, MaxDownloads: -1, TokenBytes: MinTokenBytes}, st, nil); err == nil {
		t.Errorf("NewEngine() with negative MaxDownloads error = nil, want an error")
	}
	if _, err := NewEngine(st, Defaults{TTL: time.Hour, MaxDownloads: 0, TokenBytes: 1}, st, nil); err == nil {
		t.Errorf("NewEngine() with too-small TokenBytes error = nil, want an error")
	}
}
