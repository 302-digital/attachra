package retention_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/retention"
	"github.com/302-digital/attachra/internal/core/storage"
	fsstorage "github.com/302-digital/attachra/internal/core/storage/fs"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// testEnv bundles a freshly migrated sqlite store and an fs storage
// driver rooted in a temp dir, matching the pattern internal/core/link's
// own tests use for exercising real driver behavior instead of a hand
// rolled fake (link/engine_test.go's newTestEngine doc comment explains
// the rationale).
type testEnv struct {
	store   *sqlite.Store
	storage *fsstorage.Driver
}

func newTestEnv(t *testing.T) testEnv {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "retention-test.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	drv, err := fsstorage.New(fsstorage.Config{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("fsstorage.New() error = %v, want nil", err)
	}

	return testEnv{store: st, storage: drv}
}

// seedExpiredAttachment creates a Message + Attachment whose
// RetainUntil is in the past (or, if inTheFuture is true, one hour in
// the future) and uploads a small object to storage under its key,
// returning the attachment ID.
func seedExpiredAttachment(t *testing.T, env testEnv, id string, inTheFuture bool) (attachmentID, storageKey string) {
	t.Helper()
	ctx := context.Background()

	if err := env.store.CreateMessage(ctx, store.NewMessageParams{
		ID:      id,
		QueueID: "queue-" + id,
		Sender:  "sender@example.com",
	}); err != nil {
		t.Fatalf("CreateMessage() error = %v, want nil", err)
	}

	retainUntil := time.Now().Add(-1 * time.Hour)
	if inTheFuture {
		retainUntil = time.Now().Add(1 * time.Hour)
	}

	const payload = "payload"
	storageKey = "ab/" + id
	if err := env.storage.Put(ctx, storageKey, strings.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("Storage.Put() error = %v, want nil", err)
	}

	attachmentID = id + "-att"
	if err := env.store.CreateAttachment(ctx, store.NewAttachmentParams{
		ID:           attachmentID,
		MessageID:    id,
		PartRef:      "1",
		Filename:     "report.pdf",
		DeclaredType: "application/pdf",
		DetectedType: "application/pdf",
		Size:         int64(len(payload)),
		StorageKey:   storageKey,
		RetainUntil:  retainUntil.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("CreateAttachment() error = %v, want nil", err)
	}

	return attachmentID, storageKey
}

// TestSweepDeletesExpiredAttachment covers the core ATR-179 contract:
// an expired, non-held attachment has both its storage object and its
// metadata (attachment + its links) removed, and the deletion is
// recorded as an audit event.
func TestSweepDeletesExpiredAttachment(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	attachmentID, storageKey := seedExpiredAttachment(t, env, "msg-sweep-delete", false)

	if err := env.store.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-sweep-delete",
		MessageID:    "msg-sweep-delete",
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-sweep-delete",
		ExpiresAt:    time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano),
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	sweeper, err := retention.New(retention.Params{Metadata: env.store, Storage: env.storage, AuditSink: env.store})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}

	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.Deleted != 1 {
		t.Errorf("Sweep().Deleted = %d, want 1", res.Deleted)
	}
	if res.Failed != 0 {
		t.Errorf("Sweep().Failed = %d, want 0", res.Failed)
	}
	if res.HeldSkipped != 0 {
		t.Errorf("Sweep().HeldSkipped = %d, want 0", res.HeldSkipped)
	}

	if _, err := env.store.GetAttachment(ctx, attachmentID); err == nil {
		t.Errorf("GetAttachment() after sweep = nil error, want ErrNotFound (metadata must be deleted)")
	}
	if _, err := env.storage.Get(ctx, storageKey); err == nil {
		t.Errorf("Storage.Get() after sweep = nil error, want ErrNotFound (object must be deleted)")
	}

	var sawDeletionEvent bool
	if err := env.store.StreamEvents(ctx, audit.Filter{Type: audit.TypeRetentionCleanup}, func(rec audit.Recorded) error {
		if rec.Details["scope"] == "deletion" && rec.Details["attachment_id"] == attachmentID {
			sawDeletionEvent = true
		}
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	if !sawDeletionEvent {
		t.Error("no TypeRetentionCleanup deletion audit event recorded for the deleted attachment")
	}
}

// TestSweepSkipsHeldAttachment covers ATR-259: an attachment whose
// retention has elapsed but which has a held link must survive the
// sweep untouched, and the skip must be visible via
// Result.HeldSkipped/a held_summary audit event, distinct from a
// normal deletion.
func TestSweepSkipsHeldAttachment(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	attachmentID, storageKey := seedExpiredAttachment(t, env, "msg-sweep-held", false)

	if err := env.store.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-sweep-held",
		MessageID:    "msg-sweep-held",
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-sweep-held",
		ExpiresAt:    time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano),
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}
	if err := env.store.SetHold(ctx, "link-sweep-held", true, "compliance-officer", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	sweeper, err := retention.New(retention.Params{Metadata: env.store, Storage: env.storage, AuditSink: env.store})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}

	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.Deleted != 0 {
		t.Errorf("Sweep().Deleted = %d, want 0 (held attachment must survive)", res.Deleted)
	}
	if res.HeldSkipped != 1 {
		t.Errorf("Sweep().HeldSkipped = %d, want 1", res.HeldSkipped)
	}

	if _, err := env.store.GetAttachment(ctx, attachmentID); err != nil {
		t.Errorf("GetAttachment() after sweep error = %v, want nil (held attachment metadata must survive)", err)
	}
	if _, err := env.storage.Get(ctx, storageKey); err != nil {
		t.Errorf("Storage.Get() after sweep error = %v, want nil (held attachment object must survive)", err)
	}

	var sawHeldSummary bool
	if err := env.store.StreamEvents(ctx, audit.Filter{Type: audit.TypeRetentionCleanup}, func(rec audit.Recorded) error {
		if rec.Details["scope"] == "held_summary" {
			sawHeldSummary = true
		}
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	if !sawHeldSummary {
		t.Error("no held_summary TypeRetentionCleanup audit event recorded")
	}
}

// TestSweepLeavesFutureRetentionUntouched verifies an attachment whose
// RetainUntil has not yet elapsed is never selected for deletion.
func TestSweepLeavesFutureRetentionUntouched(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	attachmentID, storageKey := seedExpiredAttachment(t, env, "msg-sweep-future", true)

	sweeper, err := retention.New(retention.Params{Metadata: env.store, Storage: env.storage})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}

	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.Deleted != 0 {
		t.Errorf("Sweep().Deleted = %d, want 0", res.Deleted)
	}

	if _, err := env.store.GetAttachment(ctx, attachmentID); err != nil {
		t.Errorf("GetAttachment() after sweep error = %v, want nil", err)
	}
	if _, err := env.storage.Get(ctx, storageKey); err != nil {
		t.Errorf("Storage.Get() after sweep error = %v, want nil", err)
	}
}

// TestSweepIsIdempotent verifies that running Sweep twice in a row over
// the same backlog is safe: the second call finds nothing left to do.
func TestSweepIsIdempotent(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	seedExpiredAttachment(t, env, "msg-sweep-idempotent", false)

	sweeper, err := retention.New(retention.Params{Metadata: env.store, Storage: env.storage})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}

	first, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("first Sweep() error = %v, want nil", err)
	}
	if first.Deleted != 1 {
		t.Fatalf("first Sweep().Deleted = %d, want 1", first.Deleted)
	}

	second, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("second Sweep() error = %v, want nil", err)
	}
	if second.Deleted != 0 {
		t.Errorf("second Sweep().Deleted = %d, want 0 (nothing left to purge)", second.Deleted)
	}
	if second.Failed != 0 {
		t.Errorf("second Sweep().Failed = %d, want 0", second.Failed)
	}
}

// TestSweepChunksAcrossMultipleBatches verifies a backlog larger than
// ChunkSize is fully drained within a single Sweep call by looping over
// several chunks.
func TestSweepChunksAcrossMultipleBatches(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	const total = 5
	for i := 0; i < total; i++ {
		seedExpiredAttachment(t, env, "msg-sweep-chunk-"+string(rune('a'+i)), false)
	}

	sweeper, err := retention.New(retention.Params{Metadata: env.store, Storage: env.storage, ChunkSize: 2})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}

	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.Deleted != total {
		t.Errorf("Sweep().Deleted = %d, want %d (chunked sweep must drain the full backlog in one call)", res.Deleted, total)
	}
}

// TestNewRejectsMissingDependencies covers New's required-field
// validation.
func TestNewRejectsMissingDependencies(t *testing.T) {
	env := newTestEnv(t)

	if _, err := retention.New(retention.Params{Storage: env.storage}); err == nil {
		t.Error("New() with nil Metadata error = nil, want non-nil")
	}
	if _, err := retention.New(retention.Params{Metadata: env.store}); err == nil {
		t.Error("New() with nil Storage error = nil, want non-nil")
	}
}

// holdRaceStore wraps a store.MetadataStore, setting a legal hold on a
// target link the first time ListExpiredAttachments is called,
// simulating a compliance "race to preserve" landing in the window
// between the sweep's initial listing (T0) and this attachment's
// actual purge — the exact TOCTOU window the ATR-259 security review
// (B1) flagged. Since the hold lands before Sweeper even attempts to
// purge this attachment, it is expected to be caught by purgeOne's
// IsAttachmentHeld re-check, before any storage.Delete call happens.
type holdRaceStore struct {
	store.MetadataStore
	targetLinkID string
	injected     bool
}

func (h *holdRaceStore) ListExpiredAttachments(ctx context.Context, now string, limit int) ([]store.Attachment, error) {
	batch, err := h.MetadataStore.ListExpiredAttachments(ctx, now, limit)
	if err != nil {
		return nil, err
	}
	if !h.injected {
		h.injected = true
		if err := h.SetHold(ctx, h.targetLinkID, true, "compliance-officer", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, fmt.Errorf("inject hold: %w", err)
		}
	}
	return batch, nil
}

// TestSweepRaceHoldSetBetweenListAndPurge is the B1 regression test:
// a hold lands in the window between ListExpiredAttachments (T0) and
// this attachment's purge attempt. Both the storage object and the
// attachment metadata must survive completely untouched, and the sweep
// must report it as HeldSkipped, not Deleted and not Failed.
func TestSweepRaceHoldSetBetweenListAndPurge(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	attachmentID, storageKey := seedExpiredAttachment(t, env, "msg-race-list", false)
	if err := env.store.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-race-list",
		MessageID:    "msg-race-list",
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-race-list",
		ExpiresAt:    time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano),
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	racingStore := &holdRaceStore{MetadataStore: env.store, targetLinkID: "link-race-list"}
	sweeper, err := retention.New(retention.Params{Metadata: racingStore, Storage: env.storage, AuditSink: env.store})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}

	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.Deleted != 0 {
		t.Errorf("Sweep().Deleted = %d, want 0 (hold landed before purge)", res.Deleted)
	}
	if res.HeldSkipped != 1 {
		t.Errorf("Sweep().HeldSkipped = %d, want 1", res.HeldSkipped)
	}
	if res.Failed != 0 {
		t.Errorf("Sweep().Failed = %d, want 0", res.Failed)
	}

	if _, err := env.store.GetAttachment(ctx, attachmentID); err != nil {
		t.Errorf("GetAttachment() after race error = %v, want nil (metadata must survive the race)", err)
	}
	if _, err := env.storage.Get(ctx, storageKey); err != nil {
		t.Errorf("Storage.Get() after race error = %v, want nil (object bytes must survive the race)", err)
	}
}

// holdAfterStorageDeleteStorage wraps a storage.Driver, setting a legal
// hold on a target link right after its Delete call for the target key
// succeeds — simulating a hold landing in the narrower window between
// Sweeper's IsAttachmentHeld re-check and the storage delete completing
// (the one residual case this design documents rather than eliminates,
// see internal/core/retention's package doc comment and purgeOne's).
type holdAfterStorageDeleteStorage struct {
	storage.Driver
	metadata     store.MetadataStore
	targetLinkID string
	targetKey    string
	injected     bool
}

func (h *holdAfterStorageDeleteStorage) Delete(ctx context.Context, key string) error {
	err := h.Driver.Delete(ctx, key)
	if err == nil && key == h.targetKey && !h.injected {
		h.injected = true
		if setErr := h.metadata.SetHold(ctx, h.targetLinkID, true, "compliance-officer", time.Now().UTC().Format(time.RFC3339Nano)); setErr != nil {
			return fmt.Errorf("inject hold: %w", setErr)
		}
	}
	return err
}

// TestSweepRaceHoldSetBetweenStorageDeleteAndMetadataDelete covers the
// deepest, documented-residual layer of the B1 fix: a hold set after
// storage.Delete has already removed the object's bytes but before
// DeleteAttachment's own guard runs. DeleteAttachment must still refuse
// to remove the metadata row (store.ErrHeld), Sweeper must report this
// as HeldSkipped (never Deleted, never Failed), and the Attachment
// metadata row must survive — even though, in this specific scenario,
// the object bytes themselves are already gone (the accepted residual
// risk this package's doc comment describes, not a silent bug).
func TestSweepRaceHoldSetBetweenStorageDeleteAndMetadataDelete(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	attachmentID, storageKey := seedExpiredAttachment(t, env, "msg-race-storage", false)
	if err := env.store.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-race-storage",
		MessageID:    "msg-race-storage",
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-race-storage",
		ExpiresAt:    time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano),
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	racingStorage := &holdAfterStorageDeleteStorage{
		Driver:       env.storage,
		metadata:     env.store,
		targetLinkID: "link-race-storage",
		targetKey:    storageKey,
	}
	sweeper, err := retention.New(retention.Params{Metadata: env.store, Storage: racingStorage, AuditSink: env.store})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}

	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.Deleted != 0 {
		t.Errorf("Sweep().Deleted = %d, want 0", res.Deleted)
	}
	if res.HeldSkipped != 1 {
		t.Errorf("Sweep().HeldSkipped = %d, want 1", res.HeldSkipped)
	}
	if res.Failed != 0 {
		t.Errorf("Sweep().Failed = %d, want 0", res.Failed)
	}

	if _, err := env.store.GetAttachment(ctx, attachmentID); err != nil {
		t.Errorf("GetAttachment() after race error = %v, want nil (metadata must survive even though the object was already deleted)", err)
	}

	// The accepted residual risk this scenario documents: the object's
	// bytes are gone by the time the hold landed, since it was injected
	// right after storage.Delete succeeded.
	if _, err := env.storage.Get(ctx, storageKey); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Storage.Get() after race error = %v, want wrapping ErrNotFound (documented residual: bytes already deleted before the hold landed)", err)
	}
}

// erroringDeleteStorage wraps a storage.Driver, failing Delete for one
// specific key with a non-ErrNotFound error (e.g. simulating a
// permission-denied response from a real object store), leaving every
// other key's behavior delegated to the wrapped driver.
type erroringDeleteStorage struct {
	storage.Driver
	failKey string
}

func (e *erroringDeleteStorage) Delete(ctx context.Context, key string) error {
	if key == e.failKey {
		return errors.New("simulated storage error: permission denied")
	}
	return e.Driver.Delete(ctx, key)
}

// TestSweepStorageErrorLeavesMetadataAndObjectIntact covers N2: a
// non-ErrNotFound storage failure must not delete the metadata row
// (DeleteAttachment must never be reached for that attachment) and
// must not lose the object's bytes; the attachment is counted as
// Failed, not Deleted, and not silently dropped from future sweeps.
func TestSweepStorageErrorLeavesMetadataAndObjectIntact(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	attachmentID, storageKey := seedExpiredAttachment(t, env, "msg-storage-err", false)

	failingStorage := &erroringDeleteStorage{Driver: env.storage, failKey: storageKey}
	sweeper, err := retention.New(retention.Params{Metadata: env.store, Storage: failingStorage, AuditSink: env.store})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}

	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.Failed != 1 {
		t.Errorf("Sweep().Failed = %d, want 1", res.Failed)
	}
	if res.Deleted != 0 {
		t.Errorf("Sweep().Deleted = %d, want 0", res.Deleted)
	}
	if res.HeldSkipped != 0 {
		t.Errorf("Sweep().HeldSkipped = %d, want 0", res.HeldSkipped)
	}

	if _, err := env.store.GetAttachment(ctx, attachmentID); err != nil {
		t.Errorf("GetAttachment() after storage error error = %v, want nil (metadata must survive a storage error)", err)
	}
	if _, err := env.storage.Get(ctx, storageKey); err != nil {
		t.Errorf("Storage.Get() after storage error error = %v, want nil (object bytes must not be lost on a storage error)", err)
	}

	var sawFailedEvent bool
	if err := env.store.StreamEvents(ctx, audit.Filter{Type: audit.TypeRetentionCleanup}, func(rec audit.Recorded) error {
		if rec.Details["scope"] == "deletion" && rec.Details["attachment_id"] == attachmentID && rec.Details["ok"] == false {
			sawFailedEvent = true
		}
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	if !sawFailedEvent {
		t.Error("no failed (ok=false) TypeRetentionCleanup deletion audit event recorded for the storage error")
	}
}

// canceledDeleteStorage wraps a storage.Driver, failing Delete for one
// specific key with an error wrapping context.Canceled — simulating a
// ctx cancellation landing mid-call inside purgeOne's own storage
// delete, independent of whether the ctx passed into Sweep is actually
// canceled. This is the only reliable way to exercise
// purgeAndRecord's context.Canceled/DeadlineExceeded branch from a
// black-box test: the ctx-based interruption paths already covered by
// cancelAfterNDeletesStorage below (and Sweep's own per-attachment/
// per-chunk ctx.Err() checks) stop the pass *before* purgeAndRecord is
// ever called for the next attachment, so they never reach that
// branch themselves.
type canceledDeleteStorage struct {
	storage.Driver
	failKey string
}

func (c *canceledDeleteStorage) Delete(ctx context.Context, key string) error {
	if key == c.failKey {
		return fmt.Errorf("delete %q: %w", key, context.Canceled)
	}
	return c.Driver.Delete(ctx, key)
}

// TestSweepSuppressesContextCanceledAsFailure covers ATR-295's N4: a
// purge that fails specifically because of ctx cancellation (as
// opposed to a genuine storage error, already covered by
// TestSweepStorageErrorLeavesMetadataAndObjectIntact above) must not
// be counted in Result.Failed nor recorded as an ok=false audit event
// — purgeAndRecord's own doc comment already documents this
// suppression as deliberate (a shutdown/timeout landing on one
// attachment mid-pass is not a per-attachment failure, and treating it
// as one would flood the audit log every time a sweep pass happens to
// be interrupted); this test closes the gap that the suppression had
// no dedicated regression coverage (the existing ctx-cancellation
// test, TestSweepCtxCancellationSelfHealsOnNextPass, only asserts on
// the end-state data-safety invariant, not on audit-log volume/
// Result.Failed, by its own doc comment).
func TestSweepSuppressesContextCanceledAsFailure(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	attachmentID, storageKey := seedExpiredAttachment(t, env, "msg-ctx-canceled", false)

	canceledStorage := &canceledDeleteStorage{Driver: env.storage, failKey: storageKey}
	sweeper, err := retention.New(retention.Params{Metadata: env.store, Storage: canceledStorage, AuditSink: env.store})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}

	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.Failed != 0 {
		t.Errorf("Sweep().Failed = %d, want 0 (a ctx-cancellation-caused purge failure must not be counted as a failure)", res.Failed)
	}
	if res.Deleted != 0 {
		t.Errorf("Sweep().Deleted = %d, want 0", res.Deleted)
	}
	if res.HeldSkipped != 0 {
		t.Errorf("Sweep().HeldSkipped = %d, want 0", res.HeldSkipped)
	}

	// The metadata row must survive untouched, exactly like the
	// genuine-storage-error case: the next Sweep call (once the
	// interruption is over) retries it normally.
	if _, err := env.store.GetAttachment(ctx, attachmentID); err != nil {
		t.Errorf("GetAttachment() after ctx-canceled purge error = %v, want nil (metadata must survive)", err)
	}

	var sawEventForAttachment bool
	if err := env.store.StreamEvents(ctx, audit.Filter{Type: audit.TypeRetentionCleanup}, func(rec audit.Recorded) error {
		if rec.Details["attachment_id"] == attachmentID {
			sawEventForAttachment = true
		}
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	if sawEventForAttachment {
		t.Error("a per-attachment audit event was recorded for a purge that failed only because of ctx cancellation; want none (N4)")
	}
}

// cancelAfterNDeletesStorage wraps a storage.Driver, canceling ctx once
// its Delete method has been called n times, simulating a shutdown/
// timeout landing mid-pass.
type cancelAfterNDeletesStorage struct {
	storage.Driver
	cancel context.CancelFunc
	after  int
	calls  int
}

func (c *cancelAfterNDeletesStorage) Delete(ctx context.Context, key string) error {
	c.calls++
	err := c.Driver.Delete(ctx, key)
	if c.calls == c.after {
		c.cancel()
	}
	return err
}

// TestSweepCtxCancellationSelfHealsOnNextPass covers N2's ctx-
// cancellation requirement: interrupting a pass partway through must
// never leave a permanent half-deleted attachment (storage gone but
// metadata present, or vice versa) — a subsequent, uninterrupted pass
// must fully reconcile whatever the interrupted one left behind. It
// also implicitly exercises N2's "no false ok=false audit spam"
// requirement (purgeAndRecord suppresses context.Canceled): if that
// suppression were missing, the interrupted attachment would still
// self-heal here (the assertions below are about the end state, not
// about audit noise), so this test only checks the data-safety
// invariant, not the audit-log volume.
func TestSweepCtxCancellationSelfHealsOnNextPass(t *testing.T) {
	env := newTestEnv(t)

	const total = 3
	ids := make([]string, total)
	keys := make([]string, total)
	for i := 0; i < total; i++ {
		ids[i], keys[i] = seedExpiredAttachment(t, env, fmt.Sprintf("msg-sweep-cancel-%d", i), false)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cs := &cancelAfterNDeletesStorage{Driver: env.storage, cancel: cancel, after: 1}

	sweeper, err := retention.New(retention.Params{Metadata: env.store, Storage: cs, ChunkSize: 1})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}

	if _, err := sweeper.Sweep(ctx); err != nil {
		t.Fatalf("first (interrupted) Sweep() error = %v, want nil", err)
	}

	// Second pass: fresh, non-canceled context, uninterrupted storage
	// driver. Must fully drain whatever the first, interrupted pass
	// left behind.
	sweeper2, err := retention.New(retention.Params{Metadata: env.store, Storage: env.storage})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}
	if _, err := sweeper2.Sweep(context.Background()); err != nil {
		t.Fatalf("second Sweep() error = %v, want nil", err)
	}

	for i := 0; i < total; i++ {
		_, metaErr := env.store.GetAttachment(context.Background(), ids[i])
		_, storErr := env.storage.Get(context.Background(), keys[i])
		metaGone := errors.Is(metaErr, store.ErrNotFound)
		storGone := errors.Is(storErr, storage.ErrNotFound)
		if !metaGone || !storGone {
			t.Errorf("attachment %d not fully cleaned up after the recovery pass: metadata gone=%v, storage gone=%v (want both true, no permanent half-state)", i, metaGone, storGone)
		}
	}
}

// seedAuditEvent records an audit event with an explicit timestamp so a
// Sweep-level test can control which events fall before the cutoff.
func seedAuditEvent(t *testing.T, env testEnv, ts time.Time) {
	t.Helper()
	if _, err := env.store.Record(context.Background(), audit.Event{
		Timestamp: ts,
		Type:      audit.TypeMessageProcessed,
		Actor:     "milter",
		MessageID: "m",
		Details:   map[string]any{"k": "v"},
	}); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}
}

func countAuditRows(t *testing.T, env testEnv) int {
	t.Helper()
	var n int
	if err := env.store.StreamEvents(context.Background(), audit.Filter{}, func(audit.Recorded) error {
		n++
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	return n
}

// TestSweepLeavesAuditUntouchedByDefault pins the opt-in default (ADR-017,
// ATR-308): with no AuditTruncator/AuditRetention configured, a sweep pass
// never touches the append-only audit log, however old its rows are.
func TestSweepLeavesAuditUntouchedByDefault(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		seedAuditEvent(t, env, time.Now().Add(-100*24*time.Hour).Add(time.Duration(i)*time.Minute))
	}
	before := countAuditRows(t, env)

	// Default Params: no AuditTruncator, no AuditRetention.
	sweeper, err := retention.New(retention.Params{Metadata: env.store, Storage: env.storage, AuditSink: env.store})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}
	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.AuditTruncated != 0 {
		t.Errorf("AuditTruncated = %d, want 0 (retention disabled by default)", res.AuditTruncated)
	}
	if got := countAuditRows(t, env); got != before {
		t.Errorf("audit rows = %d, want %d unchanged (append-only preserved)", got, before)
	}
}

// TestSweepTruncatesAuditWhenConfigured covers the wired path: with a
// Truncator and a positive retention window, a sweep pass truncates the
// old audit prefix and reports the count.
func TestSweepTruncatesAuditWhenConfigured(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// 6 old events (~100 days ago) + 2 recent (now): with a 1h retention
	// window the 6 old ones are eligible, the 2 recent survive.
	for i := 0; i < 6; i++ {
		seedAuditEvent(t, env, time.Now().Add(-100*24*time.Hour).Add(time.Duration(i)*time.Minute))
	}
	for i := 0; i < 2; i++ {
		seedAuditEvent(t, env, time.Now())
	}

	sweeper, err := retention.New(retention.Params{
		Metadata:       env.store,
		Storage:        env.storage,
		AuditSink:      env.store,
		AuditTruncator: env.store,
		AuditRetention: time.Hour,
	})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}
	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.AuditTruncated != 6 {
		t.Errorf("AuditTruncated = %d, want 6", res.AuditTruncated)
	}

	// Exactly one checkpoint event now exists, and the two recent rows
	// survive alongside it (2 data + 1 checkpoint = 3).
	var checkpoints, total int
	if err := env.store.StreamEvents(ctx, audit.Filter{}, func(rec audit.Recorded) error {
		total++
		if rec.Type == audit.TypeRetentionCheckpoint {
			checkpoints++
		}
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	if checkpoints != 1 {
		t.Errorf("checkpoint events = %d, want 1", checkpoints)
	}
	if total != 3 {
		t.Errorf("surviving audit rows = %d, want 3 (2 recent + 1 checkpoint)", total)
	}
}

// TestSweepFullyClampedAuditTruncationLogsWarn covers N1 (security
// review, ATR-308): when legal hold clamps the truncation boundary all
// the way down to nothing eligible (HeldClamped && !Truncated), the
// sweep must not pass silently — an operator who enabled
// audit_retention_seconds and sees no growth relief needs a signal why.
func TestSweepFullyClampedAuditTruncationLogsWarn(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// A held message: message + attachment + link + hold.
	if err := env.store.CreateMessage(ctx, store.NewMessageParams{ID: "m-held", QueueID: "q-held", Sender: "a@example.com"}); err != nil {
		t.Fatalf("CreateMessage() error = %v", err)
	}
	if err := env.store.CreateAttachment(ctx, store.NewAttachmentParams{
		ID: "att-held", MessageID: "m-held", PartRef: "1", Filename: "f.bin",
		DeclaredType: "application/octet-stream", DetectedType: "application/octet-stream",
		Size: 10, StorageKey: "ab/held",
	}); err != nil {
		t.Fatalf("CreateAttachment() error = %v", err)
	}
	if err := env.store.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID: "link-held", MessageID: "m-held", AttachmentID: "att-held", Recipient: "r@example.com",
		TokenHash: "hash-fully-clamped", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v", err)
	}
	if err := env.store.SetHold(ctx, "link-held", true, "officer@example.com", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v", err)
	}

	// The ONLY old, otherwise-eligible event is tied to the held message,
	// so the whole eligible prefix gets clamped away.
	if _, err := env.store.Record(ctx, audit.Event{
		Timestamp: time.Now().Add(-100 * 24 * time.Hour),
		Type:      audit.TypePolicyDecision,
		Actor:     "milter",
		MessageID: "m-held",
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	sweeper, err := retention.New(retention.Params{
		Metadata:       env.store,
		Storage:        env.storage,
		AuditSink:      env.store,
		AuditTruncator: env.store,
		AuditRetention: time.Hour,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("retention.New() error = %v, want nil", err)
	}
	res, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep() error = %v, want nil", err)
	}
	if res.AuditTruncated != 0 {
		t.Errorf("AuditTruncated = %d, want 0 (fully clamped, nothing removed)", res.AuditTruncated)
	}
	if !strings.Contains(logBuf.String(), "audit truncation fully blocked by legal hold") {
		t.Errorf("log output = %q, want a Warn line about audit truncation fully blocked by legal hold", logBuf.String())
	}
}
