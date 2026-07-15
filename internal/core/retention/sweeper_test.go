package retention_test

import (
	"context"
	"errors"
	"fmt"
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
