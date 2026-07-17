package sqlite_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
	"github.com/302-digital/attachra/internal/core/store/storetest"
)

// openTestStore opens a fresh Store backed by a SQLite file inside
// t.TempDir(), running migrations, and registers Close via t.Cleanup.
func openTestStore(t *testing.T) *sqlite.Store {
	t.Helper()

	path := filepath.Join(t.TempDir(), "attachra-test.db")
	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("sqlite.Open(%q) error = %v, want nil", path, err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Store.Close() error = %v, want nil", err)
		}
	})

	return st
}

// TestContractSuite runs the shared store.MetadataStore behavioral
// contract against the sqlite implementation.
func TestContractSuite(t *testing.T) {
	storetest.Run(t, openTestStore(t))
}

// TestAPITokenContractSuite runs the shared store.APITokenStore
// behavioral contract (ATR-201) against the sqlite implementation.
func TestAPITokenContractSuite(t *testing.T) {
	storetest.RunAPITokenStore(t, openTestStore(t))
}

// TestMigrationsOnCleanDB verifies that Open() against a brand-new
// file path runs migrations to completion and that reopening the same
// path is a no-op (idempotent), per docs/architecture/adr-011-metadata-db.md
// ("golang-migrate with a versioned migration set from commit #1").
func TestMigrationsOnCleanDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attachra-migrate-test.db")

	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("first Open() error = %v, want nil", err)
	}

	ctx := context.Background()
	if err := st.CreateMessage(ctx, store.NewMessageParams{ID: "m1", QueueID: "q1", Sender: "a@example.com"}); err != nil {
		t.Fatalf("CreateMessage() after fresh migration error = %v, want nil", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}

	// Reopen: migrations must be idempotent (no "table already exists"
	// error) and the previously written row must still be there.
	st2, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("second Open() error = %v, want nil (migrations must be idempotent)", err)
	}
	defer func() { _ = st2.Close() }()

	got, err := st2.GetMessage(ctx, "m1")
	if err != nil {
		t.Fatalf("GetMessage() after reopen error = %v, want nil", err)
	}
	if got.ID != "m1" {
		t.Errorf("GetMessage().ID = %q, want %q", got.ID, "m1")
	}
}

// TestOpen_CreatesMissingNestedDBDir is the end-to-end regression for
// ATR-310: on a fresh install, database.path's containing directory
// may not exist yet (e.g. a systemd StateDirectory= that only created
// the top-level state directory, not a configured nested subpath
// underneath it). Open must create it (mode 0700) and come up fully
// migrated and usable, rather than the caller hitting a lazy,
// unhelpful SQLITE_CANTOPEN the first time a query runs - mirroring
// internal/core/storage/fs.New's TestNew_CreatesMissingNestedBaseDir
// for the storage-side ATR-309 fix.
func TestOpen_CreatesMissingNestedDBDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "db")
	path := filepath.Join(dir, "attachra.db")

	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("sqlite.Open(%q) error = %v, want nil for missing nested database directory", path, err)
	}
	t.Cleanup(func() { _ = st.Close() })

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat database directory after Open(): %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("database directory %q exists but is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("database directory mode = %o, want 0700", perm)
	}

	// The store must be immediately usable against the directory Open
	// just created, migrations and all.
	ctx := context.Background()
	if err := st.CreateMessage(ctx, store.NewMessageParams{ID: "m1", QueueID: "q1", Sender: "a@example.com"}); err != nil {
		t.Errorf("CreateMessage() after auto-created database directory error = %v, want nil", err)
	}
}

// TestRegisterDownloadConcurrent exercises the guarded atomic UPDATE
// under real concurrency: 16 goroutines race to download a link
// capped at max_downloads=3. Exactly 3 must succeed and 13 must
// observe ErrDownloadLimitReached — never more than 3 successes (a
// lost-update bug would let more than 3 through), matching the
// go test -race requirement for this critical path (the
// mail-must-never-be-lost invariant,
// docs/architecture/adr-011-metadata-db.md "atomic download counter
// increment").
func TestRegisterDownloadConcurrent(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	if err := st.CreateMessage(ctx, store.NewMessageParams{ID: "m-race", QueueID: "q-race", Sender: "a@example.com"}); err != nil {
		t.Fatalf("CreateMessage() error = %v, want nil", err)
	}
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID: "att-race", MessageID: "m-race", PartRef: "1", Filename: "f.bin",
		DeclaredType: "application/octet-stream", DetectedType: "application/octet-stream",
		Size: 10, StorageKey: "ab/race",
	}); err != nil {
		t.Fatalf("CreateAttachment() error = %v, want nil", err)
	}

	const maxDownloads = 3
	const goroutines = 16

	tokenHash := "hash-race"
	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	if err := st.CreateLink(ctx, store.NewLinkParams{
		ID: "link-race", MessageID: "m-race", AttachmentID: "att-race",
		Recipient: "r@example.com", TokenHash: tokenHash, ExpiresAt: expiresAt,
		MaxDownloads: maxDownloads,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	var wg sync.WaitGroup
	var successes int64
	var limitReached int64
	var unexpected int64

	now := time.Now().UTC().Format(time.RFC3339Nano)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := st.RegisterDownload(ctx, tokenHash, now)
			switch {
			case err == nil:
				atomic.AddInt64(&successes, 1)
			case errors.Is(err, store.ErrDownloadLimitReached):
				atomic.AddInt64(&limitReached, 1)
			default:
				atomic.AddInt64(&unexpected, 1)
				t.Errorf("RegisterDownload() unexpected error = %v", err)
			}
		}()
	}
	wg.Wait()

	if unexpected != 0 {
		t.Fatalf("got %d unexpected errors, want 0", unexpected)
	}
	if successes != maxDownloads {
		t.Errorf("successes = %d, want exactly %d (max_downloads)", successes, maxDownloads)
	}
	if limitReached != goroutines-maxDownloads {
		t.Errorf("limitReached = %d, want %d", limitReached, goroutines-maxDownloads)
	}

	got, err := st.GetLinkByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetLinkByTokenHash() error = %v, want nil", err)
	}
	if got.Downloads != maxDownloads {
		t.Errorf("final Downloads = %d, want %d (no lost updates, no over-count)", got.Downloads, maxDownloads)
	}
}

// TestHoldBlocksIndividualRevoke documents that RevokeLink itself is
// the low-level unguarded primitive (hold enforcement lives in
// internal/core/link.Engine.Revoke, tested there); this test only
// pins the sqlite-level guarantee that SetHold persists correctly and
// that RevokeLinksByMessage's hold-skipping behavior (exercised in the
// contract suite) is visible via GetLinkByTokenHash.
func TestSetHoldPersistsMetadata(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	if err := st.CreateMessage(ctx, store.NewMessageParams{ID: "m-hold", QueueID: "q-hold", Sender: "a@example.com"}); err != nil {
		t.Fatalf("CreateMessage() error = %v, want nil", err)
	}
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID: "att-hold", MessageID: "m-hold", PartRef: "1", Filename: "f.bin",
		DeclaredType: "application/octet-stream", DetectedType: "application/octet-stream",
		Size: 10, StorageKey: "ab/hold",
	}); err != nil {
		t.Fatalf("CreateAttachment() error = %v, want nil", err)
	}

	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID: "link-hold-meta", MessageID: "m-hold", AttachmentID: "att-hold",
		Recipient: "r@example.com", TokenHash: "hash-hold-meta", ExpiresAt: expiresAt,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	setAt := time.Now().UTC().Format(time.RFC3339Nano)
	if err := st.SetHold(ctx, "link-hold-meta", true, "officer@example.com", setAt); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	got, err := st.GetLinkByTokenHash(ctx, "hash-hold-meta")
	if err != nil {
		t.Fatalf("GetLinkByTokenHash() error = %v, want nil", err)
	}
	if !got.Hold {
		t.Fatalf("Hold = false, want true")
	}
	if got.HoldSetBy != "officer@example.com" {
		t.Errorf("HoldSetBy = %q, want %q", got.HoldSetBy, "officer@example.com")
	}
	if got.HoldSetAt.IsZero() {
		t.Errorf("HoldSetAt is zero, want the time SetHold was called")
	}
}
