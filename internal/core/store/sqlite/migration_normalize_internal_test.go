package sqlite

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	migsqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// newVersionedMigrator returns a golang-migrate instance against a
// fresh SQLite file at path, letting a test step through individual
// schema versions with Migrate(uint) — the public Open() always
// migrates straight to the latest version, which cannot exercise
// migration 000007 against deliberately pre-normalization data the
// way TestMigration000007NormalizesExistingAddresses needs to.
func newVersionedMigrator(t *testing.T, path string) (*migrate.Migrate, *sql.DB) {
	t.Helper()

	db, err := openSQLDB(path)
	if err != nil {
		t.Fatalf("openSQLDB(%q) error = %v, want nil", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })

	sourceDriver, err := iofs.New(migrationsFS, "migrations/sqlite")
	if err != nil {
		t.Fatalf("load embedded migrations: %v", err)
	}
	dbDriver, err := migsqlite.WithInstance(db.writer, &migsqlite.Config{})
	if err != nil {
		t.Fatalf("create migration driver: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "sqlite", dbDriver)
	if err != nil {
		t.Fatalf("init migrator: %v", err)
	}
	return m, db.writer
}

// TestMigration000007NormalizesExistingAddresses is the regression for
// ATR-293 (closing the ATR-258 review's N1 finding): a message written
// by a pre-fix milter adapter could have its sender stored exactly as
// the sending MTA delivered it — mixed case, SMTP angle brackets, or
// both — so a case/bracket-mismatched `attachra link revoke --sender`
// silently found nothing. This test seeds rows in that exact shape at
// schema version 6 (before migration 000007 exists) and asserts they
// come out in mail.NormalizeAddress's canonical form once version 7
// has run, across every table that stores a sender/recipient address.
func TestMigration000007NormalizesExistingAddresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attachra-normalize-migrate-test.db")
	m, writer := newVersionedMigrator(t, path)

	if err := m.Migrate(6); err != nil {
		t.Fatalf("migrate to version 6: %v", err)
	}

	if _, err := writer.Exec(
		`INSERT INTO messages (id, queue_id, sender, status, created_at) VALUES (?, ?, ?, ?, ?)`,
		"msg-legacy", "q-legacy", "<Alice@EXAMPLE.com>", "replace", "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("insert legacy message: %v", err)
	}
	if _, err := writer.Exec(
		`INSERT INTO attachments (id, message_id, part_ref, filename, declared_type, detected_type, size, storage_key, retain_until, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"att-legacy", "msg-legacy", "1", "f.pdf", "application/pdf", "application/pdf", 10, "key-legacy", "", "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("insert legacy attachment: %v", err)
	}
	if _, err := writer.Exec(
		`INSERT INTO links (id, message_id, attachment_id, recipient, token_hash, expires_at, max_downloads, downloads, status, hold, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 0, ?)`,
		"link-legacy", "msg-legacy", "att-legacy", " <Bob@EXAMPLE.com> ", "hash-legacy", "2027-01-01T00:00:00Z", 0, "active", "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("insert legacy link: %v", err)
	}
	if _, err := writer.Exec(
		`INSERT INTO message_links (token_hash, message_id, recipient, expires_at, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"msglink-hash-legacy", "msg-legacy", "<Bob@EXAMPLE.com>", "2027-01-01T00:00:00Z", "active", "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("insert legacy message_link: %v", err)
	}

	if err := m.Migrate(7); err != nil {
		t.Fatalf("migrate to version 7: %v", err)
	}

	var sender string
	if err := writer.QueryRow(`SELECT sender FROM messages WHERE id = ?`, "msg-legacy").Scan(&sender); err != nil {
		t.Fatalf("query normalized sender: %v", err)
	}
	if sender != "alice@example.com" {
		t.Errorf("messages.sender after migration = %q, want %q", sender, "alice@example.com")
	}

	var linkRecipient string
	if err := writer.QueryRow(`SELECT recipient FROM links WHERE id = ?`, "link-legacy").Scan(&linkRecipient); err != nil {
		t.Fatalf("query normalized link recipient: %v", err)
	}
	if linkRecipient != "bob@example.com" {
		t.Errorf("links.recipient after migration = %q, want %q", linkRecipient, "bob@example.com")
	}

	var msgLinkRecipient string
	if err := writer.QueryRow(`SELECT recipient FROM message_links WHERE token_hash = ?`, "msglink-hash-legacy").Scan(&msgLinkRecipient); err != nil {
		t.Fatalf("query normalized message_link recipient: %v", err)
	}
	if msgLinkRecipient != "bob@example.com" {
		t.Errorf("message_links.recipient after migration = %q, want %q", msgLinkRecipient, "bob@example.com")
	}

	// Confirm ListMessagesBySender — the actual revoke-by-sender lookup
	// path — now finds the legacy row via a clean, bracket-free,
	// lower-case query, per this ticket's acceptance criteria.
	st := &Store{db: &sqlDB{writer: writer, reader: writer}}
	got, err := st.ListMessagesBySender(t.Context(), "alice@example.com")
	if err != nil {
		t.Fatalf("ListMessagesBySender() error = %v, want nil", err)
	}
	if len(got) != 1 || got[0].ID != "msg-legacy" {
		t.Fatalf("ListMessagesBySender(\"alice@example.com\") = %+v, want exactly [msg-legacy]", got)
	}

	// Migrations are meant to be safely re-appliable (golang-migrate
	// itself no-ops a repeat Migrate() call to an already-applied
	// version); the up.sql's own idempotency for a second genuine
	// execution is covered by mail.NormalizeAddress's own
	// TestNormalizeAddressIdempotent, which this SQL mirrors.
	if err := m.Migrate(7); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("re-migrate to version 7: %v, want nil or ErrNoChange", err)
	}
}
