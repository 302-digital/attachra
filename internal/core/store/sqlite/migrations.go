package sqlite

import (
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migsqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// migrationsFS embeds the versioned SQLite migration set
// (docs/architecture/adr-011-metadata-db.md item 3: "golang-migrate
// with a versioned migration set from commit #1"). The directory
// structure keeps a per-dialect sibling (migrations/postgres/) able to
// be added in v0.2 without reworking the runner.
//
//go:embed migrations/sqlite/*.sql
var migrationsFS embed.FS

// migrate runs every pending "up" migration against db, using the
// embedded SQLite migration set. It is idempotent: running it against
// an already-up-to-date database is a no-op.
func runMigrations(db *sqlDB) error {
	sourceDriver, err := iofs.New(migrationsFS, "migrations/sqlite")
	if err != nil {
		return fmt.Errorf("sqlite: load embedded migrations: %w", err)
	}

	dbDriver, err := migsqlite.WithInstance(db.writer, &migsqlite.Config{})
	if err != nil {
		return fmt.Errorf("sqlite: create migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "sqlite", dbDriver)
	if err != nil {
		return fmt.Errorf("sqlite: init migrator: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("sqlite: run migrations: %w", err)
	}

	return nil
}
