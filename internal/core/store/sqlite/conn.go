package sqlite

import (
	"database/sql"
	"fmt"
	"net/url"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver.
)

// pragmas configures every connection per
// docs/architecture/adr-011-metadata-db.md ("Required SQLite
// configuration (enforced at open time)"):
//   - journal_mode=WAL: readers do not block the writer.
//   - busy_timeout: a transient SQLITE_BUSY waits-and-retries instead
//     of failing immediately.
//   - foreign_keys=ON: enforce the message -> attachment -> link graph.
//   - synchronous=NORMAL: safe with WAL, good durability/throughput
//     balance.
const pragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"

// sqlDB bundles the two connection pools ADR-011 requires: a single,
// serialized writer connection and a separate, wider read pool. Every
// exported method on Store routes writes through writer and reads
// through reader, so the concurrency model matches the ADR
// ("Route all writes through a single serialized writer path").
type sqlDB struct {
	writer *sql.DB
	reader *sql.DB
}

// openSQLDB opens the writer and reader pools against the SQLite file
// at path, applying the required pragmas to both.
func openSQLDB(path string) (*sqlDB, error) {
	dsn := fmt.Sprintf("file:%s?%s", url.PathEscape(path), pragmas)

	writer, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open writer pool: %w", err)
	}
	// A single writer connection is the mechanism ADR-011 mandates to
	// avoid self-inflicted SQLITE_BUSY from concurrent writes issued
	// by this process itself; SQLite's own single-writer semantics
	// already serialize writes across processes, but capping our pool
	// to 1 conn means Go's database/sql never even attempts a second
	// concurrent write from within this binary.
	writer.SetMaxOpenConns(1)

	reader, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("sqlite: open reader pool: %w", err)
	}
	// Readers do not block the writer in WAL mode, so the read pool
	// can be reasonably wide; database/sql's default MaxOpenConns (0,
	// unlimited) is fine here.

	return &sqlDB{writer: writer, reader: reader}, nil
}

// Close closes both pools. It returns the first error encountered, if
// any, but always attempts to close both.
func (d *sqlDB) Close() error {
	errWriter := d.writer.Close()
	errReader := d.reader.Close()
	if errWriter != nil {
		return fmt.Errorf("sqlite: close writer pool: %w", errWriter)
	}
	if errReader != nil {
		return fmt.Errorf("sqlite: close reader pool: %w", errReader)
	}
	return nil
}
