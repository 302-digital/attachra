// Package store defines the domain interface for Attachra's metadata
// database (messages, attachments, links, message-links) and the
// portable types it operates on (see docs/architecture/adr-011-metadata-db.md).
// It must not depend on any driver-specific package (database/sql
// driver, modernc.org/sqlite, a future Postgres driver) or any
// adapter-specific code (e.g. Postfix milter) — see ADR-002.
//
// Concrete implementations live under internal/core/store/<driver>
// (e.g. sqlite) and are selected at startup by configuration
// (internal/config, database.driver). MVP ships the sqlite
// implementation only; a postgres implementation is v0.2 (ADR-011).
package store
