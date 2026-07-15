// Package sqlite implements store.MetadataStore on top of
// modernc.org/sqlite, a pure-Go SQLite driver (ADR-011): no CGO is
// required, preserving the single static cross-compiled binary
// invariant (ADR-001).
//
// Package sqlite is an adapter: it may import database/sql-adjacent
// driver packages freely, but internal/core code must depend only on
// the store.MetadataStore interface, never on this package directly,
// except at the composition root (cmd/attachra) where the concrete
// driver is selected by configuration (ADR-002).
package sqlite
