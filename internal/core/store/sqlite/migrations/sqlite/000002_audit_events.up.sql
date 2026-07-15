-- Audit event log (ATR-189, US-7.1, ADR-011).
--
-- Dialect-neutral notes, same discipline as 000001_init (docs/architecture/
-- adr-011-metadata-db.md "What we lock into MVP code"):
--   * id is TEXT (a crypto/rand-generated identifier from Go), not an
--     autoincrement primary key, so no dialect-specific identity syntax
--     is needed.
--   * created_at is TEXT in strict UTC ISO-8601, matching every other
--     timestamp column in this schema.
--   * seq is a plain INTEGER, assigned by the application (not
--     AUTOINCREMENT) so the exact same assignment logic runs unchanged
--     against a future Postgres backend.
--   * details is a TEXT column holding a JSON-encoded object: untrusted,
--     event-specific fields (filenames, error text, IPs) are always
--     carried here as data, never concatenated into any other column
--     or into this DDL (SR-128-2).
--
-- Tamper-evidence hook (SR-128-1): seq is the monotonic append order and
-- prev_hash is the hash of the previous row's content, computed by the
-- application at write time (internal/core/store/sqlite's AuditSink
-- implementation). This table intentionally exposes no UPDATE/DELETE
-- path in the Go API (store.AuditSink has only Record) — full hash-chain
-- verification is a deliberate follow-up, not implemented by this
-- migration or its Go caller (see internal/core/audit's package doc
-- comment).
CREATE TABLE audit_events (
    id         TEXT PRIMARY KEY,
    seq        INTEGER NOT NULL,
    prev_hash  TEXT NOT NULL,
    type       TEXT NOT NULL,
    actor      TEXT NOT NULL,
    message_id TEXT NOT NULL,
    recipient  TEXT NOT NULL,
    details    TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_audit_events_seq ON audit_events (seq);
CREATE INDEX idx_audit_events_message_id ON audit_events (message_id);
CREATE INDEX idx_audit_events_type ON audit_events (type);
CREATE INDEX idx_audit_events_created_at ON audit_events (created_at);
