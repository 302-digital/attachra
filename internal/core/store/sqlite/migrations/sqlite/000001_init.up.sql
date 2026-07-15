-- Initial metadata schema (ATR-182, ADR-011).
--
-- Dialect-neutral notes for future Postgres port (docs/architecture/
-- adr-011-metadata-db.md "What we lock into MVP code"):
--   * Primary keys are TEXT (UUID-shaped identifiers generated in Go via
--     crypto/rand), not AUTOINCREMENT/BIGSERIAL, so no dialect-specific
--     identity syntax is needed.
--   * Timestamps are stored as TEXT in strict UTC ISO-8601
--     ("2026-07-06T12:34:56.789Z"), never SQLite's non-standard
--     datetime() helpers, so the same column type and values are valid
--     Postgres TEXT (or later, TIMESTAMPTZ via a cast) without rewrite.
--   * Booleans are stored as INTEGER 0/1 (SQLite has no BOOLEAN type;
--     Postgres accepts INTEGER too, and the Go layer maps bool<->int).
--   * No AUTOINCREMENT, no SQLite-only pragmas or functions in DDL.
--   * Foreign keys are declared; enforcement is turned on at the
--     connection level (PRAGMA foreign_keys=ON), not in DDL, since that
--     pragma has no Postgres equivalent (Postgres always enforces FKs).

CREATE TABLE messages (
    id         TEXT PRIMARY KEY,
    queue_id   TEXT NOT NULL,
    sender     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_messages_queue_id ON messages (queue_id);

CREATE TABLE attachments (
    id             TEXT PRIMARY KEY,
    message_id     TEXT NOT NULL REFERENCES messages (id),
    part_ref       TEXT NOT NULL,
    filename       TEXT NOT NULL,
    declared_type  TEXT NOT NULL,
    detected_type  TEXT NOT NULL,
    size           INTEGER NOT NULL,
    storage_key    TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE INDEX idx_attachments_message_id ON attachments (message_id);

-- link: the per-(message, attachment, recipient) grant, per
-- docs/architecture/package-page-decision.md §4.1 item 4. This is the
-- sole granularity for revoke/audit; the "package page" is a read-only
-- projection of these rows filtered by message_id, not a separate
-- aggregate table (package-page-decision.md, rejected option 4).
CREATE TABLE links (
    id             TEXT PRIMARY KEY,
    message_id     TEXT NOT NULL REFERENCES messages (id),
    attachment_id  TEXT NOT NULL REFERENCES attachments (id),
    recipient      TEXT NOT NULL,
    token_hash     TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    max_downloads  INTEGER NOT NULL,
    downloads      INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL,
    hold           INTEGER NOT NULL DEFAULT 0,
    hold_set_by    TEXT,
    hold_set_at    TEXT,
    created_at     TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_links_token_hash ON links (token_hash);
CREATE INDEX idx_links_message_id ON links (message_id);

-- message_link: the thin per-message token backing the package page
-- (docs/architecture/package-page-decision.md §4.1 item 4, "message_link
-- ... a thin new record, not a package-as-file-aggregate"). It carries
-- only the token identifying the message-level landing page; the file
-- list itself is derived by selecting links WHERE message_id = ?.
CREATE TABLE message_links (
    token_hash TEXT PRIMARY KEY,
    message_id TEXT NOT NULL REFERENCES messages (id),
    recipient  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_message_links_message_id ON message_links (message_id);
