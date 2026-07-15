-- API tokens (ATR-201, US-8.1/T-8.1.7, SR-130-2).
--
-- token_hash holds the hex-encoded SHA-256 of the bearer secret; the
-- raw secret is never stored (CLAUDE.md invariant #5), mirroring the
-- links.token_hash discipline from 000001_init.up.sql. The UNIQUE index
-- on token_hash makes the authentication lookup a single indexed
-- equality (no linear scan, no timing side-channel from the query
-- itself) and enforces that two tokens can never collide on the same
-- secret hash.
--
-- revoked_at is NULL while the token is active; setting it revokes the
-- token immediately (SR-130-2). last_used_at is NULL until the token
-- first authenticates a request; it is a best-effort observability
-- column, updated (throttled) by the auth middleware.
--
-- Every timestamp column follows the same dialect-neutral discipline as
-- 000001_init.up.sql: TEXT in strict UTC RFC3339Nano, sortable and
-- comparable lexicographically, valid as-is on a future Postgres port.
CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    role         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);

CREATE UNIQUE INDEX idx_api_tokens_token_hash ON api_tokens (token_hash);

-- Supports the (created_at, id) keyset pagination ListAPITokens uses so
-- a page fetch is an index range scan rather than a full-table sort.
CREATE INDEX idx_api_tokens_created_at_id ON api_tokens (created_at, id);
