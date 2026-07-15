-- Attachment storage retention (ATR-178, US-5.3, SR-123-1).
--
-- retain_until is TEXT in the same strict UTC RFC3339Nano form as every
-- other timestamp column in this schema (000001_init.up.sql's dialect-
-- neutral discipline). An empty string ('') is the legacy sentinel for
-- "no retention recorded", used exclusively by attachment rows created
-- before this column existed: every attachment created via
-- internal/core/link.Engine.CreateLinks from this point on always sets
-- a real retain_until value (the matched policy's `then.retention` or
-- the configured global default), never leaving it empty. The empty
-- sentinel is deliberately excluded from retention cleanup rather than
-- treated as "already expired" (see the sqlite driver's
-- ListExpiredAttachments/CountHeldExpiredAttachments queries below).
ALTER TABLE attachments ADD COLUMN retain_until TEXT NOT NULL DEFAULT '';

-- Supports ListExpiredAttachments/CountHeldExpiredAttachments (T-5.3.2,
-- ATR-179): both scan attachments by a retain_until range, so this
-- index keeps a periodic sweep from taking a time proportional to the
-- total number of attachments ever stored.
CREATE INDEX idx_attachments_retain_until ON attachments (retain_until);
