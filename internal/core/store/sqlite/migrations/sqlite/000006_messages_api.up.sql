-- Message-level policy status + list-pagination indices (ATR-198,
-- US-8.1/T-8.1.4, api/openapi.yaml `GET /messages` status filter
-- implementation note).
--
-- status mirrors policy.MessageDecision.Action (pass/replace/block).
-- Every existing row in this table was written exclusively via
-- internal/core/link.Engine.CreateLinks, which pipeline.AttachmentProcessor
-- only ever calls once its policy decision has already resolved to
-- "replace" (see hasReplace's guard in
-- internal/core/pipeline/processor.go): a "pass" message is delivered
-- untouched with no messages row at all, and a "block" message is
-- rejected before one is ever created. Every pre-existing row is
-- therefore unambiguously a "replace" decision, so the backfill below
-- is exact, not a best-effort guess — mirroring the empty-string legacy
-- sentinel convention 000004_attachments_retention.up.sql established
-- for retain_until, the DEFAULT '' only ever applies to a row inserted
-- by a caller that does not supply a status (predates this column, or
-- a direct test fixture), never to production traffic from this point
-- on: internal/core/link.Engine.CreateLinks always sets a real value.
ALTER TABLE messages ADD COLUMN status TEXT NOT NULL DEFAULT '';
UPDATE messages SET status = 'replace';

-- Supports GET /messages' status filter as a plain indexed equality.
CREATE INDEX idx_messages_status ON messages (status);

-- Supports ListMessages'/ListAttachments' (created_at, id) keyset
-- pagination (US-8.1/T-8.1.4) as an index range scan rather than a
-- full-table sort, matching the idx_api_tokens_created_at_id precedent
-- (000005_api_tokens.up.sql).
CREATE INDEX idx_messages_created_at_id ON messages (created_at, id);
CREATE INDEX idx_attachments_created_at_id ON attachments (created_at, id);
