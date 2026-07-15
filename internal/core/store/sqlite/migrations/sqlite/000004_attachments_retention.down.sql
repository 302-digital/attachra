DROP INDEX IF EXISTS idx_attachments_retain_until;
ALTER TABLE attachments DROP COLUMN retain_until;
