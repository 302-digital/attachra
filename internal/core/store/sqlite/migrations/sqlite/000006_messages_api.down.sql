DROP INDEX IF EXISTS idx_attachments_created_at_id;
DROP INDEX IF EXISTS idx_messages_created_at_id;
DROP INDEX IF EXISTS idx_messages_status;
ALTER TABLE messages DROP COLUMN status;
