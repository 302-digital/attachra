-- Index supporting ListMessagesBySender (ATR-258, US-6.3
-- revoke-by-sender): an exact-match lookup on messages.sender must not
-- take a time proportional to the number of stored messages, matching
-- the existing idx_messages_queue_id precedent (000001_init.up.sql).
CREATE INDEX idx_messages_sender ON messages (sender);
