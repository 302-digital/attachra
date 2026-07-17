-- Normalize every existing envelope address on disk to the same
-- canonical form internal/core/mail.NormalizeAddress now enforces at
-- milter ingest (ATR-293, closing the ATR-258 review's N1 finding):
-- surrounding whitespace trimmed, one enclosing pair of SMTP
-- reverse/forward-path angle brackets stripped, entire address
-- lower-cased. Before this migration, messages.sender/links.recipient/
-- message_links.recipient held exactly what the raw MAIL FROM/RCPT TO
-- command (or an MTA macro not guaranteed bracket-free) delivered, so
-- `attachra link revoke --sender john@corp.com` could silently miss a
-- message recorded as `John@Corp.com` or `<john@corp.com>` — the
-- attachment stayed downloadable after an operator believed access was
-- revoked. See internal/core/store/sqlite/store.go's
-- ListMessagesBySender doc comment for why the read side stays a plain
-- indexed equality (idx_messages_sender) rather than a functional
-- comparison: this migration is what makes that safe.
--
-- TRIM(X, '<>') is SQLite's two-argument form: it strips every leading
-- and trailing '<'/'>' character from X (not only a single matching
-- pair, unlike mail.NormalizeAddress's stricter check) — a difference
-- that only matters for already-malformed input no real MTA produces
-- for an envelope address, so it is an acceptable approximation for a
-- one-time data cleanup. The single-argument TRIM(X) that runs first
-- only strips ASCII space (0x20), which is all a milter-delivered
-- address is ever padded with in practice.
--
-- Idempotent by construction: LOWER()/TRIM() applied to an already-
-- canonical value returns that same value, so re-running this
-- statement (e.g. a manual re-apply, or golang-migrate replaying it
-- against a Postgres port later, ADR-011) changes nothing further.
--
-- The outer TRIM strips whitespace that the bracket TRIM may expose
-- (legacy '< user@host >' forms), matching mail.NormalizeAddress; a
-- value that survives with interior spaces would otherwise never be
-- found by normalized queries (review minor on MR !65).
UPDATE messages
SET sender = LOWER(TRIM(TRIM(TRIM(sender), '<>')));

UPDATE links
SET recipient = LOWER(TRIM(TRIM(TRIM(recipient), '<>')));

UPDATE message_links
SET recipient = LOWER(TRIM(TRIM(TRIM(recipient), '<>')));
