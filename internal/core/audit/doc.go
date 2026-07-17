// Package audit contains the domain logic for recording policy
// decisions, storage/link lifecycle events, downloads, revokes and
// errors for compliance and traceability (US-7.1, ATR-128). It must
// not depend on any adapter-specific code (e.g. Postfix milter) — see
// ADR-002.
//
// The log is append-only for event producers (SR-128-1): AuditSink
// exposes only Record, never update or delete. The one controlled
// exception is retention truncation (ADR-017), exposed through the
// separate Truncator interface — not AuditSink — so producers cannot
// reach it: it removes an old, contiguous, hold-respecting seq-prefix
// and appends a TypeRetentionCheckpoint anchoring the survivors, so the
// removal is itself tamper-evident. It is opt-in and off by default
// (see internal/core/retention and ADR-017 for the mechanism). Every
// Recorded event carries a Seq and PrevHash: the store computes PrevHash
// as HashRecord of the previous row at write time (see
// internal/core/store/sqlite's AuditSink implementation and HashRecord in
// this package), so the chain can be walked and any altered, removed, or
// reordered row detected. HashRecord is the single canonical row hash,
// used both at write time and by the verifier. Verify and VerifyJSONL
// (ATR-240) implement that walk: Verify checks the live log through a
// Reader, VerifyJSONL an offline segment previously written by
// ExportJSONL. Both are strictly read-only — verifying records nothing
// (an appended event would perturb the very chain it checks). A clean
// verdict covers the surviving chain from its earliest trusted anchor
// forward; it does not prove a truncation anchor's own legitimacy
// (ADR-017 "Limitations: what verification does not prove").
//
// Untrusted, mail-derived values (recipient addresses, filenames,
// error text) must always cross this package's boundary as
// Event.Recipient (a plain parameterized field) or inside
// Event.Details (a JSON object), never concatenated into a string
// anywhere on the write path (SR-128-2).
package audit
