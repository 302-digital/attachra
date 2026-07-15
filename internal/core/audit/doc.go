// Package audit contains the domain logic for recording policy
// decisions, storage/link lifecycle events, downloads, revokes and
// errors for compliance and traceability (US-7.1, ATR-128). It must
// not depend on any adapter-specific code (e.g. Postfix milter) — see
// ADR-002.
//
// The log is append-only (SR-128-1): AuditSink exposes only Record,
// never update or delete. Every Recorded event carries a Seq and
// PrevHash, the hook this package lays down for future tamper-evidence
// verification: an implementation computes PrevHash as a hash of the
// previous row's content at write time (see
// internal/core/store/sqlite's AuditSink implementation), so a later
// verifier can walk the chain and detect any row that was altered or
// removed after the fact. Actually *verifying* the chain end-to-end
// (a `attachractl audit verify` style command, or an on-read check) is
// intentionally out of scope for ATR-189/190/191: only the structural
// hook (Seq + PrevHash present and consistent at write time) is
// delivered here. This is a deliberate, documented scope cut, not an
// oversight — see this task's final report for the rationale.
//
// Untrusted, mail-derived values (recipient addresses, filenames,
// error text) must always cross this package's boundary as
// Event.Recipient (a plain parameterized field) or inside
// Event.Details (a JSON object), never concatenated into a string
// anywhere on the write path (SR-128-2).
package audit
