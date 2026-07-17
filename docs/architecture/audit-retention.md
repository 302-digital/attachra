# Audit log retention: checkpoint/anchor truncation

Status: implements ADR-017. Read that ADR first for the decision and
rationale; this document is the concrete mechanism and the invariants a
reviewer (and `attachra audit verify`) can check against.

## Problem

`audit_events` is append-only with a per-row hash chain (SR-128-1): row
`seq` stores `prev_hash` = hash of row `seq-1`. The milter sees the whole
mail flow, so the table grows forever (pilot: 2 events per inbound
message). A naive `DELETE` severs the chain and destroys tamper-evidence
for every surviving row. We need bounded growth **without** losing
provable integrity of what remains.

## Mechanism

To truncate the contiguous prefix up to and including `seq N`:

```
BEGIN (single writer tx, ADR-011)
  N        := boundary(cutoff)                 -- see "Boundary" below
  N        := clampByHold(N)                   -- see "Legal hold" below
  if nothing at seq <= N -> COMMIT no-op, Truncated=false, no checkpoint
  H_N      := chainHash(row at seq N)          -- recomputed anchor hash
  append retention_checkpoint {                -- normal chained tail row
      anchor_seq      = N,
      anchor_hash     = H_N,
      truncated_count = <rows about to be deleted>,
      cutoff          = <RFC3339 cutoff>,
      held_clamped    = <bool>,
  }
  DELETE FROM audit_events WHERE seq <= N
COMMIT
```

The checkpoint is appended **before** the delete and lands at the current
tail (`seq = maxSeq+1 > N`), so the delete never touches it. Its
`prev_hash` is the hash of the pre-existing tail row, unaffected by the
delete.

### Why the survivors stay verifiable

The first surviving data row is `seq N+1`. It was written with
`prev_hash = H_N` (hash of row `N`). After the delete, row `N` is gone,
but the checkpoint's `anchor_hash = H_N` re-supplies exactly that value
as a trusted, self-recorded anchor. A verifier resumes the chain from the
anchor. See ADR-017 "Verification recipe".

A segment exported **before** truncation (existing streaming
`ExportJSONL`) is a full prefix from genesis, so it verifies standalone;
its last row's hash equals the checkpoint `anchor_hash`, bridging archive
to live tail.

**Degenerate case: nothing survives but the checkpoint itself.** When the
whole table is older than the cutoff, the checkpoint — appended at
`seq = old_max_seq + 1`, past the boundary — is the *only* row left after
the delete. Its `prev_hash` and its own `Details.anchor_hash` are the
same value (the hash of the last row it just deleted), so it is
self-anchoring: a future verifier must recognize this shape (a single
live row, `Type == retention_checkpoint`, `prev_hash == anchor_hash`) and
treat it as an established, trusted starting point — not as "chain not
found" or an error — without expecting `anchor_seq` to name a still-live
row (it never will; that row was just deleted). See ADR-017
"Verification recipe" for the full statement of this and every other
case a verifier must handle.

### Boundary (time-safe, contiguous)

`seq` is insertion order; `created_at` is caller-suppliable. The boundary
is defined so we never delete a row newer than the cutoff, regardless of
any seq/time skew:

```
firstRecent := MIN(seq) WHERE created_at >= cutoff
N           := firstRecent - 1        (or MAX(seq) if no recent rows)
```

Every row with `seq <= N` is therefore strictly older than the cutoff.
In production, callers pass a zero `Timestamp` and `Record` stamps
`time.Now()`, so seq order equals time order and `N` is just "max old
seq"; the definition above only matters for tests that inject explicit
past timestamps.

### Legal hold (clamp, do not fragment)

Held-related event = an `audit_events` row whose `message_id` belongs to
a message that has at least one link with `hold = 1`. These
must never be truncated. Instead of skipping them individually (which
would leave holes and void the single-anchor model), the boundary is
clamped:

```
oldestHeld := MIN(seq) WHERE seq <= N AND message_id IN
                  (SELECT message_id FROM links WHERE hold = 1)
if oldestHeld exists: N := oldestHeld - 1 ; held_clamped := true
```

Consequence: one held message pins all older audit history until the hold
is lifted; a later sweep then truncates further. The clamp runs inside
the same writer transaction as the delete, so a concurrently-set hold is
honored (single-writer serialization).

**Fully-clamped pass is logged, not silent.** When the clamp removes
every eligible row (`HeldClamped == true && Truncated == false`), the
sweep logs a `Warn` rather than passing through silently — otherwise an
operator who enabled `audit_retention_seconds` sees no growth relief and
no signal why. This is also a documented footgun for an **authorized
insider with hold-setting privileges**: setting (and never lifting) a
hold on one old, low-value message is a way to indefinitely defeat audit
truncation for the whole prefix behind it, without needing any DB-level
access — see ADR-017 "Limitations" for the broader tamper-masking
discussion this sits alongside.

## Limitations: what verification does not prove

This mechanism proves the surviving chain has not changed **since the
anchor**; it does not prove the anchor itself is legitimate. An attacker
(or an authorized insider) with direct write access to the SQLite file —
outside `TruncateAudit`'s transaction — can fabricate a
`retention_checkpoint` whose `anchor_hash` is the *genuine* recomputed
hash of any row they pick, then delete everything up to it: the result
is indistinguishable from a real truncation, and `Actor`/`cutoff`/
`truncated_count` on the checkpoint are self-attested, not independently
verified. Closing this requires an external reference predating the
alleged truncation (an offsite/WORM export, or a future
operator-signed anchor) — neither is in scope for this design. Full
discussion: ADR-017 "Limitations: what verification does not prove" and
`docs/security/threat-model.md` T2.10.

## Operational recommendation

Set `audit_retention_seconds` **noticeably larger than your export
cadence**, and take an offsite/WORM export (`GET /audit/export`, or
`attachractl audit export`) before the *first* time truncation actually
removes anything — the export is the only artifact that survives a
forged-anchor scenario (see "Limitations" above) and the only durable
record of history once old `retention_checkpoint` rows are themselves
eventually truncated by a later pass (ADR-017 Consequences). A retention
window shorter than or close to the export interval risks truncating
data that was never captured externally.

## Seq-cursor safety

API clients page by an opaque seq cursor (`GET /api/v1/audit`). After
truncation, a cursor positioned before the new minimum surviving seq
would silently skip removed rows. `ListEvents` guards this — and, when a
cursor is present, runs the guard and the paged fetch inside **one
read-only transaction**, not two independent statements:

```
if cursor present:
    afterSeq := decode(cursor)
    BEGIN read-only tx (single reader-pool connection, fixes the WAL snapshot)
      minSeq := MIN(seq)                 -- current minimum surviving seq, same snapshot
      if minSeq valid and afterSeq + 1 < minSeq:
          ROLLBACK; return ErrCursorTruncated   -- HTTP 410 Gone
      rows := SELECT ... WHERE seq > afterSeq ORDER BY seq LIMIT n+1   -- same snapshot
    ROLLBACK (read-only; nothing to commit)
else:
    rows := SELECT ... ORDER BY seq LIMIT n+1   -- plain reader pool, no cursor to guard
```

**Why a transaction, not two plain queries (security review, B2).** `internal/core/store/sqlite`'s reader pool is intentionally a
wide, multi-connection pool (readers don't block the writer, ADR-011).
Two independent `QueryContext` calls against that pool can land on
*different* connections and therefore straddle a commit: if a retention
truncation lands between them, the guard reads the pre-truncation
`minSeq` (passes), and the following `SELECT` — now on a fresher
connection/snapshot — silently starts past the just-removed rows,
exactly the silent-gap failure `ErrCursorTruncated` exists to prevent. A
single read-only transaction fixes the snapshot at its first statement
(standard SQLite WAL semantics: a deferred transaction's view is
established the moment it first reads, and held fixed for every
subsequent read in that same transaction, regardless of what commits
elsewhere afterward), so the guard and the fetch are guaranteed to agree.
This is exercised by an internal-package test that opens the transaction
manually, executes a concurrent write on a separate connection in the
middle, and asserts the open transaction's second read still sees its
original snapshot (`TestListEventsCursorGuardSnapshotIsolation`), plus a
best-effort concurrent stress test driving the real `ListEvents` call
against a running `TruncateAudit` loop
(`TestListEventsCursorNoSilentSkipUnderConcurrentTruncation`) — the
latter was confirmed, by deliberately reintroducing the two-query shape,
to reliably reproduce the silent-skip symptom against the broken code and
pass cleanly against the fix.

`afterSeq + 1 == minSeq` (cursor exactly at the anchor) resumes cleanly;
`afterSeq >= minSeq` is unaffected. With retention disabled `minSeq == 1`
and the guard never fires, so existing clients see no behavior change.
The no-cursor path (first page) never opens a transaction — there is
nothing to guard against, so it keeps using the plain reader pool.

`StreamEvents` / `ExportJSONL` have no cursor and simply export the
current live state; the `retention_checkpoint` rows in the stream
document any truncation that happened.

## Scheduling

Truncation runs inside the existing US-5.3 retention Sweeper pass, gated
by `retention.audit_retention_seconds` (default `0` = disabled, opt-in)
and requiring `retention.enabled = true`. The Sweeper computes
`cutoff = now - audit_retention_seconds` and calls
`audit.Truncator.TruncateAudit`. Disabled (the default) means the log
stays append-only forever — byte-for-byte current behavior.

## Module boundaries (ADR-002)

- `internal/core/audit`: `Truncator` interface, `TypeRetentionCheckpoint`,
  checkpoint detail keys, `ErrCursorTruncated`. Contract only, no SQL.
- `internal/core/store/sqlite`: `TruncateAudit` implementation, the
  boundary/hold/anchor SQL, the `ListEvents` cursor guard.
- `internal/core/retention`: schedules the call within `Sweep`.
- `internal/adapters/http`: maps `ErrCursorTruncated` to `410 Gone`.

`AuditSink` (the event-producer interface) is unchanged and stays
append-only; truncation is a distinct, separately named capability so a
mail-path/API producer can never reach a delete.
