# Attachra --- Architecture Decision Record (ADR)

## ADR-001: Language

Decision: - Backend implemented in Go.

Reason: - Excellent networking libraries. - Single static binary. -
Strong concurrency. - Easy cross-platform builds.

Clarification (2026-07-09, US-9.1 review): "single static binary" is a
per-artifact property (every shipped binary is statically linked,
CGO-free, cross-compiled for linux/amd64+arm64), not a project-wide
"exactly one binary" mandate. The server `attachra` remains one static
binary; the `attachractl` admin CLI (E9) is a second, equally static
artifact that talks to the server only over the REST API.

------------------------------------------------------------------------

## ADR-002: Core and Adapter Separation

Decision: Core must not depend on Postfix.

Adapters communicate with the Core.

Reason: Allows future support for SMTP Proxy, Exchange, Stalwart, Exim
and others.

------------------------------------------------------------------------

## ADR-003: Plugin Architecture

Decision: Commercial and community features are delivered as plugins.

Reason: Avoid separate Community and Enterprise builds.

Preferred runtime: WebAssembly (WASI).

------------------------------------------------------------------------

## ADR-004: Open Core

Decision: Community edition remains production-ready.

Enterprise value is delivered through additional capabilities, not
artificial limitations.

------------------------------------------------------------------------

## ADR-005: Marketplace

Marketplace distributes:

-   Plugins
-   Policy Packs
-   Integrations
-   Storage Drivers
-   Themes

Categories:

-   Official
-   Verified
-   Community

------------------------------------------------------------------------

## ADR-006: Policy Engine

Policies are declarative.

Business users should understand and modify rules without programming.

Policy Packs provide reusable compliance templates.

------------------------------------------------------------------------

## ADR-007: Storage

Use S3-compatible object storage as the primary backend.

Support:

-   AWS S3
-   MinIO
-   Ceph
-   Filesystem

Future adapters are plugins.

------------------------------------------------------------------------

## ADR-008: Initial Integration Strategy

MVP:

-   Postfix Milter

Immediate compatibility:

-   grommunio
-   Mailcow
-   iRedMail
-   Modoboa
-   Mail-in-a-Box

Long-term:

-   SMTP Proxy
-   Stalwart
-   Exchange
-   Exim

------------------------------------------------------------------------

## ADR-009: Product Philosophy

Attachra is not an email server.

Attachra is an Attachment Policy Engine.

It governs how files enter, leave and move through enterprise
communication systems.

------------------------------------------------------------------------

## ADR-010: Product Success Metric

Success is achieved when self-hosted mail administrators naturally
recommend:

-   Rspamd for spam
-   ClamAV for antivirus
-   Attachra for attachment management

------------------------------------------------------------------------

## ADR-011: Metadata Database

Status: **Accepted by founder 2026-07-09** (full decision record
in `docs/architecture/adr-011-metadata-db.md`).

Decision:

-   **Embedded SQLite** (`modernc.org/sqlite`, pure Go, WAL mode) is the
    default metadata store for links, audit events, and API tokens —
    zero-ops, keeps the single-static-binary promise (ADR-001).
-   **PostgreSQL** is the opt-in production/HA backend, planned for v0.2
    (planned as a dedicated epic): one new `MetadataStore` implementation, a parallel
    migration directory, a config switch — zero domain-logic changes.
-   MVP code locks in portability: portable SQL, guarded atomic UPDATE
    for download counters, `golang-migrate`, token hashes only (never
    raw tokens) in storage.
-   SQLite is single-node only; horizontal scaling of the download/API
    tiers requires the Postgres backend. Both backends stay in Community
    (infrastructure is never monetized, ADR-015).

------------------------------------------------------------------------

## ADR-012: Licensing Model

Status: **Accepted by founder 2026-07-06, pending legal review before
public release.**

Decision:

-   Core Attachra is licensed under **AGPL-3.0-or-later**.
-   Enterprise plugin packs and the right to keep modifications private
    are offered under a **separate commercial license** (dual-licensing).
-   The plugin SDK and the published plugin ABI are licensed under
    **Apache-2.0** — third-party and proprietary plugins are not subject
    to core copyleft (boundary: WASI sandbox + IPC, per ADR-003).
-   Contributions to the core require a **CLA** including a pledge that
    every contribution remains available under an OSI-approved license
    forever.

Reason: AGPL is the only OSI-approved option that both prevents cloud
strip-mining and preserves the trust of self-hosted mail administrators.
Industry cases 2021--2026 (Elastic, HashiCorp, Redis vs Grafana) show
leaving OSI-open reliably triggers a foundation-backed fork, while AGPL
became the consensus for "protection without betrayal".

Full analysis, trade-off table and action plan (lawyer, trademark,
domains): `docs/business/license-decision.md`,
`docs/business/adr-license-draft.md` (ADR-013 CLA, ADR-014 trademark).

Note: ADR-011 (metadata DB) is drafted separately in
`docs/architecture/adr-011-metadata-db.md` and pending founder ack.
ADR-013 (CLA) and ADR-014 (trademark) are drafted in
`docs/business/adr-license-draft.md`, pending legal review.

------------------------------------------------------------------------

## ADR-015: Community and Enterprise Boundary

Status: **Accepted by founder 2026-07-06.**

Decision:

-   Community edition fully covers the single-admin product forever:
    milter adapter, MIME rewrite, Policy Engine (incl. hot reload,
    dry-run), S3-family + FS storage, per-recipient links, **revoke,
    audit, full admin Web UI, REST API, CLI**, retention, Postgres
    backend and HA topology (infrastructure is never monetized).
-   Enterprise value ships as proprietary WASI plugin packs on top of
    the single AGPL binary: Identity (SSO/LDAP/AD-group policies/fine
    RBAC/multi-tenant), Compliance (certified policy packs, reports),
    Security (SIEM connectors), Cloud (Azure/GCS/Wasabi drivers),
    Notification, AI. v1 priority: Compliance + Identity.
-   Community roles: admin / viewer / auditor (read-only audit).
-   Domains are not counted or limited in Community; tenant isolation
    is Identity Pack.
-   Community policy examples are free and community packs shareable;
    certified compliance packs are paid.
-   Ten public anti-promises (no feature clawbacks, no volume/seat
    limits, no forced telemetry, no crippled builds, no paywalled data,
    no nags) are part of the public commitment.

Details, upgrade triggers and rationale:
`docs/product/open-core-boundary.md`.

------------------------------------------------------------------------

## ADR-016: Inline (CID) Attachment Handling in Policy

Status: **Accepted** (2026-07-13). Refines the policy format
(ADR-006) and §2.3.2 of docs/architecture/policy-format-v1.md.

### Context

The MVP pipeline submits every leaf MIME part to policy evaluation and
replaces any part decided `replace` with a personal link. This ignores
whether a part is a presentation-inline asset — a logo or signature
image referenced from the HTML body via `cid:` (RFC 2387/2392,
multipart/related). Replacing such a part removes the target of its
`<img src="cid:...">`, breaking the message layout for the recipient.
The grommunio pilot (2026-07-13) reproduced this: two nameless inline
parts (6 B, 272 B) were turned into links, corrupting the signature.
Two facts make naive fixes wrong:

-   `Content-Disposition: inline` is unreliable: some MUAs (Apple Mail)
    mark genuine downloadable attachments `inline`. Trusting the header
    alone would let a real attachment escape policy — a policy bypass.
-   A truly-inline asset is reliably marked by BOTH a `Content-ID`
    header AND membership in a `multipart/related` container.

### Decision

1.  Classification (message parser): extract the part's Content-ID and
    track its immediate parent container media type. A part is an
    InlineAsset iff it has a non-empty Content-ID AND its parent is
    multipart/related. Both signals are available during the streaming
    walk with no body buffering (invariant #4 preserved).
2.  Protective default (pipeline): an InlineAsset whose resolved action
    is `replace` is downgraded to `pass` --- UNLESS the winning rule
    explicitly constrained `disposition` (opt-in). The downgrade
    applies only when the part is image/\* by DETECTED type (magic
    bytes) AND its size is within `limits.inline_max_size` (default
    256 KiB). `block` is never downgraded. Opt-in is OR'd across
    envelope recipients (policy.strongerDecision): if any recipient's
    winning rule explicitly opted the part in, the merged decision
    keeps InlineOptIn=true, matching the pipeline's existing
    single-rewrite-per-message trade-off (one MIME body is embedded
    for every recipient, §3.4 of the policy format spec already forces
    one shared outcome per part).
3.  Grammar (policy format v1, §2.3.2): optional
    `when.attachment.disposition: [attachment | inline]` matching the
    EFFECTIVE classification (InlineAsset), not the raw header. Absent
    field matches any part; backward-compatible, no version bump
    (§7.1).
4.  Observability: the downgrade is recorded in the policy_decision
    audit event (detail `inline_protected`) and an attachment-action
    metric label. It is never silent.

### Alternatives considered

-   Disposition header only: rejected --- Apple Mail-style
    inline+filename on real attachments would create a policy bypass.
-   Full cid: reference verification from HTML: deferred to phase 2
    --- requires HTML scanning and out-of-order tolerance; residual
    false-negative of the chosen heuristic is harmless and the bypass
    is closed by the detected-type + size clamp.
-   include_inline flag in ActionParams: rejected --- ActionParams
    holds replace-only link parameters; a matcher fits the §2.3.2
    grammar and also expresses "block oversized inline".
-   Operator-written protect rules: rejected --- a forgotten rule means
    broken mail; the safe default must live in the engine.

### Consequences

-   Behavior change: inline image assets under a broad replace rule
    now pass; documented in CHANGELOG; install base is the pilot only.
-   Residual bypass surface (accepted, see threat-model.md T2.8): a
    small (≤ inline_max_size) genuine image/\* file with Content-ID
    inside multipart/related can avoid link replacement; bounded by
    verified (detected, not declared) type and size; block still
    applies; closable per-policy via an explicit `disposition`
    opt-in rule.
-   New: limits.inline_max_size; Attachment.ContentID/InlineAsset;
    optional AttachmentMatch.Disposition. Module boundaries unchanged
    (ADR-002): classification in core/message, protection in
    core/pipeline, matching in core/policy.
-   Related fix (same protective layer): structural body parts
    (text/plain, text/html) are never REPLACE CANDIDATES --- a
    `default: replace` policy previously destroyed message bodies
    They ARE fully evaluated like any other part (spooled,
    sniffed, matched against every rule including `block`); only a
    `replace` verdict on them is downgraded to `pass`
    (pipeline.protectStructuralBodies). An earlier draft of this fix
    instead excluded these parts from policy.Evaluate entirely before
    protection existed, which silently defeated detected-type/`block`
    enforcement on anything shaped like a message body --- an
    architect/security review (2026-07-14) caught this as a BLOCKER
    and required the evaluate-then-downgrade shape documented here
    (see threat-model.md T2.7).
-   Phase 2 (delivered): verify cid: references from the HTML
    body — see the Implementation note below.

### Implementation note --- phase 2 cid: verification

Phase 2 refines decision 2 (it does NOT change any accepted decision):
an InlineAsset is spared the protective downgrade only if its
`Content-ID` is actually referenced via a `cid:` URL (RFC 2392) from a
`text/html` body of the same `multipart/related` container. An asset
whose `Content-ID` no HTML embeds now replaces normally, closing the
"unreferenced `Content-ID` asset protected for free" residual
(threat-model.md T2.8). The structural signal from decision 1
(`Content-ID` + `multipart/related` parent, `Attachment.InlineAsset`)
is unchanged and remains a necessary precondition; the cid: check is an
additional gate on top of the existing detected-`image/*` + size clamp.

-   **Where.** In the pipeline (`pipeline.protectInlineAssets` →
    `cidReferenced`, `internal/core/pipeline/cid.go`), not the message
    parser. The parser deliberately never buffers part bodies (invariant
    #4); the pipeline already spools every leaf part's decoded content
    for later upload/rewrite, so the text/html bodies are already
    captured and are reused for the scan. No new field on
    `message.Attachment` and no module-boundary change (ADR-002): the
    `multipart/related` container of an InlineAsset is, by decision 1,
    its immediate parent, so the container path is
    `parentPath(asset.PartPath)`, and any text/html part whose
    `PartPath` is a descendant of that path is in the same container
    (covering an HTML nested inside a `multipart/alternative`, the common
    Outlook shape).
-   **Streaming / bound (per part).** The HTML is scanned for `cid:`
    tokens with a lightweight case-insensitive token scan (not a DOM
    parse), bounded to `maxHTMLCIDScanBytes` (1 MiB) per SINGLE part, so
    a single scan call costs O(bound) in memory and CPU — this is a
    per-part bound, not a message-level one; see the aggregate-budget
    bullet below for what bounds the message as a whole. A full DOM
    parse would add cost and a dependency for no benefit — only the set
    of embedded `Content-ID`s matters.
-   **Aggregate budget (message-level; security review, B1).** A
    security review of the first version of this change found the
    per-part bound alone insufficient: a message with many separate
    `text/html` inline parts (each individually within
    `maxHTMLCIDScanBytes` and `message.Limits.MaxParts`/`MaxTotalSize`)
    could still make `pipeline.collectHTMLCIDRefs` retain every part's
    token map simultaneously, aggregating to several GiB of RAM for one
    message-processing call — a mail-path memory-exhaustion DoS,
    violating invariant #4. Two message-wide budgets now cap the total
    across every `text/html` part of one message:
    `maxAggregateHTMLScanBytes` (4 MiB total bytes read) and
    `maxAggregateCIDTokens` (65536 total distinct tokens retained).
    Once either is spent, every remaining `text/html` part is left
    entirely unscanned — not even opened — and marked truncated, so its
    container falls back to the fail-safe path below rather than
    growing memory further; `collectHTMLCIDRefs`'s total work and
    retained memory for one message are both O(one bounded constant),
    independent of how many `text/html` parts the message contains.
-   **Scan gate (security review, B2).** `pipeline.hasInlineCandidate`
    gates the whole scan behind "does this message contain at least one
    part that is both `InlineAsset` and within `inline_max_size`?" —
    the same two checks `protectInlineAssets` itself needs before ever
    consulting the scan result. An ordinary message with no
    Content-ID/`multipart/related` asset at all (the common case) never
    pays for a spool re-read or a `text/html` scan.
-   **Part order.** RFC 2387 only SHOULD (not MUST) place the root/HTML
    part first. The pipeline collects every HTML body's references before
    applying protection, so an image that appears before its referencing
    HTML is handled correctly — no two-pass parse, no ordering
    assumption.
-   **Fail-safe.** When a referencing HTML body cannot be fully scanned —
    a single part larger than `maxHTMLCIDScanBytes`, the message-wide
    aggregate budget already spent by earlier parts, or the body is
    unreadable — verification for that container falls back to phase-1
    protection (treat the asset as referenced) rather than breaking a
    message it cannot verify. This is a documented residual (T2.8), not
    a regression: it is strictly the pre-phase-2 behavior, and an
    attacker who deliberately forces this path (oversized HTML, or
    exhausting the aggregate budget with unrelated parts) gains nothing
    beyond that residual — the fallback still only ever protects a part
    that already satisfies the structural signal + detected-`image/*` +
    size clamp. It is surfaced, never silent — recorded in the
    `policy_decision` audit event as `inline_protected_unverified` (a
    subset of `inline_protected`) and counted under the
    `inline_protected_unverified` attachment-action metric label. A scan
    I/O error never aborts message processing (invariant #3).
-   **Precision.** False positives in the token scan (a `cid:` string
    that is not a live reference) only ever over-protect (fail-safe
    direction, never worse than phase 1); a scheme-boundary guard rejects
    the obvious non-references (e.g. the `cid:` inside `acid:`). The token
    charset is permissive and percent-decoding is applied to avoid false
    negatives that would break legitimate inline mail. Two known,
    accepted false-negative shapes remain (T2.8 residual 3-4): container
    scoping is narrower than RFC 2392's message-global resolution (a
    referencing HTML structurally outside the asset's own
    `multipart/related` container is not found — not observed in
    real-world MUAs), and HTML-entity/multi-byte-encoded `cid:`
    references (e.g. `&#99;id:...`, a UTF-16 body) are not recognized by
    the single-byte ASCII token scan.
-   **Behavior change.** An unreferenced `Content-ID` image under a broad
    `replace` policy now replaces (it was protected in phase 1);
    documented in CHANGELOG. Install base at the time of the change is
    the pilot only.

## ADR-017: Audit Log Retention via Checkpoint/Anchor Truncation

Status: **Proposed** (2026-07-16). Refines the tamper-evident
audit log (SR-128-1, previously delivered) and the retention
sweep (US-5.3/ADR-011). Awaiting atr-security + atr-architect review.

### Context

The audit log (`internal/core/audit`, `audit_events` table) is
append-only with a per-row hash chain: each row stores `prev_hash` =
the hash of the row at `seq-1`, so altering or removing any earlier row
changes every later row's recomputed hash (the SR-128-1 tamper-evidence
hook). The `AuditSink` contract exposes only `Record` — no update, no
delete — by design.

The grommunio pilot (mxbox, 2026-07-14) showed this is a problem in
production: the milter sits on `smtpd_milters` and sees the whole
server's mail flow, including inbound internet mail, and every message
leaves at least two audit events (`policy_decision` +
`message_processed`) even on `pass`. The `audit_events` table therefore
grows by thousands of rows/day forever. The storage-retention Sweeper
(US-5.3) prunes attachments and links but deliberately never touches
`audit_events` — a naive `DELETE` there would sever the hash chain and
destroy the tamper-evidence for every surviving row. There is also a
privacy angle (GDPR): third-party sender addresses accumulate
indefinitely.

### Decision

Introduce **opt-in** audit retention that truncates a contiguous prefix
of the log while preserving verifiability via a checkpoint anchor.

1.  **Anchor semantics.** To truncate everything up to and including
    `seq N`, the store first appends a `retention_checkpoint` audit
    event (a normal chained row, at the current tail) whose `Details`
    record `anchor_seq = N` and `anchor_hash = H_N` (the recomputed
    hash of the row at `seq N`), plus `truncated_count`, `cutoff`, and
    `held_clamped`. Then, in the **same writer transaction**, it deletes
    every row with `seq <= N`. The first surviving data row (`seq N+1`)
    already carries `prev_hash = H_N` from when it was written, so the
    checkpoint's `anchor_hash` is exactly the trusted continuation point
    for the survivors. Because the checkpoint is itself a chained,
    hash-covered row, its declared anchor cannot be forged without
    breaking the chain from the checkpoint forward. Truncation is only
    performed — and a checkpoint only written — when at least one row is
    actually removed, so an idle log never accretes empty checkpoints
    (which would themselves defeat the purpose).

2.  **Contiguous, time-safe boundary.** The truncation boundary is the
    largest `N` such that *every* row with `seq <= N` is older than the
    cutoff: `N = (min seq with created_at >= cutoff) - 1`, or the max
    seq if all rows are old. This never removes a row newer than the
    cutoff even though `seq` is insertion order and `created_at` is
    caller-suppliable (only deterministic tests set an explicit past
    timestamp; production always stamps `time.Now()`, so seq order and
    time order coincide — but the boundary is defined to be correct
    regardless).

3.  **Legal hold clamps the boundary (does not fragment the chain).**
    Events tied to a message that has any link under legal hold
    must never be truncated. Rather than skip individual
    held rows mid-prefix (which would fragment the chain and void the
    single-anchor model), the boundary is clamped down to just before
    the oldest held-related event: `N = min(N, oldestHeldSeq - 1)`. A
    single held message therefore pins all older audit history from
    truncation until the hold is lifted, at which point a later sweep
    truncates further. This is compliance-correct (litigation hold
    freezes data), keeps truncation a clean contiguous-prefix delete,
    and is self-resolving. The clamp is recomputed inside the same
    writer transaction as the delete, so a hold set concurrently is
    honored (single-writer serialization, ADR-011).

4.  **Configuration.** `retention.audit_retention_seconds`, default `0`
    = **disabled**: the log stays append-only forever, byte-for-byte the
    current behavior. Truncation is opt-in and separate from the file
    retention period (`links.default_retention_seconds`). When set > 0,
    it runs inside the existing retention Sweeper pass (US-5.3), so it
    requires `retention.enabled = true`.

5.  **`AuditSink` stays append-only; truncation is a distinct, audited
    capability.** The delete path is a new, separately named
    `audit.Truncator` interface — never folded into `AuditSink` — so the
    SR-128-1 "no update/delete reachable from an event producer" contract
    is preserved: mail-path and API producers depend only on `AuditSink`
    and cannot reach truncation. Every truncation is itself an audit
    event (the checkpoint), so the act of truncating is tamper-evident.

6.  **Seq-cursor safety.** API clients page the audit log by an opaque
    seq cursor. After truncation, a cursor whose position precedes the
    new minimum surviving seq would silently skip the removed range.
    `ListEvents` detects this (`afterSeq + 1 < min(seq)`) and returns
    `audit.ErrCursorTruncated`, which the HTTP layer maps to `410 Gone`
    — an explicit, distinguishable error, never a silent gap. A cursor
    at or after the anchor resumes cleanly.

### Verification recipe (foundation for `attachra audit verify`)

A verifier walking live rows in ascending seq:

-   If the first row's `prev_hash` is empty, it is genesis; walk forward
    confirming each row's `prev_hash` equals the recomputed hash of its
    predecessor.
-   If the first row's `prev_hash` is non-empty (a prefix was
    truncated), locate the `retention_checkpoint` whose
    `anchor_hash` equals that `prev_hash` (and `anchor_seq` = first
    row's seq − 1). That establishes the trusted anchor; walk forward
    from there. The checkpoint records who/when/through-which-seq, so
    the truncation itself is auditable.
-   A segment exported *before* truncation (via the existing streaming
    `ExportJSONL`) is a complete prefix from genesis and is therefore
    **autonomously verifiable**; its last row's hash equals the
    checkpoint's `anchor_hash`, bridging the archived segment to the
    live tail. Chained archives + live tail thus compose into one
    end-to-end verifiable history.
-   **Degenerate case: every row was older than the cutoff.** When
    `TruncateAudit` truncates the entire table (no row survives the
    boundary), the checkpoint it appends is itself the *only* surviving
    row: it lands at `seq = old_max_seq + 1` (past the boundary, so the
    delete never touches it), and its own `prev_hash` equals its own
    `Details.anchor_hash` (both are the hash of the last row it just
    deleted). A verifier's walk therefore starts on a single live row
    that is simultaneously the anchor-establishing checkpoint AND the
    first (only) row to verify — there is no separate, later data row
    for it to "precede". This must be handled explicitly, not treated as
    a chain-not-found error: confirm `Type == retention_checkpoint` and
    `prev_hash == Details.anchor_hash` (self-consistency) on that one
    row, and — unlike the genesis case, where `prev_hash` is empty and
    there is nothing to check it against — do **not** expect
    `anchor_seq` to correspond to a live row; it never will, since the
    row it names was the last one just deleted. Treat this row as
    established/trusted the same way genesis is, then stop (there is
    nothing further to walk).

**Delivered** (`attachra audit verify`): the canonical
row-hash function was lifted from `internal/core/store/sqlite` (where it
lived unexported) to `internal/core/audit.HashRecord`, so both the
store's write path and the verifier call the same function (ADR-002).
`HashRecord` deliberately reproduces the EXISTING `"|"`-delimited field
construction byte-for-byte — a stricter, collision-proof length-prefixed
framing was drafted during review but deferred to a follow-up (with an
explicit hash-format version) specifically so `attachra audit verify`
does not report a false "tampered" verdict against every audit log that
predates it, including the live pilot database. See `HashRecord`'s own
doc comment for the full rationale and the security team's assessment of
why the residual delimiter-collision risk is not practically exploitable
today.

### Limitations: what verification does not prove

The chain-walk above proves the surviving log has not been altered
**since the anchor**. It does not, and by construction cannot, prove
that the anchor itself is legitimate. This is a real, accepted residual
gap, not an oversight, and must be stated plainly:

-   **The threat.** An attacker (or authorized insider) with direct write access to the SQLite database file —
    outside `TruncateAudit`'s transaction, e.g. via the `sqlite3` CLI
    against a stopped process or a mounted volume — can fabricate a
    `retention_checkpoint` row whose `anchor_hash` is *genuinely* the
    recomputed hash of whatever row they choose to make the new
    boundary, and then delete every row up to and including it. Because
    `anchor_hash` is computed the same way `TruncateAudit` computes it,
    the resulting log is **indistinguishable from a legitimate
    truncation**: the surviving chain verifies cleanly from the forged
    anchor, exactly as it would from a real one. This is not a flaw in
    the hash construction — it is the same limitation every hash chain
    without an external anchor has (a chain proves *sequence*, not
    *completeness*).
-   **Self-attested fields.** `Actor`, `cutoff` and `truncated_count` on
    the checkpoint event are supplied by the caller (the sweeper, or
    whoever else can reach `Truncator`) and are not independently
    attested. An attacker with write access can set these to any
    plausible-looking value, including ones that make an unauthorized
    deletion read as a routine scheduled sweep.
-   **What verification DOES prove.** Internal integrity of the chain
    from the anchor forward: nothing in the surviving log was altered
    or reordered after the anchor was established, and the checkpoint
    that created the anchor is itself part of that same tamper-evident
    chain (so at least *when the checkpoint was written relative to
    other surviving events* is trustworthy).
-   **What closes the gap (not delivered by this ADR).** The only
    guarantee against a forged anchor is an **external reference
    predating the alleged truncation**: an offsite/WORM export
    (`ExportJSONL`, already streaming and usable today, N3 below) taken
    before the truncation, or — as a stronger, in-product future
    mitigation — a checkpoint signed with a key the truncating process
    does not itself control (e.g. an operator-held key, or a remote
    attestation service), so a local DB-write attacker cannot forge one.
    Neither is in scope for this design; this paragraph exists so nobody
    downstream (compliance docs, security questionnaires, an operator
    reading `docs/architecture/audit-retention.md`) mistakes "the
    surviving chain verifies" for "nothing was tampered with".
-   **Deleting the most recent events is invisible to a backward chain**
    (security review finding, R1). `attachra audit verify`'s chain walk
    proceeds forward from a trusted start, confirming each surviving
    row's `prev_hash` matches the recomputed hash of its predecessor. An
    attacker who deletes the NEWEST rows off the tail (rather than an old
    prefix via the audited `Truncator`) leaves every remaining row's
    chain fully self-consistent — there is nothing in the surviving data
    to indicate that even-newer rows used to exist. `TestVerifyDoesNotDetectTailDeletion`
    (`internal/core/audit/verify_test.go`) pins this as an intentional,
    accepted verdict (`OK == true`), not an oversight. Detecting tail
    deletion requires an external, independently maintained high-water
    mark — e.g. a periodically exported max `seq`, or an offsite/WORM
    export whose most recent line reveals the log grew further after the
    point an attacker rolled it back to — which is exactly the same
    external-reference mitigation the forged-anchor gap above requires,
    and is likewise not delivered by this design.

### Alternatives considered

-   **Skip held rows individually (sparse truncation):** rejected —
    fragments the hash chain, so a single anchor can no longer certify
    the survivors; would require per-segment anchors and a far more
    complex verifier.
-   **Segmented chains by period, archive whole segments:** viable but
    heavier; a period boundary still needs an anchor between segments,
    which is exactly the checkpoint here. The prefix-truncate model is
    the minimal form of the same idea and reuses the existing single
    chain unchanged.
-   **Automatic archive-to-file before truncation:** deferred to a
    follow-up. The existing streaming export already lets an operator
    capture the segment before enabling truncation; auto-archive adds
    filesystem failure-mode surface (must-not-truncate-if-archive-failed)
    orthogonal to the chain-preservation core this ADR delivers. The
    autonomous-verifiability property is guaranteed by design and tested
    regardless.

### Consequences

-   New: `audit.Truncator`, `audit.TypeRetentionCheckpoint`,
    `audit.ErrCursorTruncated`, `retention.audit_retention_seconds`,
    a `410 Gone` response on `GET /api/v1/audit` for a truncated cursor.
    Module boundaries unchanged (ADR-002): truncation contract in
    core/audit, implementation in core/store/sqlite, scheduling in
    core/retention.
-   The append-only guarantee is now "append-only for event producers;
    truncation only via the audited, checkpoint-preserving `Truncator`,
    opt-in and off by default". SR-128-1 tamper-evidence is preserved:
    any removal is anchored and self-recorded.
-   Behavior unchanged unless an operator sets
    `audit_retention_seconds > 0`. Community edition default keeps the
    full, immutable log.
-   See "Limitations: what verification does not prove" above for the
    accepted residual gap (threat-model.md T2.10): a forged anchor is
    possible for an attacker with direct DB write access, closed only by
    an external reference (offsite export) or a future signed anchor,
    neither delivered here.
-   Old `retention_checkpoint` rows are themselves ordinary chain rows
    and therefore eligible for a **later** truncation pass: a second,
    later-cutoff sweep can remove an earlier checkpoint along with the
    data it anchored, re-anchoring at the new boundary (exactly the
    "advances" case `TestTruncateAuditIsIdempotentAndAdvances` covers).
    Consequently the full history of *which truncations ever happened*
    is not durable from the live database alone once enough time passes
    — only the current anchor and whatever was exported before each
    pass survive indefinitely. An operator who needs a permanent
    truncation history must rely on the streamed export (N3 below), not
    on querying the live table.
