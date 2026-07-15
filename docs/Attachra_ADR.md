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
-   Phase 2 (separate ticket): verify cid: references from the HTML
    body.
