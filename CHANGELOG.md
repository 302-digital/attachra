# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-07-17

A production bug found in the mxbox pilot — a spurious blank line
corrupting nested MIME parts on rewrite — is the headline fix. Also:
a real security-review sweep across rate limiting, recipient isolation
and the observability surface, address normalization so sender-based
revoke actually finds what it should, and the metrics/health endpoint
moving off the public listener by default (**operator action may be
required**, see Changed).

### Added

- **`attachra audit verify` — tamper-detection for the audit log.** Walks
  the append-only audit log's per-row hash chain (SR-128-1) and reports
  whether it is intact, or the first point (seq, expected vs. actual
  hash) at which an event was altered, removed, or reordered. Verifies
  the live database by default, or an offline `attachra audit export`
  segment via `--jsonl PATH` (`-` for stdin), without touching the
  database. Exit codes distinguish a clean verdict (0) from a detected
  break (1) from an operational failure (2). Handles every chain-start
  shape ADR-017 describes (genesis, post-truncation anchored resume, the
  degenerate self-anchoring checkpoint) and states plainly, when any
  truncation checkpoint is present, that integrity is verified only from
  the earliest trusted anchor forward. Strictly read-only. See ADR-017
  and `docs/architecture/audit-retention.md` for what this does and does
  not prove.
- **Audit-log retention (opt-in).** The tamper-evident audit log can now
  be truncated so it does not grow without bound (the milter sees the
  whole mail flow, ~2 events per message). Set
  `retention.audit_retention_seconds` (default `0` = disabled, so the log
  stays append-only forever by default). Truncation removes an old,
  contiguous prefix and writes a `retention_checkpoint` event that
  anchors the survivors, so hash-chain verifiability is preserved across
  the boundary; events tied to a message under legal hold are never
  removed. A cursor into a truncated range on `GET /api/v1/audit` now
  returns `410 Gone` instead of silently skipping. See ADR-017 and
  `docs/architecture/audit-retention.md`.
- **`GET /about`**: a static, unauthenticated Recipient Trust Kit page on
  the public download listener, alongside `/p/`. Lets an unfamiliar
  recipient's IT admin verify a download link before whitelisting or
  reporting the domain — what Attachra is, why the link exists, and how
  it's safe (sender-owned domain, revocable/TTL-bound links, forced
  save-as downloads, no inline execution or redirect).
- `spool.dir` config (`ATTACHRA_SPOOL_DIR`, `spool.dir` in YAML): lets
  operators under a locked-down deployment (noexec/quota'd `/tmp`, no
  systemd `PrivateTmp`) point large-message spool files somewhere
  writable instead of failing on the first oversized message. Validated
  at config-load time, not on first use.

### Changed

- **Inline (CID) asset protection now verifies the `cid:` reference**
  (ADR-016 phase 2). An inline image is spared from a broad `replace`
  policy only if its `Content-ID` is actually referenced via a `cid:`
  URL from a `text/html` body of the same `multipart/related` container.
  A `Content-ID` image that no HTML body embeds now replaces normally
  like any other attachment (previously it was protected on the
  structural signal alone). Legitimate inline logos/signatures — which
  are referenced from the HTML body — are unaffected. The scan is bounded
  both per part (1 MiB per `text/html` part) and in aggregate across a
  whole message (4 MiB total scanned bytes / 65536 total distinct
  `cid:` tokens), and only runs at all if the message has at least one
  Content-ID inline-asset candidate to begin with. When a referencing
  HTML body — or the message's aggregate scan budget — cannot cover full
  verification, verification falls back to the previous protect-anyway
  behavior and the asset is recorded in the audit as
  `inline_protected_unverified` (also a new metric label). Narrows the
  residual documented in threat-model T2.8.
- **`/metrics` and the dependency-detailed `/readyz` move to a new admin
  listener, off the public download listener by default.** Previously
  both shared `http.listen` (the same listener as `/p/`) — a deployment
  that exposed `http.listen` publicly would also leak Go build/runtime
  fingerprinting data and internal dependency names. A new
  `admin.listen` config defaults to loopback-only `127.0.0.1:18090`
  (not 9090 — that's Prometheus's own default and the most likely
  collision on a mail host). **If you scrape `/metrics` from a
  Prometheus (or similar) target pointed at `http.listen`, update it to
  the new `admin.listen` address** — an upgrade with no config changes
  picks up the new listener automatically and nothing else moves.
  Folding admin routes back onto `http.listen` (the old, single-listener
  behavior) requires an explicit `admin.fold_into_http` opt-in and logs
  a warning (an error if the public listener isn't loopback). An empty
  `admin.listen` is now a validation error rather than a silent fold.
  `GET /healthz` (liveness — a static "ok", no dependency detail) stays
  on both listeners, so existing container/orchestrator/`attachra
  doctor` liveness probes are unaffected. An admin-listener bind/serve
  failure is no longer fatal: `/p/` and the milter stay up, only the
  observability surface goes missing.
- **Sender/recipient addresses are normalized at ingest and at query
  time**, both for what the milter records (`MAIL FROM`/`RCPT TO`, or
  the MTA's macros, weren't guaranteed a consistent case or
  angle-bracket wrapping) and for `ListMessages`/`ListLinks` filters and
  `attachra link revoke --sender`. Previously a message could be
  recorded as `John@Corp.com` and a revoke for `john@corp.com` would
  silently miss it — the attachment stayed downloadable after an
  operator believed access was revoked. Migration 000007 normalizes
  every existing stored sender/recipient value in place (one-way,
  idempotent).
- CI and the Go toolchain bumped to 1.26.5 (from 1.26.2): govulncheck
  found 8 reachable stdlib CVEs on 1.26.2, including an ECH privacy leak
  in `crypto/tls` fixed only in 1.26.5. `govulncheck ./...` now reports
  zero findings and is a gate in CI.

### Fixed

- **Rewrite could corrupt nested MIME structures with a spurious blank
  line.** The MIME rewriter unconditionally appended a trailing CRLF
  after every multipart closing delimiter it wrote, which is only
  correct for the message's genuinely outermost multipart structure —
  for a nested `multipart/*` child, a `message/rfc822` envelope's own
  body, or the synthesized replacement-block part, that CRLF belongs to
  whatever delimiter comes next in the enclosing structure, not this
  one. The result: any message with `multipart/related` or
  `multipart/alternative` nesting (e.g. an HTML body with an inline
  image, next to a replaced attachment) came out with a corrupted body
  after rewrite — a real defect hit during the mxbox production pilot.
  Found by a new round-trip byte-integrity test corpus, which also
  caught the test harness itself sending attachments as raw bytes
  instead of base64 (masking CTE mismatches). This is the most
  significant fix in this release.
- **Single-part-to-multipart promotion could produce a malformed or
  header-losing message.** Two compounding bugs on the path where
  rewrite promotes a single-part message into a `multipart/mixed`
  envelope (attachment stripped from an otherwise-plain email):
  the promoted `Content-Type`/`MIME-Version` were being written after
  the header block's terminating blank line — landing in the message
  body instead of the headers — and the milter adapter could only ever
  *add* headers, never change or delete one, so this and any other
  changed/dropped header on the promotion path was routed into the
  configured fail-open/fail-closed path instead of being applied.
  The adapter now negotiates `ChangeHeader` and reconciles the
  rewritten header block against the MTA's own headers (change in
  place, add if new, delete if dropped).
- **`sqlite`'s database directory is now created automatically if
  missing**, instead of failing lazily with an opaque
  `SQLITE_CANTOPEN` on the first query — e.g. a systemd
  `StateDirectory=` that only creates its top-level directory, not a
  configured nested subpath. Mirrors the same fix already applied to
  the filesystem storage driver. `attachra doctor`'s
  `database_dir` check is downgraded from FAIL to WARN on a missing
  directory to match.
- Orphaned metadata rows after a failed rewrite: if `CreateLinks`
  succeeded but a later pipeline step (packaging, MIME rewrite) failed,
  the already-created message/attachment/link rows are now deleted
  along with the rolled-back storage objects, instead of being left
  behind as active-status rows pointing at deleted files. The cleanup
  itself is legal-hold-safe (refuses and leaves everything untouched if
  any link is under hold) and is recorded in the audit trail.
- Download `Content-Length` is now read from the storage backend at
  serve time instead of the metadata database's cached size, so it
  can no longer drift from what's actually streamed if the underlying
  object was replaced or re-uploaded out of band.

### Security

- **Per-IP rate limiter and auth-throttle memory is now bounded**
  (LRU + TTL eviction on a new dependency-free `evictingBucketMap`).
  Previously each grew one entry per distinct source IP for the
  process lifetime with no eviction — a distributed attacker spraying
  requests across many source IPs (trivial over IPv6) could grow
  either map without bound.
- **Concurrent `GET /audit/export`, `/stats/summary` and
  `/stats/deliverability` requests are now capped.** Each does an
  unpaginated full-log scan or a full-window aggregate; nothing
  previously bounded how many could run at once, so a single
  low-privilege `viewer`/`auditor` token could pressure reader
  connections, CPU and IO in parallel. Keeps the blast radius of a
  low-privilege token small, per the viewer/auditor role split
  (ADR-015).
- **The package page and downloads are now scoped to the resolving
  recipient.** `CreateLinks` persists one `Link` per
  (attachment, recipient) pair, but package-page listing and download
  registration were previously scoped by message only — so the one
  recipient token embedded in a message's own copy could see and drain
  every *other* recipient's `Link` rows for that same message: a
  composition leak and a shared download-budget exhaustion risk.
- `attachractl` now warns when a token file (`--token-file`, config
  `token_file`, or an inline config `token:`) is readable or writable
  by group or other, mirroring `ssh`'s own private-key permission
  hygiene.

### Docs

- Recorded the DKIM/Attachra milter-ordering conflict found during
  live verification against the mxbox pilot (rspamd-sign before
  Attachra breaks the DKIM body hash) and documented archiving milter
  order in the Postfix integration guide.
- New download-domain reputation guide and replacement-block
  anti-phishing principles writeup.
- Pinned the minimum Go version in CONTRIBUTING.md.

## [0.2.1] - 2026-07-16

### Added

- **Signed releases.** Release artifacts are now signed with cosign
  (keyless, GitHub OIDC): the container image is signed by digest, and
  `SHA256SUMS` ships with a Sigstore bundle
  (`SHA256SUMS.sigstore.json`). A new "Verifying releases" section in
  the README documents the two verification commands.

### Changed

- Dependency updates: `spf13/cobra` 1.10.2 and the `aws-sdk-go-v2`
  modules used by the S3 storage driver (config 1.32.30, credentials
  1.19.29, s3 1.105.1). No behavior changes.
- CI: every GitHub Action bumped to its current major (checkout v7,
  build-push-action v7, gitleaks-action v3, golangci-lint-action v9,
  action-gh-release v3) — the only breaking change in all five is the
  Node 24 runtime, which GitHub-hosted runners already provide.

## [0.2.0] - 2026-07-16

A REST API and a companion CLI client, link lifecycle management
(hold/revoke/retention), a guided setup wizard and install diagnostics,
and first-class packaging (Debian package, Docker image, one-line
installer). Also two pipeline hardening fixes surfaced by a live
production pilot: inline (CID) assets and message bodies are no longer
at risk from a broad `replace` policy.

### Added

- **REST API** (US-8.1): a versioned admin API under `/api/v1` covering
  everything an operator previously had to do by hand or by reaching
  into the database — inspect processed messages and attachments;
  list, hold, unhold and revoke download links (one at a time, by
  message, or by sender); view, validate, reload and dry-run the active
  policy; pull summary and per-domain deliverability stats; and page or
  stream-export the audit log. Authentication is Bearer-token,
  deny-by-default, with three roles (`admin`, `viewer`, `auditor`);
  bootstrap the first token with `attachra token create`. Repeated
  invalid-token attempts are throttled, and creating or revoking a
  token is itself recorded in the audit trail. The OpenAPI spec
  (`api/openapi.yaml`) is the source of truth and is linted in CI.
- **`attachractl`**: a second, self-contained binary that is a pure
  REST API client for the API above — `policy`, `links`, `stats`,
  `audit` and `token` subcommands, human-readable tables or `--json`,
  TLS verification on by default. The API token is only ever read from
  a file, an environment variable, or a config file, never a
  command-line flag, so it can't leak into `ps` output or shell
  history.
- **`attachra link hold` / `unhold` / `revoke`** (US-6.3): put a link
  under legal hold, clear a hold, or revoke it — one link at a time,
  every link on a message, or every link ever sent by a given sender
  address. A held link refuses revocation until the hold is cleared.
- **Automatic attachment retention** (US-5.3): a background job deletes
  stored attachments once their retention period has passed (30 days by
  default, configurable globally via `links.default_retention_seconds`
  or per policy), runs hourly by default (`retention.interval_seconds`),
  and skips anything under legal hold instead of deleting it.
- **`attachra setup`**: a guided first-run wizard that writes a working
  config, interactively or non-interactively via flags, and starts new
  installs in dry-run/log-only mode by default. It makes a best-effort,
  advisory-only guess at the mail stack it's running alongside (plain
  Postfix, grommunio, Mailcow, iRedMail) to suggest sane defaults — it
  never modifies that other software.
- **`attachra doctor`**: one command to check whether an install is
  actually healthy — config and policy loading, storage and database
  directory permissions, whether the HTTP and milter ports are
  listening, whether the public download URL and SPF record look
  right, and whether Postfix is actually wired to the milter. Supports
  `--json` for scripting.
- Man pages and shell completions for both `attachra` and `attachractl`.
- Official Debian packages (amd64 and arm64), built with a hardened
  systemd unit (dynamic unprivileged user, filesystem/network
  sandboxing), published with checksums on every GitHub release.
- A Docker image, published to `ghcr.io/302-digital/attachra`.
- A one-line install/uninstall script for the Debian package
  (`curl -fsSL https://attachra.org/install | sudo bash`, see the
  README Quickstart). Neither script touches Postfix or writes a
  config — that's what `attachra setup` is for.
- `http.trusted_proxies`: a CIDR allowlist for a co-located reverse
  proxy (e.g. nginx in front of the download page and API). Configure
  it so audit records and rate limiting see the real client IP instead
  of the proxy's; left empty (the default), behavior is unchanged from
  v0.1.0.
- A per-message `INFO` log line (`milter: message processed`) is now
  written by the milter for every ordinary message handled, not just
  errors — previously an operator tailing logs had no confirmation a
  message was even seen unless something went wrong.
- Supply-chain hardening: OpenSSF Scorecard (badge in the README),
  CodeQL scanning, Dependabot and `govulncheck` are now part of CI, and
  every GitHub Action and base image is pinned to a specific
  commit/digest.

### Changed

- **A `default: replace` policy no longer risks the message body.**
  Every leaf MIME part, including the message's own text/plain and
  text/html body, is evaluated against policy as normal, but a body
  part's `replace` decision is now automatically downgraded to `pass`
  instead of being dropped or corrupted; a `block` rule matching the
  body's actual (detected, not declared) content still rejects the
  message. Downgrades are recorded in the audit trail (`body_protected`
  detail) and as a metric label.
- **Inline (CID) attachment protection** (ADR-016): a
  presentation-inline asset (e.g. a logo or signature image referenced
  from the HTML body via `cid:`, inside `multipart/related`) decided
  `replace` by policy is now downgraded to `pass` by default, instead of
  being turned into a broken link. This is a **behavior change**: inline
  image assets under a broad `replace` rule are no longer replaced
  unless the policy explicitly opts in via the new
  `when.attachment.disposition: [inline]` matcher. `block` decisions are
  never downgraded. New config option `limits.inline_max_size` (default
  256 KiB) bounds the downgrade to logo/signature-sized images; larger or
  type-mismatched parts still replace normally. See
  `docs/Attachra_ADR.md` ADR-016 for the full design.
- **Behavior change: the built-in Russian recipient-notice locale has
  been removed.** `rewrite.TemplateConfig.Locale` now only ships an
  English template; any other value (including `"ru"`) falls back to
  English. A proper multi-locale story (translated built-in templates,
  config-driven selection) is tracked as a follow-up; in the meantime,
  operators needing a different language can supply
  `TextTemplatePath`/`HTMLTemplatePath` overrides pointing at a custom
  template.

### Fixed

- **The filesystem storage driver no longer crash-loops on a fresh
  install.** It previously required its configured storage directory
  to already exist; a freshly installed system only has its parent
  directory created for it, so every clean install failed to start.
  The directory is now created automatically if missing.
- **Debian package versions built from a development commit now
  compare correctly for upgrades.** A package built from a commit with
  no reachable release tag previously fell back to a bare short commit
  hash as its version, which `dpkg` treats as newer than any real
  release and breaks upgrade ordering. It now falls back to the latest
  known release tag plus a commit suffix instead.

## [0.1.0] - 2026-07-09

First end-to-end mail path (M1 core). An outgoing message passes through
Postfix milter → MIME parsing → policy engine → object storage → personal
links → MIME rewrite → recipient download page, with an append-only audit
trail. Single static binary, linux/amd64 + linux/arm64.

> **Note on the published v0.1.0 packages.** The v0.1.0 packages and
> container image published on GitHub were built from a 2026-07-15
> development snapshot, which already included early versions of several
> features documented under 0.2.0 — the REST API, `attachractl`, link
> lifecycle management, retention, and the setup wizard. 0.2.0 is the
> first release in which those features are properly versioned and
> documented. The entries below describe the original v0.1.0 release
> line.

### Added

- **Postfix milter adapter** (US-2.1): milter server with session lifecycle,
  streaming message handoff to the core, rewritten body/header return
  (`replacebody`, `addheader`), graceful shutdown, connection limits and
  timeouts.
- **Fail-open / fail-closed modes** (US-2.2): every core error resolves to a
  configured mode — accept unchanged or tempfail; a message can never be lost.
- **MIME attachment detection** (US-3.1): full MIME-tree traversal, real file
  type detection by magic bytes, RFC 2231/2047 filename decoding, golden-test
  corpus.
- **MIME rewrite** (US-3.2): attachment replaced by a link block
  (text/plain + text/html, RU/EN templates) with the original tree structure
  preserved; DKIM sign-after-milter documented.
- **Declarative YAML policies v1** (US-4.1, ADR-006): sender / recipient /
  attachment matchers, prioritized rules, table-driven tests; policy format
  specification.
- **Policy hot reload & dry-run** (US-4.2): atomic reload without restart,
  per-policy and global dry-run, policy file validation command.
- **S3-compatible storage** (US-5.1, ADR-007): streaming S3 driver
  (aws-sdk-go-v2), object key/metadata scheme, MinIO integration tests.
- **Filesystem storage driver** (US-5.2): atomic writes, directory layout,
  contract test suite shared by all storage drivers.
- **Personal recipient links** (US-6.1): crypto/rand tokens (≥128 bit, only
  hashes stored — ADR-011), per-policy TTL and download limits, link/message/
  attachment/recipient relations in embedded SQLite.
- **Download endpoint** (US-6.2): streaming download page (multi-attachment
  package page), expired/revoked/not-found pages, atomic download counters,
  rate limiting.
- **Append-only audit log** (US-7.1): hash-chained event model recorded across
  the pipeline, download and revoke paths; `attachra audit export`
  (JSON Lines).
- **Project foundation** (US-1.1/1.2/1.3): single static binary with
  version from `git describe` (`attachra --version`), YAML + env configuration
  with startup validation, structured logging (slog), Makefile, golangci-lint,
  CI (build + race tests + lint + cross-compile), docker-compose dev
  environment with Postfix + MinIO, e2e test harness, security hardening of
  the skeleton (SR-113).

### Infrastructure

- CI runner memory raised to 6 GiB; lint is a required (blocking) CI job
  (internal CI change).
- Container image built by CI from git tags and pushed to the project
  container registry (Kaniko, staging branch and version tags).

[0.2.1]: https://github.com/302-digital/attachra/releases/tag/v0.2.1
[0.2.0]: https://github.com/302-digital/attachra/releases/tag/v0.2.0
[0.1.0]: https://github.com/302-digital/attachra/releases/tag/v0.1.0
