# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/302-digital/attachra/releases/tag/v0.2.0
[0.1.0]: https://github.com/302-digital/attachra/releases/tag/v0.1.0
