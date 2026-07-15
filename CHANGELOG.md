# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Structural body parts are never replace candidates**: a
  `default: replace` policy previously destroyed message bodies, because
  every leaf MIME part — including the text/plain and text/html body
  itself — was submitted to policy evaluation. The message body is now
  always excluded from evaluation and delivered intact.

### Changed

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

## [0.1.0] - 2026-07-09

First end-to-end mail path (M1 core). An outgoing message passes through
Postfix milter → MIME parsing → policy engine → object storage → personal
links → MIME rewrite → recipient download page, with an append-only audit
trail. Single static binary, linux/amd64 + linux/arm64.

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
  GitLab CI (build + race tests + lint + cross-compile), docker-compose dev
  environment with Postfix + MinIO, e2e test harness, security hardening of
  the skeleton (SR-113).

### Infrastructure

- CI runner memory raised to 6 GiB; lint is a required (blocking) CI job
  (internal CI change).
- Container image built by CI from git tags and pushed to the project
  container registry (Kaniko, staging branch and version tags).

[0.1.0]: https://github.com/302-digital/attachra/releases/tag/v0.1.0
