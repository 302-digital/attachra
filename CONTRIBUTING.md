# Contributing to Attachra

Thanks for taking an interest in Attachra. The project is in early
development — expect rough edges, and please read this file (and
`docs/Attachra_ADR.md`) before sending non-trivial changes so we don't
waste each other's time on rework.

Participation in this project is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Building and testing

Attachra is a single Go module that builds to one static binary
(see [ADR-001](docs/Attachra_ADR.md#adr-001-language)). Building from
source requires the Go toolchain version pinned in
[`go.mod`](go.mod) (currently Go 1.26.5) or newer.

```
make build   # builds the attachra binary
make test    # unit tests (go test -race ./...)
make lint    # golangci-lint
make check   # test + lint — run this before opening a PR / marking it ready for review
make run     # local run
```

If `make` targets aren't available yet in your checkout (the Makefile
is tracked as its own task), fall back to:

```
go build ./...
go test -race ./...
```

`make check` (or the fallback above) passing is a prerequisite for
review, not a nice-to-have.

## Repository structure

```
cmd/attachra/        entrypoint for the single binary
internal/core/       domain logic: policy, storage, link, audit
                     (must not import anything Postfix/milter-specific)
internal/adapters/   milter and future transport adapters (depend on core,
                     never the other way around)
pkg/                 public packages — only what's deliberately a public API
docs/                vision, ADRs, backlog, role/process docs
deploy/              docker-compose, helm, systemd
```

If you're not sure whether something belongs in `internal/core` or
`internal/adapters`, ask before writing code: the boundary is a
deliberate architectural constraint (see below), not a suggestion.

## Pull request rules

- **Tests are required**, not optional, for any behavioral change.
  PRs that touch `internal/core` or `internal/adapters/milter` without
  test coverage will be sent back.
- **`make check` must be green** before requesting review.
- **Milter invariants are non-negotiable.** Any change touching the
  milter adapter, MIME handling, the policy engine, or storage/link
  code must preserve:
  1. `internal/core` never imports anything Postfix/milter-specific.
  2. The binary stays a single static binary, cross-compilable for
     `linux/amd64` and `linux/arm64`.
  3. A mail message can never simply be lost: every failure path
     resolves to a configured **fail-open** (accept unmodified) or
     **fail-closed** (tempfail) behavior — never a silent drop.
  4. Attachments and messages are processed as streams, not fully
     buffered in memory.
  5. Link tokens are generated only via `crypto/rand`, ≥128 bits of
     entropy; storage holds hashes of tokens, never the tokens
     themselves.
  6. The Community edition stays production-ready — no PR may make
     Community functionality worse to create room for a paid feature
     (see [ADR-004](docs/Attachra_ADR.md#adr-004-open-core)).
- Keep PRs scoped to one concern. Large, mixed-purpose PRs are harder
  to review and more likely to hide a violation of the above.
- Commit messages: atomic, meaningful, in English, prefixed by area
  (`core:`, `milter:`, `storage:`, `ci:`, `docs:`, etc.).
- Never commit secrets, credentials, or `.idea/`/editor-specific state.

## Architectural changes go through ADRs

Changes to module boundaries, policy/API formats, or the introduction
of a new dependency with a non-trivial license are **architectural
decisions**, not implementation details. These require an ADR entry in
[`docs/Attachra_ADR.md`](docs/Attachra_ADR.md) (next sequential
`ADR-NNN`) describing the decision and the reasoning, proposed in your
PR description or a preceding discussion, before the code lands.

If you're unsure whether your change counts as "architectural," open an
issue first and ask — that's cheaper for everyone than reverting a
merged PR.

## Licensing of contributions (CLA)

The Attachra core is AGPL-3.0-or-later with commercially licensed
Enterprise plugin packs
([ADR-012](docs/Attachra_ADR.md#adr-012-licensing-model)). To make
that dual-licensing possible, contributions to the core will require a
**Contributor License Agreement (CLA)**. The CLA will include a binding
pledge in the contributor's favor: every contribution remains available
under an OSI-approved open-source license, forever — your code can
never be made closed-only.

The exact CLA text is pending legal review and will be published (with
automated signing in the PR flow) before external contributions open.
Until then, check back here or in the PR template before making large
external contributions.

## Questions

If something in this file, the ADRs, or the backlog is unclear, open an
issue rather than guessing — an incorrect assumption caught early is a
lot cheaper than a PR built on it.
