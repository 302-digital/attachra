# Attachra REST API — OpenAPI contract

This directory holds the **source-of-truth contract** for Attachra's admin/
automation REST API (US-8.1, epic E8, task T-8.1.1). The HTTP handlers
that implement each resource are built to match
`openapi.yaml`, not the other way around: if an implementation and this
document disagree, that is a bug in the implementation (or a sign this
document needs an update first, reviewed like any other API change).

## Files

- `openapi.yaml` — the OpenAPI 3.0.3 specification.
- `redocly.yaml` — lint configuration (see "Validating" below).

## Why OpenAPI 3.0.3, not 3.1

3.1 is newer and fully JSON-Schema-compatible, but the Go tooling this
project is most likely to reach for next — `oapi-codegen`
(github.com/oapi-codegen/oapi-codegen) for generating server
interfaces/types, and `swagger-cli`/`redocly` for linting/docs — has the
most mature, widely-relied-on support for 3.0.x today. 3.0.3 has no
expressiveness gap for this contract (no need for 3.1-only features like
webhooks or the full 2020-12 JSON Schema dialect), so there is nothing to
gain from 3.1 here and a real, current risk of rougher edges in Go codegen.
If a future need (e.g. webhooks for an event/notification pack) requires
3.1-only features, revisit this choice in an ADR rather than switching
silently.

## Why cursor pagination, not offset/page

Every list resource here (`messages`, `attachments`, `links`, `audit`,
`api-tokens`) is backed by a table that keeps growing while mail flows
through the system, or — for `audit` — is by definition append-only and
already ordered by a monotonic `seq` (`internal/core/audit`). Offset
pagination (`?page=2&page_size=50`) silently skips or repeats rows when a
row is inserted between two page requests; for the audit log specifically,
that is a correctness problem, not just a UX rough edge — a compliance
consumer paging through `GET /audit` needs to see every row exactly once.
A single opaque `limit`/`cursor` pair is used uniformly instead: see the
"Pagination" section of `openapi.yaml`'s `info.description` for the exact
contract. `GET /audit/export` is the one endpoint that intentionally has no
pagination at all — it streams the complete filtered result set in one
response, mirroring `audit.ExportJSONL`, for exactly the same reason an
external SIEM/archival job wants the full export, not one page of it.

## Roles

Community ships exactly three fixed roles (`admin` / `viewer` / `auditor`,
ADR-015 / `docs/product/open-core-boundary.md` OQ-4). Every operation in
`openapi.yaml` carries an `x-required-role` extension (an array of the
roles allowed to call it); the full access matrix is also written out as a
table in `info.description` for anyone reading the rendered docs rather
than the raw YAML. `auditor` is deliberately narrower than "read-only over
everything": it can reach only `GET /audit` and `GET /audit/export`.

## Validating the spec

Validate with [Redocly CLI](https://redocly.com/docs/cli/) via `npx`, pinned
to an exact version so local runs and CI agree:

```sh
make openapi-lint
```

which runs:

```sh
npx -y @redocly/cli@1.25.11 lint api/openapi.yaml --config api/redocly.yaml
```

`api/redocly.yaml` extends Redocly's built-in `recommended` ruleset with no
overrides — every operation in `openapi.yaml` declares at least one 4XX
response.

This is a separate Makefile target, not part of `make check`: `make check`
(the Go test+lint gate every task's Definition of Done requires) must stay
usable on a Go-only toolchain with no Node/npm installed. CI runs
`openapi-lint` as its own job (`.gitlab-ci.yml`), independent of the Go
build/test/lint jobs, so a spec regression is still caught on every
pipeline without coupling the two toolchains together.

## Viewing the spec

Any OpenAPI-aware viewer works; two zero-install options:

- Redocly's own preview: `npx -y @redocly/cli@1.25.11 preview-docs api/openapi.yaml`
- Paste `api/openapi.yaml` into <https://editor.swagger.io>

## Scope note

This document intentionally does **not** cover three HTTP surfaces that
already exist in `internal/adapters/http`:

- `GET /p/{token}` / `POST /p/{token}/d/{ref}` — the anonymous,
  Bearer-free recipient package/download pages (US-6.2). Not a JSON
  resource; documented by `internal/adapters/http/handler.go` and
  `docs/architecture/package-page-decision.md`.
- `GET /metrics` — Prometheus text exposition format, not JSON.
- `GET /healthz` / `GET /readyz` — liveness/readiness probes
  (`internal/adapters/http/health.go`). These are mounted at the server
  root (`internal/adapters/http/server.go`), not under `/api/v1`; listing
  them as `paths` in a document whose `servers` entry is `/api/v1` would
  misrepresent their real mount point as part of this contract, so they
  are named here instead of documented as operations.

All three remain unauthenticated per SR-130-1's explicit exception (health
and download), unaffected by anything in this contract.
