## What and why

Briefly describe the change and the problem it solves. Link the
related issue/ADR if any.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup (no behavior change)
- [ ] Documentation
- [ ] CI / tooling

## Checklist

- [ ] `make check` passes locally (or `go build ./...` && `go test -race ./...`
      if `make` targets aren't available yet)
- [ ] Tests added/updated for the behavior change
- [ ] No secrets, credentials, or `.idea/`/editor state committed
- [ ] If this touches `internal/core` or `internal/adapters`: the
      core/adapter boundary is preserved (core has no Postfix/milter
      imports)
- [ ] If this touches milter/MIME/policy/link/storage code, the
      following invariants still hold (see `CONTRIBUTING.md`):
  - [ ] No mail message can be silently lost — failures resolve to a
        configured fail-open (accept) or fail-closed (tempfail)
  - [ ] Attachments/messages are processed as streams, not fully
        buffered in memory
  - [ ] Link tokens use `crypto/rand`, ≥128 bits; only hashes are stored
  - [ ] Community-edition functionality is not degraded to make room
        for a paid feature
- [ ] If this is an architectural change (module boundaries, policy/API
      format, new dependency with a non-trivial license): an ADR entry
      is included or referenced

## Environment tested against

- Attachra version / commit:
- Postfix version:
- Mail stack (e.g. Mailcow, iRedMail, Mail-in-a-Box, custom), if applicable:

## How was this verified?

Describe manual testing, added automated tests, or note if something
couldn't be verified (e.g. no Docker available) — say so explicitly
rather than leaving it silent.
