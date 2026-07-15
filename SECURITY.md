# Security Policy

Attachra processes outbound mail and attachments on behalf of its
users. Trust in how it handles that data is the core of the product,
not an afterthought — so we take vulnerability reports seriously, even
while the project is in early development and has not yet had a public
release.

## Supported versions

Attachra has not reached a v0.1 release yet. Until a first release
exists, treat the `main` branch as the only supported target for
reports. Once versioned releases begin, this section will be updated
with a support table.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security
vulnerabilities.**

Report privately to:

**security@attachra.org** *(placeholder — will be confirmed/updated
before the first public release)*

Include as much of the following as you can:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof of concept, if available.
- Affected component (e.g. milter adapter, MIME parsing, policy engine,
  download/link endpoint, storage backend, REST API).
- Any relevant version/commit information.

### What to expect

- **Acknowledgement within 72 hours** of your report.
- We will work with you to understand and validate the issue, and keep
  you informed of progress toward a fix.
- We ask for **coordinated disclosure**: please give us a reasonable
  window to investigate and ship a fix before any public disclosure.
  We will work with you to agree on a disclosure timeline once the
  report is triaged — the goal is a fix and an advisory landing
  together, not a silent fix or an unplanned public disclosure.
- Credit is given to reporters who want it, once a fix is public.

## Scope

Security reports are in scope for the Attachra codebase in this
repository, including (non-exhaustively):

- **Milter input handling** — hostile/malformed MIME parsing, zip
  bombs, unbounded nesting, header injection.
- **The download/link endpoint** — token enumeration/brute-force,
  access control on stored files, SSRF via redirects, denial of
  service.
- **Storage** — cross-tenant access to files, metadata leakage through
  object keys or logs.
- **Authentication and the REST API** — authorization boundaries,
  token/session handling, privilege escalation.
- **Link token generation and storage** — tokens must be generated with
  `crypto/rand` at ≥128 bits of entropy and compared in constant time;
  only hashes of tokens are expected to be persisted, never the tokens
  themselves.

Out of scope (for now, given the project has no public deployment):

- Denial-of-service reports that require unrealistic resource
  assumptions (e.g. requiring privileged local access).
- Issues in third-party dependencies without a demonstrated,
  Attachra-specific impact — please report those upstream as well.
- Social engineering, physical security, and reports against
  infrastructure that isn't part of this repository (e.g. unrelated
  websites).

This scope will be revised as the product grows (REST API, Web UI,
plugin system) and as a formal threat model is published.

## A note on disclosure to us vs. the community

Attachra is committed to communicating security issues honestly once
they're fixed, including in released versions — no downplaying, no
silent patches. See `CONTRIBUTING.md` for how fixes flow into releases.
