# Security Requirements (threat model v1 → backlog tasks)

Source: `docs/security/threat-model.md`. Format: **requirement → backlog task**.
Each requirement is folded into the acceptance criteria / checklist of the corresponding
backlog story. The threat reference is the ID from the threat model (T-x.y).

Every requirement carries a stable `SR-*` identifier (referenced from the code); the
number family matches the story it belongs to and does not change.

---

## US-1.1 — Project skeleton / config
- **SR-113-1** (T5.3, T2.6, T1.4): load secrets from env/a file with restricted permissions, `${ENV}` substitution; validate config at startup **without printing secrets**; redact secrets in any output. → T-1.1.5.
- **SR-113-2** (T2.6): configurable global limits — max message/attachment size, max part count, max MIME depth, connection limits/timeouts. → T-1.1.5.
- **SR-113-3** (T5.3): structured logging (slog/JSON) with redaction of secrets and tokens; untrusted values as fields, not concatenation. → T-1.1.6.
- **SR-113-4** (TR-F): add secret scanning and dependency scanning to the CI pipeline (with DevOps). → T-1.1.4.
- **SR-113-5** (T1.4, question #4): config for a separate public host for download links (without cookies shared with API/UI). → T-1.1.5.

## US-2.1 — Milter server
- **SR-115-1** (T2.6): a limit on concurrent milter connections, session timeouts, graceful shutdown. → T-2.1.4.
- **SR-115-2** (T1.2): reuse the same timeout/limit primitives for the HTTP download server. → T-2.1.4.
- **SR-115-3** (T2.6, TR-B): streaming assembly of the message and hand-off to Core without full buffering in memory. → T-2.1.2.

## US-2.2 — Fail-open / fail-closed
- **SR-116-1** (T2.2, T5.4): any parser/storage error/panic → the configured fail-open (accept) or fail-closed (tempfail 4xx); recover from a panic; the message is not lost; an audit event. → T-2.2.1.
- **SR-116-2** (T5.4): tests for both modes, including exceeding MIME limits and storage errors. → T-2.2.2.

## US-3.1 — MIME parser
- **SR-117-1** (T2.2): a tree depth limit and a total part-count limit (configurable); iterative or depth-guarded traversal; exceedance → the fail policy + audit. → T-3.1.1.
- **SR-117-2** (T2.3): a limit on total/per-header size and header count. → T-3.1.1.
- **SR-117-3** (T2.5): traversal of **all** leaf parts (inline and attachment), expanding `message/rfc822` one level within the limit. → T-3.1.1.
- **SR-117-4** (T2.1, T2.5): detect the real type by top-level magic bytes **without** recursive archive decompression in the MVP. → T-3.1.2.
- **SR-117-5** (T2.4): robust RFC 2231/2047 name decoding with a fallback, without panicking; sanitization (strip control characters, cap the length). → T-3.1.3.

## US-3.2 — MIME rewrite
- **SR-118-1** (T2.3): when adding `X-Attachra-Processed` and rewriting — strip CR/LF from any value taken from the message (anti header-injection). → T-3.2.1.
- **SR-118-2** (T1.5): a correct `Content-Disposition`/name per RFC 5987; the file name is data only, not a path. → T-3.2.1.

## US-4.1 — Policy Engine
- **SR-119-1** (T2.5, question #5): a safe policy default (an explicit decision — "replace everything" or "> N MB"); the default policy must not silently let attachments through. → T-4.1.1.

## US-5.1 — Storage (S3)
- **SR-121-1** (T3.1): objects are private, no public ACLs; access to the bytes only through the download endpoint (no direct presigned URLs to the client in the MVP). → T-5.1.2.
- **SR-121-2** (T3.3): support/documentation of SSE at-rest (SSE-S3/SSE-KMS); a hook for client-side encryption in the interface, without blocking the MVP. → T-5.1.2.
- **SR-121-3** (T3.2, T2.4): the object key is an opaque random ID (UUID), with no file name/sender/recipient; the name and addresses only in the metadata DB. → T-5.1.3.
- **SR-121-4** (T3.1): documented least-privilege IAM (the needed bucket, Get/Put/Delete/Stat, no public ListBucket). → T-5.1.3.

## US-5.2 — FS driver
- **SR-122-1** (T3.4): write only inside the base dir (`filepath.Clean` + a prefix check), reject on traversal, no following of symlinks; atomic write (temp+rename). → T-5.2.1.
- **SR-122-2** (T3.4): the driver contract test suite includes traversal/special-character cases. → T-5.2.2.

## US-5.3 — Retention
- **SR-123-1** (T3.5): retention in metadata (from policy/global). → T-5.3.1.
- **SR-123-2** (T3.5): background cleanup deletes the object **and** metadata consistently, idempotently, with an audit event. → T-5.3.2.

## US-6.1 — Link Engine / tokens
- **SR-124-1** (T1.1, TR-A): the link token ≥128 bit from `crypto/rand`, URL-safe. → T-6.1.1.
- **SR-124-2** (T1.1, TR-A): in the DB — a hash of the token (SHA-256), not the token itself; lookup by hash; a single response path for found/not found (no timing oracle). → T-6.1.3.
- **SR-124-3** (T3.2, T5.1): the DB model separates the object (random key) and metadata (name/sender/recipient); parameterized queries. → T-6.1.3.

## US-6.2 — Download endpoint
- **SR-125-1** (T1.2, TR-B): streaming from the StorageDriver without buffering; read/write/idle timeouts, a limit on concurrent connections and downloads per token. → T-6.2.1.
- **SR-125-2** (T1.4): the headers `Cache-Control: private,no-store,max-age=0`, `Pragma: no-cache`, `Expires: 0`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`, `X-Content-Type-Options: nosniff`. → T-6.2.1.
- **SR-125-3** (T1.4): two-step delivery for one-time links (the GET landing does not decrement the counter; delivery of bytes — by an explicit action), so preview bots do not consume the limit and do not cache the content. → T-6.2.1.
- **SR-125-4** (T1.5): `Content-Type` from the verified magic type (risky types → `application/octet-stream`); a correct RFC 5987 `Content-Disposition`; CSP on the endpoint pages; no redirects based on user input. → T-6.2.1.
- **SR-125-5** (T1.1, T1.3, T1.5): a single generic 404/410 page for "not found/expired/revoked/exhausted" without disclosing the reason; escaping of any reflected values; the reason goes only to the audit. → T-6.2.2.
- **SR-125-6** (T1.4): the download counter decrements atomically and only on actual delivery of bytes; idempotent on a duplicate preflight. → T-6.2.3.
- **SR-125-7** (T1.1, T1.2): per-IP + global rate limiting, backoff/tarpit on a burst of 404s. → T-6.2.4.

## US-6.3 — Link revocation
- **SR-126-1** (T3.5): an option for immediate deletion of the object on revocation. → T-6.3.1.
- **SR-126-2** (T5.2): an audit event on revocation (by link/message/sender). → T-6.3.2.

## ADR-011 — Database choice + related ADRs
- **SR-127-1** (T5.1): in ADR-011, pin the secure default DB configuration (TLS connection, least-privilege user, parameterized queries only). → ADR-011.
- **SR-127-2** (T3.3, question #3): a separate ADR on file encryption at rest (SSE vs client-side) — pin the decision before GA.

## US-7.1 — Audit
- **SR-128-1** (T5.2): an append-only event model; a hook for tamper evidence (a hash chain / record signing). → T-7.1.1.
- **SR-128-2** (T2.3, T5.2, TR-D): record events at all points (policy decision, download, revocation, errors, token/policy changes); untrusted values as JSON fields, without injection. → T-7.1.2.
- **SR-128-3** (T5.2): audit export to JSON lines for external immutable storage. → T-7.1.3.

## US-8.1 — REST API
- **SR-130-1** (T4.1): auth middleware, all resources behind auth except health and download; deny-by-default. → T-8.1.2.
- **SR-130-2** (T4.2, TR-A): API tokens — a hash in the DB, a one-time secret at creation, constant-time comparison, `Authorization: Bearer` (not the query), redaction in logs. → T-8.1.7 + T-8.1.2.
- **SR-130-3** (T4.1): admin/viewer roles, a check on every mutating endpoint (links revoke, policies reload, token mgmt). → T-8.1.3/T-8.1.5.
- **SR-130-4** (T4.3): pin the Bearer model and CORS policy (only trusted origins, not `*` with credentials); on a cookie session — SameSite + a CSRF token + an Origin check. → T-8.1.2.
- **SR-130-5** (T4.4): mandatory pagination and response-size limits on messages/attachments/audit; a rate limit on auth failures; timeouts; recovery middleware without leaking the trace. → T-8.1.4 + T-8.1.2.

## E10 / E11 — UI and deployment (future)
- **SR-110-1** (T4.3): when wiring in UI auth, use Bearer, not a cookie; otherwise — the full CSRF set. → T-10.0.2 (epic E10).
- **SR-111-1** (T5.3): secrets in Helm/compose — via Secret objects, not in plaintext values. → T-11.2.1 (epic E11).

## ADR-003 — WASI plugins (M4 icebox)
- **SR-003-1** (T6.1): pin the isolation model in ADR-003 — deny-by-default WASI capabilities (network/FS/env by allowlist), CPU/memory/time limits, minimal data passing, signing of Official/Verified plugins, audit of calls. A requirement for the ADR **before** the Plugin Loader is implemented.

---

## Coverage summary

| Story / area | Requirements |
|--------------|--------------|
| US-1.1 | 5 |
| US-2.1 | 3 |
| US-2.2 | 2 |
| US-3.1 | 5 |
| US-3.2 | 2 |
| US-4.1 | 1 |
| US-5.1 | 4 |
| US-5.2 | 2 |
| US-5.3 | 2 |
| US-6.1 | 3 |
| US-6.2 | 7 |
| US-6.3 | 2 |
| ADR-011 | 2 |
| US-7.1 | 3 |
| US-8.1 | 5 |
| E10 | 1 |
| E11 | 1 |
| ADR-003 | 1 |
| **Total** | **51 requirements across 18 stories/ADRs** |
</content>
