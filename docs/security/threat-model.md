# Attachra — Threat Model v1

Maintainer: security engineering.
Status: v1, written before the main code (M1). Updated with every major feature.

Scope: MVP — outbound mail through the Postfix Milter, extraction of attachments into
S3-compatible storage, replacement with personal links, the download endpoint,
the REST API, and audit. Future WASI plugins are covered briefly as requirements for ADR-003.

Method: STRIDE + ranking by (actor → vector → impact → likelihood). Likelihood and
impact use a Low/Medium/High/Critical scale. Each threat ends with a concrete code
requirement mapped to a backlog task.

The full "requirement → task" list for the backlog is in
`docs/security/requirements-for-backlog.md`.

---

## 0. Summary — Top 5 Risks

| # | Risk | Impact | Likelihood | Primary mitigation | Key tasks |
|---|------|--------|------------|--------------------|-----------|
| **R1** | Brute-forcing / enumeration of download tokens → access to other people's files | Critical | Medium | ≥128-bit `crypto/rand` tokens, hashes in DB, constant-time lookup, generic 404, rate limit + tarpit | T-6.1.1, T-6.2.2/6.2.4 |
| **R2** | Hostile MIME at the milter input (zip bomb, recursion, giant headers) → DoS/OOM of the entire mail flow | High | High | Hard depth/size/part limits BEFORE decompression, streaming parser, timeout, fail-open by default | T-3.1.1, T-2.1.4 |
| **R3** | Leakage of a file/link via caching by intermediate systems (CDN, corporate proxy, browser, messenger "preview" bots) | High | High | `Cache-Control: private,no-store`, single-use by counter, `Referrer-Policy`, a separate public host without cookies | T-6.2.1/6.2.3 |
| **R4** | Incorrect IAM permissions / shared bucket → reading other objects, listing keys with file names | High | Medium | Object keys carry no file name (random UUID), least-privilege IAM in docs, deny public ACL, SSE at-rest | T-5.1.3/T-5.1.2 |
| **R5** | Compromise/leak of an API token or config secrets → full control (revoke, read metadata, export audit) | High | Medium | Token hashes (not plaintext), admin/viewer roles, secrets from env/file kept out of logs, redaction on output | T-8.1.7/T-8.1.2, T-1.1.5 |

End-to-end invariant (a core security invariant): tokens use `crypto/rand` only, ≥128 bit,
stored as hashes, compared in constant time. Any processing error resolves to the
configured fail-open (accept) or fail-closed (tempfail); the message is never lost.

---

## 1. Public download endpoint

The only point reachable from the internet. It serves recipients (external,
unauthenticated). Maximum attack surface.

### T1.1 — Enumeration / brute-forcing of link tokens
- **Actor:** external anonymous / bot.
- **Vector:** mass brute-forcing of `GET /d/<token>`; sequential or dictionary tokens; timing attack on the comparison.
- **Impact (Critical):** access to other people's corporate attachments — a direct data leak that zeroes out the product's value.
- **Likelihood (Medium):** high with weak tokens; low with proper entropy.
- **Mitigation:**
  - token ≥128 bit from `crypto/rand`, URL-safe base64/base62;
  - the DB stores a **hash** of the token (SHA-256), not the token itself; lookup by hash;
  - the comparison/lookup does not depend on validity in a way that gives a timing signal (constant-time at the "found/not found" level — a single response path);
  - **generic 404/410** for "not found", "expired", "revoked", "exhausted" — a single page, without disclosing the reason to the unauthenticated client (details go only to the audit log);
  - per-IP rate limiting + a global one on the endpoint, exponential backoff/tarpit on a burst of 404s.
- **Requirement → task:** token generation and the Link model — T-6.1.1; hash storage and lookup — T-6.1.3; generic error pages — T-6.2.2; rate limit — T-6.2.4.

### T1.2 — DoS of the download endpoint
- **Actor:** external anonymous, botnet.
- **Vector:** request flood; slow connections (slowloris); requests for large files to exhaust bandwidth/sockets; range requests that force reopening the object.
- **Impact (High):** unavailability of legitimate downloads; indirectly — pressure on storage billing.
- **Likelihood (Medium):** a public host is always scanned.
- **Mitigation:**
  - read/write/idle timeouts on the HTTP server; a limit on concurrent connections;
  - streaming pass-through from the StorageDriver **without buffering in memory** (a core streaming invariant);
  - per-IP and global rate limit; a cap on concurrent downloads per token;
  - the response body size comes from metadata, not from an untrusted header.
- **Requirement → task:** streaming without buffering — T-6.2.1; timeouts / connection limits (reuse the milter limits) — T-2.1.4 + the HTTP layer T-6.2.1; rate limit — T-6.2.4.

### T1.3 — Metadata leakage via errors
- **Actor:** external anonymous, researcher.
- **Vector:** verbose errors (stack trace, on-disk path, object key, bucket name, software version, SQL error), different codes/timings for "expired" vs "does not exist".
- **Impact (Medium):** disclosure of the infrastructure, confirmation that a token exists (an oracle for enumeration).
- **Likelihood (Medium).**
- **Mitigation:**
  - error pages with no internal details; a single status for all "no access" states;
  - recovery middleware: a panic → 500 without leaking the trace outward, the full trace goes to the log;
  - the server banner/version is hidden or generalized.
- **Requirement → task:** error pages without leakage — T-6.2.2; recovery middleware — the shared HTTP scaffolding, applied to the download server too — T-8.1.2.

### T1.4 — Caching of links by intermediate systems
- **Actor:** not an attacker but infrastructure: CDN, corporate proxy, browser cache, "preview" bots (Slack/Teams/Telegram/WhatsApp expand a link and **download the file**), antivirus gateways, DLP.
- **Vector:** a link ends up in a cache and stays reachable after expiry/revocation; a preview bot spends the single allowed download (a false counter trigger); the file is cached on a shared proxy.
- **Impact (High):** bypass of revocation/TTL, leakage via cache, an "eaten" download — the file is unavailable to the real recipient; false audit records.
- **Likelihood (High):** messengers expand links automatically; this is the norm.
- **Mitigation:**
  - `Cache-Control: private, no-store, max-age=0`, `Pragma: no-cache`, `Expires: 0` on all download responses;
  - `Referrer-Policy: no-referrer`; `X-Robots-Tag: noindex, nofollow`; `X-Content-Type-Options: nosniff`;
  - a two-step download for one-time links: first a landing page (GET is safe, does not decrement the counter), the actual delivery — by an explicit action (POST/a signed step), so that HEAD/GET preview bots do not consume the limit and do not cache the content;
  - the download counter decreases **atomically and only on actual delivery of bytes**, idempotent on a duplicate preflight;
  - a separate public host for links (not the same as API/UI), without shared cookies — backlog open question #4.
- **Requirement → task:** cache headers and two-step delivery — T-6.2.1; a correct/idempotent counter — T-6.2.3; separate-host config — T-1.1.5 (open question #4).

### T1.5 — Security of error pages and content
- **Actor:** external anonymous; or sender abuse (a file name as a vector).
- **Vector:** XSS via reflecting a file name/token into the HTML error page or into `Content-Disposition`; content sniffing by the browser (an HTML file executes instead of downloading); an open redirect.
- **Impact (Medium):** XSS in the context of the public host, phishing via redirect.
- **Likelihood (Medium).**
- **Mitigation:**
  - HTML-escape any reflected values; better — static pages with no user data;
  - `Content-Disposition: attachment; filename*=UTF-8''...` with correct RFC 5987 encoding; `X-Content-Type-Options: nosniff`;
  - `Content-Type` from the verified magic-bytes type, not from the sender's claim; for risky types — `application/octet-stream`;
  - `Content-Security-Policy` on the endpoint's pages; no redirects based on user input (this closes SSRF-via-redirect from the agent spec).
- **Requirement → task:** safe `Content-Disposition`/`Content-Type` and security headers — T-6.2.1; escaping on error pages — T-6.2.2.

---

## 2. Milter input (hostile MIME)

The actor here is not always external: the message may be sent by an insider or a
compromised account. Attachra parses **untrusted content in the privileged mail flow**.

### T2.1 — Zip bombs and decompression bombs
- **Actor:** sender (insider/compromised) / external on inbound (future).
- **Vector:** an attachment whose decompression yields petabytes; nested archives.
- **Impact (High):** OOM/disk-full, process crash → processing of **all** outbound mail stops.
- **Likelihood (High)** if the product ever decompresses archives for detection.
- **Mitigation:**
  - **the MVP does not decompress archives** for type detection — detection is by top-level magic bytes only; record this as an explicit decision;
  - if decompression appears (inbound/plugins) — hard limits on uncompressed size and ratio, streaming reads with an abort on threshold.
- **Requirement → task:** type detection by magic bytes without recursive decompression — T-3.1.2; the limit is part of the Attachment/parser model — T-3.1.1.

### T2.2 — Recursive / infinite MIME nesting
- **Actor:** sender.
- **Vector:** deeply nested `multipart/*`, nested `.eml` (message/rfc822) many levels deep → exponential traversal, stack overflow.
- **Impact (High):** CPU exhaustion, stack overflow, milter session hang.
- **Likelihood (High):** trivial to construct.
- **Mitigation:**
  - a tree depth limit (e.g. ≤ 32) and a total part count limit (e.g. ≤ 1024) — configurable;
  - iterative (non-recursive) or depth-guarded traversal;
  - exceeding a limit → the fail-open/fail-closed policy, an audit event, the message is not lost.
- **Requirement → task:** depth/part-count limits in the MIME parser — T-3.1.1; mapping the exceedance to a milter response — T-2.2.1.

### T2.3 — Giant headers and header injection
- **Actor:** sender.
- **Vector:** megabyte-scale headers; thousands of headers; CRLF injection into a file name/parameters → forging the headers we add (`X-Attachra-Processed`) or injecting into a log/audit; smuggling via non-standard line breaks.
- **Impact (High):** parser DoS; header spoofing/forgery; log injection (audit corruption); detection bypass.
- **Likelihood (Medium/High).**
- **Mitigation:**
  - a limit on total/per-header size and header count;
  - when adding/rewriting headers — sanitization: strip CR/LF from any value taken from the message;
  - file names and any message-derived values that reach the audit are escaped (structured JSON log, not string concatenation);
  - strict boundary parsing, rejecting ambiguous structures.
- **Requirement → task:** header limits — T-3.1.1; safe writing of `X-Attachra-Processed` and rewriting — T-3.2.1; structured audit without injection — T-7.1.2.

### T2.4 — File-name encoding breaks (RFC 2047/2231)
- **Actor:** sender.
- **Vector:** broken/hostile encoded-words, mixed charsets, overlong UTF-8, path traversal (`../`, NUL, control chars) in the decoded name.
- **Impact (Medium/High):** policy bypass by extension/name; path traversal on write (especially the FS driver); UI/audit corruption.
- **Likelihood (Medium).**
- **Mitigation:**
  - robust RFC 2231/2047 decoding with a fallback, without panicking on broken input;
  - **the file name is metadata only**, never used as a path/key in storage (the key is a random UUID, see §3);
  - normalization/sanitization of the name before display and before storing metadata (strip control characters, cap the length).
- **Requirement → task:** the file-name decoder — T-3.1.3; name as metadata, key independent — T-5.1.3.

### T2.5 — Attachment detection bypass
- **Actor:** a sender who wants to exfiltrate a file around the policy.
- **Vector:** non-standard `Content-Type`/`Content-Disposition`; an attachment without a `filename`; an attachment inside `message/rfc822`; a false `Content-Transfer-Encoding`; a MIME part with an extension that does not match its content.
- **Impact (Medium):** the policy (block/replace) does not fire → the file leaves against the rules (a failure of the product's core function).
- **Likelihood (Medium).**
- **Mitigation:**
  - traversal of **all** leaf parts of the tree, not only those with `Content-Disposition: attachment` (inline too);
  - the decision is by the real type (magic bytes), not by the claimed one;
  - nested `.eml` are expanded one level (within the depth limit) for inspection;
  - the default policy is safe (open question #5: replace everything or > N MB — set an explicit default).
- **Requirement → task:** full tree traversal and the Attachment model — T-3.1.1; real type — T-3.1.2; a safe policy default — T-4.1.1.

### T2.6 — Resource exhaustion by a milter session
- **Actor:** sender / load.
- **Vector:** many concurrent sessions; a very large message entirely in memory; no session timeout.
- **Impact (High):** OOM, failure of the whole mail gateway.
- **Likelihood (Medium).**
- **Mitigation:**
  - a limit on concurrent milter connections, session timeouts, graceful shutdown;
  - streaming processing of the message body and files, without full buffering (invariant §4);
  - a global limit on message/attachment size from config.
- **Requirement → task:** connection limits and timeouts — T-2.1.4; streaming assembly of the message and hand-off to Core — T-2.1.2; a size limit in config — T-1.1.5.

### T2.7 — Detection bypass by masquerading as a structural message body
- **Actor:** a sender who wants to exfiltrate a file around the policy.
- **Vector:** a MIME part declared `Content-Type: text/plain`/`text/html`, without a `filename`, without an explicit `Content-Disposition: attachment` — structurally indistinguishable from the message body (`isStructuralBodyPart`), but the real bytes are arbitrary (e.g. a ZIP/executable).
- **Impact (High):** the first version of the protective fix (before architect+security review) fully excluded such parts from `policy.Evaluate` BEFORE sniffing — a silent bypass of both detected-type and `block` rules exactly where a sender would use it. That variant was rejected and is recorded here as a lesson.
- **Likelihood (Medium):** it requires understanding the engine's internal heuristic (documented publicly, open-core — ADR-004), but no special privileges.
- **Mitigation (adopted implementation):**
  - structural body parts go **fully** through `policy.Evaluate` — spool, sniff (`DetectType`), matching of any rules, like any other leaf of the tree (`pipeline.parseMessage`, no early filtering);
  - the protective layer (`pipeline.protectStructuralBodies`) downgrades **only** `replace` → `pass`, never touches `block`: an operator can write a rule `mime_type: ["application/zip"]` → `block`, and it fires even on a part declared `text/plain`;
  - the downgrade is observable: the `body_protected` key in the `policy_decision` audit event + a `body_protected` label on the `AttachmentsDecided` counter.
- **Requirement → task:** ADR-016 decision 2 (refined following review), the `pipeline.protectStructuralBodies`/`pipeline.parseMessage` implementation.

### T2.8 — Residual inline-protection bypass (ADR-016): polyglot image+zip in multipart/related
- **Actor:** a sender who knows the ADR-016 heuristic (the documentation is public, open-core).
- **Vector:** a polyglot file that is valid simultaneously as `image/*` by magic bytes (passes `DetectType`) and carries an arbitrary payload (e.g. a ZIP) further in the file; the part is tagged `Content-ID` inside `multipart/related` (i.e. classified as `InlineAsset`), size ≤ `limits.inline_max_size` (256 KiB by default).
- **Impact (Medium):** such a part passes as `pass` (not replaced with a link) instead of `replace` — the same would happen with a legitimate inline asset; this is not privilege escalation and not a loss of visibility for detected-type/`block` rules (T2.7 does not touch them), but specifically and only the skipping of link replacement for a ≤256 KiB file declared as an image.
- **Likelihood (Low/Medium).**
- **Mitigation:** accepted as a deliberate, documented residual bypass (ADR-016 §Consequences), not fully eliminated — full verification of the `cid:` reference from the HTML is deferred to phase 2 (see ADR-016 "Alternatives considered"). Boundaries: the downgrade is possible only when the DETECTED type is `image/*` (not the declared one) AND the size ≤ `limits.inline_max_size`; `block` is never downgraded (see T2.7); an operator with stricter requirements closes even this case with an explicit rule `when.attachment.disposition: ["inline"]` → `replace`/`block` (§2.3.2), which, thanks to `InlineOptIn`, fully disables the protective downgrade for the corresponding part.
- **Requirement → task:** ADR-016 §Consequences (accepted as an MVP limitation); the operator bypass — the documented `disposition` matcher.

---

## 3. Storage (object storage)

### T3.1 — Access to other people's objects
- **Actor:** external (on a bucket misconfig) / another tenant / an insider with storage access.
- **Vector:** a public bucket/ACL; predictable keys; reuse of a single bucket by several installations without isolation.
- **Impact (High):** direct reading of all files, bypassing Attachra and its revocations/TTL.
- **Likelihood (Medium).**
- **Mitigation:**
  - Attachra never sets public ACLs; objects are private;
  - access to the bytes is only through the download endpoint (Attachra proxies/streams); the client is not handed a presigned URL directly in the MVP (otherwise TTL/revocation/audit control is lost);
  - documented least-privilege IAM (only the needed bucket, only Get/Put/Delete/Stat), no ListBucket exposed outward.
- **Requirement → task:** private objects, access only through the endpoint — T-5.1.2; the key scheme / least-privilege in docs — T-5.1.3.

### T3.2 — Leakage of file names and metadata via object keys
- **Actor:** an insider with access to the bucket listing / S3 logs.
- **Vector:** an object key = `sender/recipient/filename.pdf` → the key reveals who sent what to whom, even without reading the content.
- **Impact (High):** leakage of sensitive metadata (who-to-whom-what) via storage listing/logs — critical for the product's privacy.
- **Likelihood (Medium).**
- **Mitigation:**
  - the object key is an **opaque random identifier** (UUID/random), with no file name, sender, recipient, or subject;
  - the file name, sender, recipient are only in the metadata DB (not in storage);
  - optionally — sharding by a random prefix, with no semantics.
- **Requirement → task:** a key scheme that discloses no names — T-5.1.3; separation of metadata and object — T-5.1.3 + the DB model T-6.1.3.

### T3.3 — No encryption at rest
- **Actor:** someone who gained access to the storage disks/backups.
- **Vector:** files sit in the clear on MinIO/FS/S3.
- **Impact (High):** content leakage on compromise of the storage/backup.
- **Likelihood (Low/Medium).**
- **Mitigation:**
  - MVP: enable SSE on the S3/MinIO side (SSE-S3/SSE-KMS), document it as a deployment requirement (open question #3);
  - FS driver: document filesystem/volume encryption as the admin's responsibility;
  - leave a hook for client-side encryption in the StorageDriver interface, without blocking the MVP.
- **Requirement → task:** SSE support/documentation in the S3 driver — T-5.1.2; the client-side-vs-SSE decision — a new ADR (open question #3), recorded as a note alongside ADR-011.

### T3.4 — Path traversal / unsafe write (FS driver)
- **Actor:** sender (via the file name) / the key logic.
- **Vector:** a file name or key with `../`, an absolute path, a symlink → write/read outside the directory.
- **Impact (High):** writing outside storage, overwriting files.
- **Likelihood (Low)** if the key is random, but check it explicitly.
- **Mitigation:**
  - the key = a random ID (not the file name), but the FS driver still validates: only inside the base dir, `filepath.Clean` + a prefix check, reject on traversal;
  - atomic write (temp + rename); no following of symlinks.
- **Requirement → task:** safe atomic write and traversal protection — T-5.2.1; the shared driver contract test includes traversal cases — T-5.2.2.

### T3.5 — Non-deletion on retention / leakage via "forgotten" objects
- **Actor:** a privacy violator / a compliance risk.
- **Vector:** expired files are not deleted; deletion of metadata without deleting the object (or vice versa) → "dangling" files.
- **Impact (Medium):** data lives longer than allowed, a violation of GDPR/policies.
- **Likelihood (Medium).**
- **Mitigation:**
  - background cleanup deletes **both** the object **and** the metadata consistently; idempotent; logged to the audit;
  - on link revocation — an option for immediate deletion of the object.
- **Requirement → task:** retention in metadata — T-5.3.1; consistent background cleanup — T-5.3.2; a revocation/deletion audit event — T-6.3.2.

---

## 4. REST API and tokens

### T4.1 — Token privileges / missing authorization
- **Actor:** external with a leaked token / an internal viewer trying to act as admin.
- **Vector:** a viewer calls revoke/reload/policy-change; no role check on an endpoint; IDOR (access to another message/link by ID).
- **Impact (High):** unauthorized revocation, policy changes, reading of other people's data.
- **Likelihood (Medium).**
- **Mitigation:**
  - admin/viewer roles, a check on every mutating endpoint (deny by default);
  - all resources behind the auth middleware; no "open" paths except health and download;
  - object-level authorization where multitenancy appears.
- **Requirement → task:** auth middleware and roles — T-8.1.2; role checks on links/policies/stats/audit — T-8.1.3/T-8.1.5/T-8.1.6.

### T4.2 — Unsafe token storage/comparison
- **Actor:** someone who gained access to the DB/logs.
- **Vector:** API tokens in plaintext in the DB or in logs; non-constant-time comparison; tokens in the URL (they land in proxy logs).
- **Impact (High):** mass compromise of access.
- **Likelihood (Medium).**
- **Mitigation:**
  - store a hash of the token (SHA-256/argon2 for long-lived ones), not plaintext; show the secret once at creation;
  - constant-time comparison; the token from `crypto/rand`;
  - the token is passed in the `Authorization: Bearer` header, not in the query; redaction of tokens in logs.
- **Requirement → task:** token generation/storage/revocation (hashes, one-time output) — T-8.1.7; auth middleware constant-time + redaction in logs — T-8.1.2.

### T4.3 — CSRF for the future Web UI
- **Actor:** an external site attacking a logged-in admin.
- **Vector:** if the UI uses a cookie session — a cross-site request to a mutating endpoint.
- **Impact (Medium/High):** revocation/policy change on behalf of the admin.
- **Likelihood (Medium)** once the UI appears (E10).
- **Mitigation:**
  - prefer `Authorization: Bearer` authentication (not a cookie) — CSRF is inapplicable;
  - if a cookie session is unavoidable — `SameSite=Strict/Lax`, a CSRF token on mutating requests, an Origin/Referer check;
  - CORS: allow only trusted origins, not `*` for an API with credentials.
- **Requirement → task:** pin the Bearer model and the CORS/CSRF policy in the HTTP scaffolding — T-8.1.2; account for it when wiring in UI auth — T-10.0.2 (epic E10).

### T4.4 — DoS / no limits on the API
- **Actor:** an authenticated but abusive client; or token brute-forcing on auth.
- **Vector:** heavy requests (export of the entire audit, search without pagination); brute-force of an API token.
- **Impact (Medium).**
- **Mitigation:** mandatory pagination; response-size limits; a rate limit on auth failures; timeouts.
- **Requirement → task:** pagination on messages/attachments — T-8.1.4; a shared rate limit/timeouts in the middleware — T-8.1.2.

---

## 5. Internal surfaces

### T5.1 — Metadata DB (injections, access)
- **Actor:** via untrusted input from the message reaching queries; an insider with DB access.
- **Vector:** SQL injection via file name/address/subject; an unencrypted DB connection; excessive DB-user privileges.
- **Impact (High):** leakage/corruption of all metadata and link relationships.
- **Likelihood (Low/Medium).**
- **Mitigation:**
  - only parameterized queries / prepared statements (no concatenation);
  - least-privilege for the DB user; TLS to the DB in docs;
  - the DB choice and its secure default configuration are part of ADR-011.
- **Requirement → task:** the link DB schema and access — T-6.1.3; the audit schema — T-7.1.1; the DB choice — ADR-011.

### T5.2 — Integrity of the audit log
- **Actor:** an insider/attacker covering their tracks; log injection from a message.
- **Vector:** editing/deleting audit records; injecting forged lines via untrusted values (see T2.3); missing capture of key events.
- **Impact (High):** inability to investigate, failure of a compliance audit (a key value for the security officer).
- **Likelihood (Medium).**
- **Mitigation:**
  - structured events (JSON), message-derived values as field data, not as raw text (no injection);
  - an append-only model; an option to export to immutable storage (JSON lines);
  - capture all critical points: policy decision, download, revocation, processing errors, token/policy changes;
  - (v1+) consider a hash chain / record signing for tamper evidence — as a requirement for the audit schema.
- **Requirement → task:** an append-only event model + a tamper-evidence hook — T-7.1.1; recording at all points without injection — T-7.1.2; JSON-lines export — T-7.1.3; revocation audit — T-6.3.2.

### T5.3 — Config with secrets
- **Actor:** someone reading the logs/dumps/repository/container environment variables.
- **Vector:** secrets (S3 creds, DB token, keys) in YAML in git, in logs at startup, in error messages; secrets in the Docker image.
- **Impact (High):** compromise of storage and DB.
- **Likelihood (Medium).**
- **Mitigation:**
  - secrets from env/a file with restricted permissions; support for `${ENV}` substitution, not hardcoding;
  - config validation at startup **without** printing secrets; redaction of secrets in any output/log;
  - `.gitignore` for local configs with secrets; an example config without real values;
  - in Helm/compose — secrets via Secret objects, not in plaintext values.
- **Requirement → task:** loading/validating config without leaking secrets, env substitution, redaction in logs — T-1.1.5; a structured log without secrets — T-1.1.6; secrets in Helm — T-11.2.1 (epic E11).

### T5.4 — Integrity of the "no message is lost" pipeline
- **Actor:** not an attacker — this is a reliability invariant with security consequences.
- **Vector:** an error/panic in the parser/storage leads to losing a message or to silently skipping an attachment around the policy.
- **Impact (High):** mail loss or policy bypass (a file left without processing).
- **Mitigation:**
  - any error → the configured fail-open (accept unchanged) or fail-closed (tempfail), explicitly, with an audit event;
  - recover from a panic in the milter session;
  - fail-closed must actually tempfail (4xx), not lose the message.
- **Requirement → task:** mapping Core errors to milter responses + recover — T-2.2.1; tests for both modes — T-2.2.2.

---

## 6. Future WASI plugins (briefly, requirements for ADR-003)

Plugins (LDAP, VirusTotal, YARA, OCR, integrations) execute third-party code next to
the mail flow. Post-MVP (icebox), but the isolation boundaries must be pinned in ADR-003
**before** the Plugin Loader is implemented, otherwise security will have to be retrofitted.

### T6.1 — Sandbox escape / excessive capabilities
- **Actor:** a malicious/vulnerable community plugin.
- **Vector:** the plugin gets access to the host FS/network/memory; reads other people's files, exfiltrates attachments, DoSes the host.
- **Impact (Critical):** full compromise of the confidentiality of the processed files.
- **Mitigation (requirements for ADR-003):**
  - WASI with **deny-by-default** capabilities: an explicit allowlist for network/FS/env access, no ambient authority;
  - CPU/memory/time limits per plugin call; abort on timeout; no access to the host FS except what is explicitly passed through;
  - only dedicated, minimal data is passed to the plugin (not the whole message unnecessarily);
  - signing/verification of Official/Verified plugins (ADR-005 marketplace); community — with an explicit trust warning;
  - audit of plugin calls and their network requests.
- **Requirement → task:** pin the isolation model (capabilities, limits, signing) as a section of **ADR-003** before the Plugin Loader (M4 icebox). Tracked as a follow-up that references this threat model §6.

---

## 7. Cross-cutting requirements (apply to many tasks)

- **TR-A. crypto/rand ≥128 bit + hash in DB + constant-time** — link tokens (T-6.1.1) and API tokens (T-8.1.7). A core security invariant.
- **TR-B. Streaming processing without full buffering** — milter (T-2.1.2), download (T-6.2.1), storage. A core streaming invariant.
- **TR-C. Fail-open/fail-closed on any error, no message is lost** — T-2.2.1/T-2.2.2. A core reliability invariant.
- **TR-D. Untrusted values from a message — always as data, never as code/path/log line** — MIME (T-3.1.*), storage keys (T-5.1.3), audit (T-7.1.2), headers (T-3.2.1).
- **TR-E. Secrets never in logs/git/errors** — config (T-1.1.5/T-1.1.6), Helm (T-11.2.1).
- **TR-F. Secure SDLC:** secret scanning and dependency scanning in CI — add to the CI pipeline (T-1.1.4) together with DevOps.

---

## Appendix: threat summary matrix

| ID | Surface | Threat | Impact | Likelihood | Tasks |
|----|---------|--------|--------|------------|-------|
| T1.1 | Download | Token enumeration | Critical | Medium | T-6.1.1/6.1.3, T-6.2.2/6.2.4 |
| T1.2 | Download | Endpoint DoS | High | Medium | T-6.2.1/6.2.4, T-2.1.4 |
| T1.3 | Download | Leakage via errors | Medium | Medium | T-6.2.2, T-8.1.2 |
| T1.4 | Download | Caching / preview bots | High | High | T-6.2.1/6.2.3, T-1.1.5 |
| T1.5 | Download | XSS/sniffing/redirect | Medium | Medium | T-6.2.1/6.2.2 |
| T2.1 | Milter | Zip bombs | High | High | T-3.1.2/3.1.1 |
| T2.2 | Milter | Recursive nesting | High | High | T-3.1.1, T-2.2.1 |
| T2.3 | Milter | Giant headers / injection | High | Med/High | T-3.1.1, T-3.2.1, T-7.1.2 |
| T2.4 | Milter | File-name encoding breaks | Med/High | Medium | T-3.1.3, T-5.1.3 |
| T2.5 | Milter | Attachment detection bypass | Medium | Medium | T-3.1.1/3.1.2, T-4.1.1 |
| T2.6 | Milter | Session resource exhaustion | High | Medium | T-2.1.4/2.1.2, T-1.1.5 |
| T2.7 | Milter | Detection bypass via message body | High | Medium | T-3.1.* (ADR-016 decision 2) |
| T2.8 | Milter | Polyglot image+zip in inline protection | Medium | Low/Med | ADR-016 §Consequences |
| T3.1 | Storage | Access to other people's objects | High | Medium | T-5.1.2/5.1.3 |
| T3.2 | Storage | Name leakage via keys | High | Medium | T-5.1.3, T-6.1.3 |
| T3.3 | Storage | No encryption at rest | High | Low/Med | T-5.1.2, ADR (question #3) |
| T3.4 | Storage | Path traversal (FS) | High | Low | T-5.2.1/5.2.2 |
| T3.5 | Storage | Retention / forgotten objects | Medium | Medium | T-5.3.1/5.3.2, T-6.3.2 |
| T4.1 | API | Privileges / IDOR | High | Medium | T-8.1.2/8.1.3 |
| T4.2 | API | Token storage/comparison | High | Medium | T-8.1.7/8.1.2 |
| T4.3 | API | CSRF (future UI) | Med/High | Medium | T-8.1.2, T-10.0.2 |
| T4.4 | API | DoS / no limits | Medium | Medium | T-8.1.4/8.1.2 |
| T5.1 | Internal | DB injections / access | High | Low/Med | T-6.1.3, T-7.1.1, ADR-011 |
| T5.2 | Internal | Audit integrity | High | Medium | T-7.1.1/7.1.2/7.1.3, T-6.3.2 |
| T5.3 | Internal | Secrets in config | High | Medium | T-1.1.5/1.1.6, T-11.2.1 |
| T5.4 | Internal | Message loss / policy bypass | High | — | T-2.2.1/2.2.2 |
| T6.1 | WASI | Sandbox escape | Critical | — | ADR-003 (M4) |
</content>
</invoke>
