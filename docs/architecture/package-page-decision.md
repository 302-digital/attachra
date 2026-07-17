# Attachra — Design Decision: the "package" page for messages with multiple attachments

- **Task:** design control point for T-3.2.x / T-6.x
- **Status:** Draft, for team review
- **Author role:** atr-architect
- **Related ADRs:** ADR-002 (Core has no knowledge of Postfix), ADR-006 (policies must be readable by a business user), ADR-011 (metadata database), ADR-009 (product philosophy)
- **Related stories:** US-3.2 (body rewrite, replacement block), US-6.1 (personal links), US-6.2 (download endpoint)
- **Related documents:** `policy-format-v1.md` §3.4 (worst-case, per-recipient tokens, open question #2), `threat-model.md` T1.1/T1.4 (enumeration, cache/preview bots, SR-125-3 two-step delivery); competitor products (e.g. mxHERO) ship redundant copies

This document settles **one question**: when a message contains several attachments matched by `replace`, what gets inserted into the rewritten body — N separate links, one "package" page per message, or a hybrid. This decision does **not** change the policy format (`replace` per-attachment, worst-case across recipients) — it only changes how the result is presented to the recipient and how the download layer is structured.

Terminology: **token** — a secret of ≥128 bits per (attachment × recipient) pair; the US-6.1 invariant — link tokens are `crypto/rand`-generated, ≥128-bit secrets, stored as hashes rather than tokens (technical invariant #5) — is preserved across every option. **Link** — the URL inserted into the body. **Package page** — the download service's HTML landing page that lists all `replace`-matched attachments of a message for a given recipient.

---

## 1. Context and constraints (what makes this question non-trivial)

1. **One milter body for all recipients (policy §3.4).** `replacebody` rewrites the single MIME body once; Postfix delivers it to every RCPT TO. It is physically impossible to insert different URLs for different people within a single transaction. Token personalization is achieved **not** through a unique URL in the body, but through recipient identification on the download-service side. This is open question #2 of the policy format — and this decision closes it for the MVP (see §5).

2. **Two-step delivery is mandatory (threat-model T1.4 / SR-125-3).** Messenger preview bots (Slack/Teams/Telegram/WhatsApp) unfurl a link and **download the file** automatically. Therefore:
   - GET on the link from the body = a **safe landing page**: the `max_downloads` counter is not decremented, content is not served or cached;
   - actual byte delivery happens only on an **explicit action** (POST / a signed second step);
   - the counter is decremented atomically, and only on byte delivery, idempotently against a duplicate preflight request.
   This means: **we already have a landing page in every case**, even for a single file. The only question is whether the landing page is for a file or for a message.

3. **Personal revocation and per-attachment×recipient audit (US-6.1, threat-model T5.2).** Revocation "by link / by message / by sender" (US-6.3) and download auditing must work at the granularity of an individual file for an individual recipient. Any option that collapses this granularity is a blocker.

4. **Readability of the replacement block (US-3.2, ADR-009).** The block is inserted into both text/plain and text/html. It must render acceptably in Gmail/Outlook/Thunderbird and on mobile. N raw URLs in text/plain is visual noise (this is exactly what the industry critique of "a wall of links" points at; mxHERO markets itself against "6,000 redundant copies" rather than against link count specifically — but the UX complaint about a wall of links is real, and is confirmed by the fact that vendors such as ShareFile and mxHERO collapse attachments into a compact representation).

5. **MVP complexity and DB schema (ADR-011).** The base DB entity per threat-model T3.2/T5.1 and US-6.1 is `link (message × attachment × recipient)`. The question: does this need an **additional** "package" entity, or is a package simply a *query* over the existing `link` rows?

**Key observation that dissolves the false dilemma:** since two-step delivery (SR-125-3) already requires a landing page for every link, a "package page" is **not new infrastructure** — it is just the mandatory landing page consolidated from "one file" granularity up to "one message for one recipient" granularity. The cost of a package, relative to the landing page we already need, is **low**.

---

## 2. Options considered

### Option (a): N separate links in the replacement block

Each `replace`-matched attachment → a separate URL in the body (`/d/<token>`), N links for N files. Each leads to its own single-file landing page (step 1) → delivery (step 2).

**How personalization works with a single body:** the token in the URL cannot be personal (the body is shared). So either (1) the body carries a "shared" pointer, and the personal token is chosen on the download service based on recipient identification — but then the URL itself carries no personalization in the body; or (2) we accept that the URL in the body is not personalized, and personal tokens exist only for revocation/audit purposes (policy §3.4 option b). With N links, recipient identification is still needed on the landing page — so a landing page with recipient identification shows up here too.

### Option (b): one "package" page per message

A **single** link to the message's package page is inserted into the body. The page (after recipient identification, §5) lists every `replace`-matched attachment of that message and offers a download button for each. Tokens remain per-attachment×recipient — they "live" on `link` records; the page merely aggregates them into a view.

### Option (c): hybrid (1 file → direct link to a single-file landing page; 2+ → package)

A threshold on the number of `replace`-matched attachments in a message: 1 → single-file landing page (as in (a) for a lone file), ≥2 → package page (as in (b)).

---

## 3. Evaluation against criteria

| Criterion | (a) N links | (b) Package | (c) Hybrid |
|---|---|---|---|
| **Recipient UX, desktop** | A wall of URLs at 3+ files; every click is a separate navigation | One click → one clear page with a list | Optimal: 1 file with no extra page, many files grouped |
| **Mobile UX** | Poor: long URLs wrap, tapping the right one is hard | Good: one link, a vertical list of buttons | Good |
| **Block readability (text/plain)** | Worst: N bare URLs, grows with file count | Best: one link line + a text list of file names | Best at 2+, minimal at 1 |
| **Block readability (text/html)** | Medium: a list of links | Good: one CTA link | Good |
| **Per-attachment revocation** | Preserved (token per file) | **Preserved** (tokens per file, the page only aggregates) | Preserved |
| **Per-attachment audit** | Preserved | **Preserved** (a download is counted by the file's token, not the page) | Preserved |
| **Partial revocation / partial expiry** | A dead link = a generic 404 (T1.3); other links stay alive, but the recipient has no context | The page shows live files as buttons, revoked/expired ones as inactive with neutral wording; **best degradation UX** | Same as (b) at 2+ |
| **SR-125-3 (preview-bot burn)** | Works, but: a preview bot unfurls **each** of the N links → N safe landing pages (step 1 is safe — fine); the risk is that each link is a separate point where it's easy to slip up and serve bytes on GET | **Works and is easier to audit**: one link in the body → one landing page unfurled by the bot → step 1 is safe, no file counters are touched; delivery only on an explicit POST from the page | Works; for 1 file, same as (a); for 2+, same as (b) |
| **MVP implementation complexity** | Looks low at first glance, but the landing page + recipient identification are needed anyway | Medium: one page with a list (data from a `link` query by message×recipient) | **Higher**: two code paths for templating and routing, a threshold, tests for both |
| **Impact on the DB schema (ADR-011)** | The `link` entity per attachment×recipient is enough | **The `link` entity is enough**; "package" = the query `WHERE message_id=? AND recipient_id=?`, no separate table needed | The `link` entity is enough; branching lives in the presentation layer |

---

## 4. Decision

**Option (b) is chosen: one "package" page per message for the recipient. A single path for both one attachment and many — no hybrid branching in the MVP.**

Rationale for choosing (b) over (c): the hybrid gives a marginally "cleaner" UX for messages with exactly one file (no intermediate page with a single-item list), but at the cost of two code paths in the most sensitive area (body rewrite + download endpoint), two sets of templates, and doubled testing of SR-125-3. Since **two-step delivery (SR-125-3) already forces us to show a landing page even for a single file**, the "direct link to the file" of option (a)/(c) is an illusion: a single file still opens a landing page (step 1) rather than starting a download. The difference between "a single-file landing page" and "a package page with one item" is cosmetic (a heading, and a list of length 1), and doesn't justify two code paths. A single path: **one template, one route, one set of security tests, one DB model.** The (c) hybrid threshold remains a documented post-MVP option if UX measurements show that a one-item page is annoying (see §7).

Rationale over (a): (a) loses on block readability (a wall of URLs), on mobile UX, on degradation UX under partial revocation, and it **does not simplify** the implementation, because recipient identification and the two-step landing page are needed regardless. The one advantage of (a) — "no intermediate page" — is nullified by the SR-125-3 requirement.

### 4.1 How it works (normative for implementation)

1. **Message body (T-3.2.2).** A **single** link of the form `https://<download-host>/p/<message-link-token>` (p = package) is inserted into the rewritten body. Plus a text list of the replaced file names (for the recipient's context, without links). The token in the body URL is **not** a personal file secret (the body is shared by all recipients) but an **unguessable message identifier** (also ≥128 bits from `crypto/rand`, generic 404 on a miss — T1.1). Personal file tokens never appear in the body.

2. **Recipient identification (closing open question #2 of policy §3.4).** MVP: the package page is opened via `/p/<message-link-token>`; since the body is shared, the page **cannot tell from the URL alone** which of the RCPT TO recipients opened it. For the MVP we adopt **model b from policy §3.4**: the package page is identical for every recipient of the message (it lists the message's replaced files), while **personal tokens per attachment×recipient pair exist at the DB level** for targeted revocation and audit, but which recipient's token is used at download time is not distinguished by the body in the MVP. The "download file X" button leads to delivery keyed by the file's token; in the MVP, one set of file tokens is generated per message, tied to the message-link record, and **every recipient who opens the page uses the same tokens** — revocation at the message level and at the file level both work, but targeted revocation ("revoke only for Alice, keep it for Bob") is **not guaranteed at the delivery layer** in the MVP (the body is shared — Alice and Bob received the same URL). This is a **deliberate MVP limitation**, the same one already stated in policy §3.4/§8.2 #2. Full per-recipient personalization of the body URL is deferred to the SMTP-proxy adapter (where delivery to each recipient is controlled individually) — at that point the package page becomes personal without changing the format.

   > Note for security review: this does not weaken enumeration protection (tokens remain ≥128 bits, generic 404). It only limits **revocation targeting at the transport level** in the milter MVP — a limitation already fixed by the policy format, not a new one.

3. **Download endpoint (T-6.2.1), two-step model (SR-125-3):**
   - `GET /p/<message-link-token>` → **the package page (step 1, safe)**: an HTML list of the message's files, each with a name, size, and status (available / expired / revoked / limit reached — worded neutrally, without leaking the reason externally; details go only to the audit log, T1.3). No bytes are served, `Cache-Control: private, no-store`, counters are untouched. A preview bot that unfurls the link only ever gets this page — file limits stay intact.
   - Downloading a specific file is **step 2, an explicit action**: `POST /p/<message-link-token>/d/<attachment-ref>` (or a signed one-time form submitted from the page). Only here is the file streamed from the StorageDriver without buffering, and only here is that file's `max_downloads` atomically decremented, idempotently against a duplicate preflight.
   - All security headers (T1.5): `Content-Disposition: attachment; filename*=UTF-8''…`, `X-Content-Type-Options: nosniff`, `Content-Type` from the real magic-detected type, `Referrer-Policy: no-referrer`, CSP on the page.

4. **DB schema (T-6.1.3, ADR-011).** **No new "package" entity is introduced.** It's enough to have:
   - `message_link` — one record per message (for the body's `/p/<token>` token: stores the token **hash**, `message_id`, expiry, status). This is a thin new record, not a "package as a file aggregate".
   - `link` — the existing entity for the **(message_id, attachment_ref, recipient)** tuple: personal token hash, TTL, `max_downloads`, counter, status (active/revoked/expired), file metadata (name, size — in the DB, not in the object key, T3.2), storage object key (random UUID).
   - The "package" shown on the page is `SELECT … FROM link WHERE message_id = ?` (+ a recipient filter once per-recipient delivery exists). Revoking a whole message (US-6.3) = a status update by `message_id`, cascading to `message_link` and every `link`. Per-attachment revocation = a status update on a single `link` record. **Revocation and audit granularity does not degrade** — it lives on `link`; the page only reads.

   > **Recipient isolation update.** The recipient filter this item anticipates is now implemented, ahead of full per-recipient body delivery: `link.Engine.ListPackageFiles` and `RegisterPackageDownload` scope by `link.recipient == message_link.recipient` (filtered in the Engine, no `store.MetadataStore` schema/interface change). This does **not** change the MVP limitation in item 2 above — every recipient of a message still receives the same body URL, so the *same* `message_link` row (and hence the same recipient's own `link` rows) is what every actual clicker sees and charges regardless of who they are. What it closes is a distinct bug: before this fix, `ListLinksByMessage`'s unfiltered result let that one shared package token additionally see and drain the download budget of *other* recipients' orphaned `link` rows (the ones `CreateLinks` still persists per (attachment, recipient) pair but whose own token never ships in the shared body) — a composition-leak and shared-budget-exhaustion risk, not the deliberate per-recipient-targeting limitation this section already accepts.

### 4.2 What stays unchanged

- The policy format (`replace` per-attachment, worst-case §3.4) — untouched.
- The token invariant (≥128 bits / hashes in the DB / generic 404 / constant-time comparison) — applies to every token (both `message_link` and `link`).
- Streaming delivery without buffering, fail-open/fail-closed on errors.
- Per-attachment revocation and audit granularity.

---

## 5. Rejected options (with rationale)

1. **(a) N separate links in the body.** Rejected: worst readability of the replacement block (a wall of URLs, growing with file count), worst mobile UX, worst degradation under partial revocation (a dead link = a generic 404 with no context), and — critically — **it does not save on complexity**, because the two-step landing page and recipient identification are needed here too (SR-125-3). The one advantage — "no intermediate page" — is nullified by the mandatory landing page.

2. **(c) Hybrid with a 1 vs 2+ threshold.** Rejected for the MVP: the marginal UX gain on single-file messages doesn't pay for two code paths in critical areas (body rewrite and the download endpoint), two template sets, and doubled security testing of SR-125-3. Kept as a **post-MVP option** (§7) if UX feedback calls for it.

3. **A personal URL per recipient directly in the body (full personalization in the milter MVP).** Rejected: not reliably possible with a single milter body (policy §3.4, §8.2 #5). Deferred to the SMTP-proxy adapter. Does not block this decision.

4. **A separate "package" aggregate table in the DB.** Rejected: violates the principle of "don't abstract without a second implementation" — a package is fully expressible as a query by `message_id`. Only a thin `message_link` for the body token is introduced, which is not the same as a file-aggregate table.

5. **Presigned URLs directly in the body (bypassing our endpoint).** Rejected (already covered in threat-model T3.1): loses control over TTL/revocation/audit/two-step delivery. All bytes flow only through our download endpoint.

---

## 6. Impact on tasks and acceptance-criteria updates

Below are **concrete edits/additions to acceptance criteria** to be applied to the tracked tasks (the orchestrator applies them in the issue tracker).

### T-3.2.2 (US-3.2) — Replacement-block templates

- The body gets **one** link to the message's package page (`/p/<token>`), **not** a link per attachment.
- The replacement block (text/plain and text/html) lists the names of the replaced files **as text** (for context), but there is only one clickable link — to the package page.
- The token in the body URL comes from `crypto/rand`, ≥128 bits; only the URL itself appears in the body (no personal file secrets).
- The template renders correctly in Gmail/Outlook/Thunderbird and on mobile for both 1 and N replaced files (a single template, no branching by file count).
- The built-in English template covers both the "files are available at this link" text and the file-name list; additional locales can be added via the templates directory (`TextTemplatePath`/`HTMLTemplatePath` overrides).

### T-6.2.1 (US-6.2) — Download HTTP server, streaming

- The endpoint implements the **two-step model for the package page** (SR-125-3): `GET /p/<token>` returns the HTML package page (step 1, safe, no byte delivery, no counter decrement, `Cache-Control: private,no-store`); file delivery only happens on an explicit `POST /p/<token>/d/<attachment-ref>` action (step 2).
- The package page lists every `replace`-matched attachment of the message with its status (available / unavailable, worded neutrally); unavailable ones (expired/revoked/limit reached) are shown inactive without leaking the reason externally (details go to the audit log, T1.3).
- The `max_downloads` counter is decremented atomically and idempotently **at the individual-file level** (not the package level), only on actual byte delivery in step 2.
- Streaming from the StorageDriver without in-memory buffering; security headers (T1.5) on delivery.
- A preview bot unfurling the link (GET) does not consume any file's limit and does not serve content — covered by a test.

### T-6.1.3 (US-6.1, ADR-011) — DB schema

- The schema includes a **`link` entity for the (message_id, attachment_ref, recipient) tuple**: personal token hash, TTL, max_downloads, counter, status, file metadata (name/size in the DB, not in the object key), storage key (random UUID).
- A thin **`message_link`** entity (per message) is added for the package-page token: hash of the `/p/<token>` token, `message_id`, expiry, status. **No separate "package" aggregate table is created** — the package view is assembled by querying `link` by `message_id`.
- Revoking "the whole message" (US-6.3) is implemented as a cascade by `message_id` (updating `message_link` plus every `link`); per-attachment revocation updates a single `link` record. Revocation/audit granularity is preserved on `link`.
- All tokens (both `message_link` and `link`) are stored as hashes (SHA-256), looked up by hash, with a constant-time response path and a generic 404 (T1.1).

### Adjacent tasks (notify, no acceptance-criteria changes needed)

- **T-6.2.2** (error pages): the "expired/revoked/limit reached" statuses are now also shown **inside** the package page (per file), not only as a separate error page — account for this in the layout.
- **T-6.3.1** (revocation): the "whole message" cascade relies on `message_id` — compatible, no separate package entity needed.
- **T-3.2.3** (client rendering checks): the checklist now verifies the single-link-plus-text-list block rendering for both 1 and N files.

---

## 7. Open questions / post-MVP

1. **The (c) hybrid threshold as a post-MVP improvement.** If UX measurements show that a package page with a single file is annoying, introduce a special case: "1 file → direct file landing page." Deferred; a single path in the MVP.
2. **Full per-recipient personalization of the package page** — pending the SMTP-proxy adapter (policy §8.2 #5). At that point `/p/<token>` becomes personal to the recipient without changing the policy format or the replacement block.
3. **Parameter conflicts under worst-case replace** (different TTL/max_downloads for different recipients, policy §4/§8.2 #3) — inherited from the policy format, unchanged by this decision; in the MVP, one set of file tokens per message uses the most restrictive parameters.
4. **A separate public host** for `/p/` and `/d/` (threat-model T1.4, backlog open question #4) — a config concern, does not affect the choice of package.
