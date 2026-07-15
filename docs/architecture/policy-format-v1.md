# Attachra — Policy Format Specification v1

- **Task:** T-4.1.1 (story US-4.1)
- **Status:** Draft, for team review
- **Author role:** atr-architect
- **Related ADRs:** ADR-006 (policies are declarative, readable by a business user), ADR-002 (Core has no knowledge of Postfix)
- **Related stories:** US-4.1 (conditions/actions), US-4.2 (hot reload, dry-run, validation), US-6.1 (TTL/max_downloads from policy), US-5.3 (retention from policy)

This document describes the **policy file format**, not the execution engine. The parser/matcher/executor implementation is covered by tasks T-4.1.2..T-4.1.5. Field names and YAML examples are English-only (a project-wide invariant); explanatory prose is in English throughout this document.

---

## 1. Overview

Attachra applies one of three actions to every outbound attachment: `pass` (leave it as is), `replace` (upload it to storage and swap it for a personal link), `block` (reject the message). Which action applies is decided by a **policy**: an ordered list of `when → then` rules, evaluated with a **first-match-wins** model and a mandatory `default` branch.

Key design goals:

1. **Readable by a business user (ADR-006).** A security officer with no programming skills must be able to read and edit the rules. Hence: flat conditions, self-explanatory names, no embedded logic/expressions/scripting in v1.
2. **Determinism.** Rule order defines priority. The first rule that matches wins; later rules are not considered. There is always a `default`.
3. **Extensibility without breakage.** An explicit `version:` field, plus the rule "an unknown top-level field is an error, but reserved sections are known-forward." Future concepts (time, geography, download count, LDAP/AD groups, storage tags) are added as new keys inside `when`/`then` without changing v1 semantics (see §7).
4. **Secure by default.** An invalid policy is **not applied** (US-4.2): the engine keeps running the last valid policy. No match → `default`. A policy-evaluation error → the global fail-open/fail-closed setting from config (a project-wide technical invariant), which the policy cannot override in v1.

A "fits on one screen" example — a fully readable policy:

```yaml
version: 1
name: "Default corporate policy"

rules:
  - name: "Internal mail passes through"
    when:
      recipient:
        domain: ["example.com"]
    then:
      action: pass

  - name: "Large attachments become links"
    when:
      attachment:
        size: { min: "10MB" }
    then:
      action: replace
      ttl: "30d"

default:
  action: pass
```

---

## 2. Schema

### 2.1 Document top level

One file = one policy (one YAML document). Multi-document files (`---`) are not supported in v1 — the validator rejects a second document.

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | integer | yes | Major version of the format. For this spec — `1`. See §7.1. |
| `name` | string | yes | Human-readable policy name (for logs, audit, UI). |
| `description` | string | no | Free-form text. |
| `rules` | list | yes (may be empty) | Ordered list of rules. Evaluated top to bottom. |
| `default` | object (action block) | yes | Action to apply when no rule matched. |
| `metadata` | map | no | Reserved (§7.2): arbitrary key-value pairs, ignored by the engine (authorship, pack tags, a link to a compliance requirement). |
| `defaults` | object | no | Reserved (§7.2): default values for action parameters (e.g. a shared `ttl`) inherited by rules. Parsed in v1 but has no effect on behavior unless set. |

Any **other** top-level key → a validation error (`unknown top-level field`). This guards against typos (`rule:` instead of `rules:`), but the list of reserved keys (`metadata`, `defaults`) is already "known" to the parser and is not treated as a typo.

### 2.2 Rule (`rules[]`)

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Rule name. Required — it shows up in audit/dry-run output ("rule X matched"). |
| `description` | string | no | Human-readable explanation. |
| `when` | object (condition block) | no | The condition. **A missing `when` always matches** (catch-all). |
| `then` | object (action block) | yes | What to do on a match. |
| `disabled` | bool | no | `true` — the rule is skipped (a soft disable without deleting it). Defaults to `false`. |

### 2.3 Condition block (`when`)

`when` is an **AND across sections**: a rule matches only if ALL present sections match (`sender` AND `recipient` AND `attachment`). A missing section does not narrow the condition. The v1 sections:

| Section | Purpose |
|---|---|
| `sender` | Conditions on the message author (envelope-from / the From header — see §3.6). |
| `recipient` | Conditions on the recipient (envelope-to). |
| `attachment` | Conditions on a specific attachment. |

#### 2.3.1 `sender` / `recipient` (shared address-matching grammar)

| Field | Type | Match semantics |
|---|---|---|
| `address` | list of string | Exact match on the full address, case-insensitive. `["ceo@example.com"]`. |
| `domain` | list of string | Match on the address's domain (the part after `@`), case-insensitive. `["example.com"]`. **Subdomains are NOT included** by default (`example.com` ≠ `eu.example.com`); use `pattern` to cover a subtree. |
| `pattern` | list of string | Glob mask over the full address (`*`, `?`), case-insensitive. `["*@*.example.com"]`, `["finance-*@example.com"]`. |

Within a single field, the list is an **OR** (`domain: ["a.com","b.com"]` = a.com OR b.com). Multiple fields within one section (`address` and `domain` together) are also **OR** between fields (the address matched OR the domain matched). Rationale: it's natural for a human to read "sender from finance OR a specific address," not an intersection. AND across different dimensions is achieved via separate sections (`sender` AND `recipient`), not within a section.

> On multiple recipients (one shared milter body for all addressees) — this is a key complication, addressed separately in §3.4.

#### 2.3.2 `attachment`

Matches **one** attachment (rules are evaluated per-attachment, see §3.1).

| Field | Type | Semantics |
|---|---|---|
| `size` | object `{min, max}` | Size range. Values are strings with units (`"10MB"`, `"512KB"`, `"1GB"`) or an integer in bytes. `min` is inclusive, `max` is inclusive. Either bound is optional. |
| `mime_type` | list of string | The real type from magic bytes (T-3.1.2). Glob over the type: `["application/pdf"]`, `["image/*"]`. This is the **actual** type, not the declared one. |
| `claimed_mime_type` | list of string | The type declared in the `Content-Type` header. A separate field — so rules can target a mismatch (spoofing), e.g. claimed `image/png` with a real `application/x-dosexec`. |
| `extension` | list of string | The extension from the file name, without the dot, case-insensitive. `["exe","js","scr"]`. |
| `filename` | list of string | Glob over the full file name (`*`, `?`), case-insensitive. `["*.exe","invoice-*.pdf"]`. |
| `disposition` | list of `inline` \| `attachment` | Matches the **effective** classification of the part (ADR-016), NOT the raw `Content-Disposition` header. `inline` = the part is a presentation-inline asset (a logo/signature embedded via `cid:` inside `multipart/related`, RFC 2387/2392); `attachment` is everything else. The raw header is intentionally ignored: some MUAs (Apple Mail) mark genuine, downloadable attachments as `inline`, and matching on the header would be a policy bypass. A missing field matches any part (backward compatible, no version bump — §7.1). Example: `disposition: ["inline"]` is an explicit opt-in by the policy author to replace inline assets (by default the pipeline's protective layer leaves them alone, see ADR-016). |

Within `attachment`: different fields are **AND** (e.g. `mime_type: ["application/pdf"]` AND `size.min: "5MB"` = "a PDF larger than 5MB"). A list within one field is **OR**. This differs from the address sections (where fields are OR) and is justified as follows: attachment attributes are different dimensions of the same object, and it's natural to narrow them by intersection ("large AND exe"). The grammar difference is documented explicitly and exercised by the §5 scenarios.

Size units: `KB/MB/GB` are treated as **1000**-based (decimal, matching how a user thinks of a file's marketed size), `KiB/MiB/GiB` as **1024**-based. Rationale: a business user writes "10MB" and expects 10,000,000, not 10,485,760. Both forms are supported; unit casing is insensitive except for distinguishing `KB` from `KiB`.

### 2.4 Action block (`then` and `default`)

| Field | Type | Required | Applies to | Description |
|---|---|---|---|---|
| `action` | enum: `pass` \| `replace` \| `block` | yes | — | What to do. |
| `ttl` | duration string | no | `replace` | The link's lifetime (US-6.1). `"30d"`, `"48h"`, `"90d"`. |
| `max_downloads` | integer ≥ 1 | no | `replace` | The per-link download limit (US-6.1). Absent = unlimited. |
| `retention` | duration string | no | `replace` | How long the file is kept in storage (US-5.3). Can differ from `ttl`: the link is dead, but we still hold the file for audit/recovery. |
| `reason` | string | no | `block` | A human-readable rejection reason (for the audit log and, optionally, a bounce back to the sender). |
| `link` | object | no | `replace` | Reserved (§7.2): future link parameters (password, watermark). Unknown subfields are an error in v1. |

Consistency rules (checked by the validator, see §3.5):
- `ttl`/`max_downloads`/`retention`/`link` are only valid with `action: replace`. An error with `pass`/`block`.
- `reason` is only valid with `action: block`.
- If `retention` is not set on `replace` — the file is kept for at least `ttl` (otherwise the link would point at a deleted file); the effective retention default comes from the global config (US-5.3).

`duration` format: suffixes `s`, `m`, `h`, `d` (`d` = 24h). Fractional and compound values (`1d12h`) are not supported in v1 — kept simple for readability. `"0"` is forbidden.

---

## 3. Semantics

### 3.1 Multiple attachments in a message → a per-attachment decision

**Decision: the policy is evaluated independently for each attachment.** A message with three files (`report.pdf` 200 KB, `archive.zip` 40 MB, `macro.exe`) can produce three different verdicts: pass / replace / block.

Rationale: the product concept (per the Vision doc) is an "attachment policy engine" — the unit of control is the attachment. A `size.min: 10MB` rule must catch exactly the large file, not "touch" the small ones. This is intuitive for a business user: "files larger than 10MB → become a link" reads naturally per-file.

Aggregating the message's verdict:
- If **at least one** attachment resolves to `block`, the whole message is blocked (a message can't be partially delivered without the dangerous file without radically rewriting the body; in v1, blocking one dangerous attachment means blocking the message, with the `reason` and the file name recorded in the audit log). This is a deliberately strict choice; a softer option ("strip only the dangerous attachment, deliver the rest") is deferred to §8 as an open question.
- Otherwise every `replace` attachment is swapped for its own link, `pass` attachments stay as they are, and the message is delivered.

Messages **without attachments** never run the attachment policy (there's no object for `attachment` conditions to match); the message's action is delivery as-is. A rule with an empty `when` and no `attachment` section is not applied to "the message as a whole" as a separate entity in v1 — the unit is always the attachment.

### 3.2 first-match-wins

For each attachment, rules are walked top to bottom. The `then` of the first rule whose `when` matches (against the current attachment and the message's address data) is taken. Remaining rules are not evaluated. If none matched, `default` applies. A `disabled: true` rule is skipped during the walk.

Order in the file = priority. This makes behavior predictable and explainable in the audit log: "attachment X → rule #2 `Large attachments`." No weights/scoring (unlike rspamd — see §6) — those are opaque to a business user.

### 3.3 Empty `when` = catch-all

A rule with no `when` always matches. Used as a "local default" before the global one, or as an explicit section terminator. The validator **warns** (a warning, not an error) if there are further rules after a catch-all rule — they are unreachable (dead rules), like unreachable code.

### 3.4 Multiple recipients: the key milter complication

**The problem.** The milter (T-2.1.x) hands Attachra **one message body**, shared across all envelope recipients. But `replacebody` in the milter rewrites that single body once — and Postfix delivers the same rewritten MIME to **every** RCPT TO recipient. We physically cannot give Alice a rewritten body with a link while giving Bob the original with the file, within one milter transaction with one body.

At the same time, US-6.1 requires a **personal link for each recipient** (for targeted revocation and tracking). There are two distinct levels here, and they must not be conflated:

1. **The body/action level** (pass/replace/block) — shared across the message, because there is one body.
2. **The link level** (a token per attachment×recipient pair) — personal, and it is compatible with a single body: the rewritten body can carry a link whose path leads to a page that, based on message context, hands the recipient their own token. Or — if genuinely different URLs are needed in the body for different people — that goes beyond what a single milter transaction can do.

**The v1 decision (worst-case aggregation for choosing the action):**

To choose the **action** (pass/replace/block) for a rule with a `recipient` condition, **worst-case (the most restrictive) semantics across all recipients** applies:

- The message's action for a given attachment is the "strongest" among the actions computed for each recipient individually. Strictness, ascending: `pass` < `replace` < `block`.
- Example: a message to `mary@example.com` (internal, the rule gives `pass`) and `bob@partner.com` (external, the rule gives `replace`) → the attachment is **replaced with a link for everyone** (`replace` is stronger than `pass`). The internal recipient also sees a link instead of the file. This is a deliberate trade-off: it's safer to rewrite for everyone than to risk sending the raw file outside accidentally.
- If the rule gives `block` for at least one recipient, the whole message is blocked (you can't deliver its safe portion without blocking the dangerous one).

**Personal links are still preserved** (US-6.1): when an attachment is replaced, the Link Engine generates a **separate token for each envelope recipient**, for audit and targeted revocation. The message body is shared, but the system knows every recipient of the transaction and creates its own link record for each. Exactly how a single URL inserted into the body resolves to a recipient's personal token (a shared URL plus recipient identification on the download-service side, or the v1 constraint "the body carries one shared token; personal tokens exist only for revocation") is an **open question, §8**, that depends on the Link Engine design (US-6.1/6.2) and does not block the policy format.

**Why not per-recipient split delivery.** Splitting one message into N messages (one per recipient) with different bodies would change Postfix's transport semantics from within the milter, which the milter API does not cleanly support (you cannot reliably spawn N different deliveries with different bodies from one transaction). This breaks the ADR-002 invariant (Core has no knowledge of transport) and the "a message is sacred" principle. So per-recipient differing bodies are **not in v1**; once an SMTP-proxy adapter exists (where we control delivery), this can be revisited as an adapter capability, not a policy-format one.

Bottom line for a policy author: **a rule with `recipient` filters whether a recipient falls under the rule; if even one addressee of the message falls under a rule with `replace`/`block`, that action applies to the whole message (worst-case).** This needs to be stated explicitly in the UI/docs for a security officer, so there's no surprise that "an internal colleague also got a link."

### 3.5 Validation and error messages

Validation is mandatory (US-4.1: "the schema is formally specified and validated with clear errors"; US-4.2: an invalid policy is not applied). Levels:

**Errors (the policy is rejected entirely, not applied):**
- `version` is missing / not an integer / unsupported.
- Unknown top-level field (other than the reserved ones).
- Unknown field inside a `when` section or `then`.
- `rules[i].then.action` is missing or not in the enum.
- A rule without `then`.
- A rule without `name`.
- A parameter that doesn't belong to its action (`ttl` with `pass`, `reason` with `replace`).
- Malformed `size`/`duration`/glob.
- `default` is missing.
- More than one YAML document in the file.

**Warnings (the policy is applied, but the log/CLI reports it):**
- Unreachable rules after a catch-all (§3.3).
- A rule that can never match anything (e.g. `size: {min: "10MB", max: "1MB"}` — an empty range).
- `replace` without `retention` when `ttl` is explicitly set (a reminder that retention will come from config).

**Message format** — with a path (JSON-pointer-like) and human-readable text, for example:

```
policy "finance.yaml": error at rules[2].then: field "ttl" is only valid for action "replace" (found action "block")
policy "finance.yaml": warning at rules[5]: rule is unreachable — preceding rule "catch-all" has no `when` and always matches
```

Text requirement: refer to the **rule by `name`**, not just by index, so a business user can find the line. The validation CLI command (`attachractl policy validate`, T-4.2.3 / US-9.1) prints all errors and warnings at once (not just the first), with a non-zero exit code when errors are present.

### 3.6 Naming conventions and disambiguation

- **Field names:** `snake_case`, English, nouns (`max_downloads`, `claimed_mime_type`). Enum values are short lowercase verbs/nouns (`pass`, `replace`, `block`).
- **Units live in the value, not the field name:** `size: {min: "10MB"}`, not `size_mb`. This is more extensible and readable.
- **Lists everywhere plurality is conceivable:** `domain`, `extension`, `mime_type` — always a list, even for one value (`domain: ["example.com"]`). Consistency matters more than brevity; a list is obvious to a YAML reader.
- **`sender`/`recipient` take addresses from the envelope** (MAIL FROM / RCPT TO) as the source of truth — that's what actually controls delivery and what the milter gives us. The header `From`/`To` can diverge from the envelope (mailing lists, BCC). In v1 we match the **envelope**; matching on headers is a reserved extension (`sender: { header_from: [...] }`, §7.2), to avoid mixing two different meanings in one field.
- **Case-insensitive** for all addresses, domains, extensions, globs (email addresses and file names are de facto case-insensitive for these purposes on the web).

---

## 4. Evaluation model (summary for implementation T-4.1.3/4.1.4)

Pseudocode (normative behavior, not an implementation language):

```
evaluate(message):
  for attachment in message.attachments:      # §3.1 per-attachment
     verdict[attachment] = decide(attachment, message.recipients)
  if any verdict == block: return BLOCK(message)   # §3.1
  apply replace/pass per attachment; deliver

decide(attachment, recipients):
  worst = pass
  for r in recipients:                          # §3.4 worst-case
    for rule in rules:                          # §3.2 first-match-wins
      if rule.disabled: continue
      if rule.when matches (attachment, sender, r):
        worst = strongest(worst, rule.then.action)
        break                                   # first match for this recipient
    else:
      worst = strongest(worst, default.action)
  return worst  (+ action params from the winning rule, see note)
```

Note: action parameters (`ttl`/`max_downloads`/`retention`) are taken from the rule that produced the final (worst-case) action. If several recipients produced `replace` with different parameters, the **most restrictive set** is taken (the smaller `ttl`, the smaller `max_downloads`); this is another worst-case rule and an **open question, §8**, pending refinement (for now: the most restrictive value).

---

## 5. Examples (5 scenarios)

### (a) All outbound attachments > 10 MB → replace with a 30d ttl

```yaml
version: 1
name: "Large outbound attachments to links"

rules:
  - name: "Internal recipients: large files pass"
    when:
      recipient:
        domain: ["example.com"]
      attachment:
        size: { min: "10MB" }
    then:
      action: pass

  - name: "External recipients: large files become links"
    when:
      attachment:
        size: { min: "10MB" }
    then:
      action: replace
      ttl: "30d"

default:
  action: pass
```

How to read it: rule 1 (internal addressee + large file → pass) comes first, so that "outbound" in the second rule means "everyone not already filtered out as internal." Order carries meaning. If there are several recipients and at least one is external, worst-case (§3.4) kicks in: the large file becomes a link for everyone.

### (b) The finance department to external domains → replace + max_downloads 3

```yaml
version: 1
name: "Finance department outbound control"

rules:
  - name: "Finance to internal: pass"
    when:
      sender:
        pattern: ["*@finance.example.com"]
      recipient:
        domain: ["example.com"]
    then:
      action: pass

  - name: "Finance to external: replace with tight download limit"
    when:
      sender:
        pattern: ["*@finance.example.com"]
    then:
      action: replace
      max_downloads: 3
      ttl: "14d"

default:
  action: pass
```

The department is identified by the sender's subdomain (`*@finance.example.com`) via `pattern`. The first rule excludes internal correspondence; everything else from finance (i.e. outbound) becomes a link with a 3-download limit. `sender` is matched via a subdomain rather than a list of addresses, to avoid maintaining a roster of people.

### (c) `*.exe`, `*.js` outbound → block

```yaml
version: 1
name: "Block executable attachments outbound"

rules:
  - name: "Executables to internal: allowed"
    when:
      recipient:
        domain: ["example.com"]
      attachment:
        extension: ["exe", "js", "scr", "bat", "cmd"]
    then:
      action: pass

  - name: "Executables to external: blocked"
    when:
      attachment:
        extension: ["exe", "js", "scr", "bat", "cmd"]
    then:
      action: block
      reason: "Executable attachments may not be sent to external recipients. Use a link or contact IT security."

default:
  action: pass
```

The whole message is blocked if at least one attachment is executable and at least one recipient is external (worst-case + block aggregation). `reason` is recorded in the audit log and can be relayed back to the sender. For real anti-spoofing coverage this should also match on `mime_type` (the real type) — see the variation below — but for readability the base scenario matches on `extension`.

### (d) Internal mail → pass everything

```yaml
version: 1
name: "Internal mail untouched"

rules:
  - name: "Both sides internal: pass everything"
    when:
      recipient:
        domain: ["example.com"]
    then:
      action: pass

default:
  action: replace
  ttl: "30d"
```

Here `default` is not `pass` but `replace` — meaning "leave internal mail untouched, everything else (outbound) becomes a link by default." This shows that "internal mail passes through" combines naturally with a safe outbound default. Note the worst-case interaction: a message to both an internal and an external address falls under the default for the external recipient → `replace` for everyone (§3.4).

### (e) GDPR starter: everything to non-EU domains → replace + 90d retention

```yaml
version: 1
name: "GDPR transfer control (starter)"
description: "Attachments to non-EU recipients get bounded retention. Placeholder until geo-matching (v-next) lands."

rules:
  - name: "EU / EEA recipients: normal handling"
    when:
      recipient:
        # List EU/EEA domains explicitly until geography matching lands (§7.3)
        domain:
          ["example.eu", "partner.de", "partner.fr", "partner.nl"]
    then:
      action: replace
      ttl: "30d"
      retention: "30d"

  - name: "All other (treated as non-EU): bounded retention"
    when:
      attachment: {}          # any attachment; an empty object means "there is an attachment"
    then:
      action: replace
      ttl: "30d"
      retention: "90d"

default:
  action: pass
```

An honest caveat: in v1, "non-EU" is approximated as "not in the EU domain list." Real geo-classification of a recipient (by country/region) is a future `geography` concept (§7.3); this starter is written so that, once it lands, the domain list can be swapped for `recipient: { geo: { not_in: ["EU"] } }` **without changing the actions or the file structure**. This also shows `attachment: {}` — an empty section meaning "applies to any attachment" (equivalent in meaning to omitting the section, but clearer to the reader as "this rule is about attachments").

---

## 6. Prior art: what we borrow, what we avoid

| DSL | We borrow | We avoid |
|---|---|---|
| **rspamd rules** | The idea of declarative per-message conditions; symbolic rule names; hot reload. | **Scoring/weights and Lua embedding.** In rspamd, the action is the sum of the weights of matched symbols against thresholds, plus arbitrary Lua. Powerful, but **opaque to a business user** (ADR-006): you cannot look at a rule and say what will happen. We take a strict first-match-wins with no arithmetic and no code in the policy. |
| **Sigma rules** | YAML as the format; a `detection` section with logical groups; an explicit, validatable schema; the idea of "a human reads the rule." | **The `condition:` mini-language** (`selection1 and not selection2`, `1 of them`). Flexible, but this is already an expression language — too high a barrier for a non-programmer. In v1, logic is fixed (sections = AND, lists = OR) with no user-defined boolean expressions. A restricted `any_of`/`all_of` may be introduced in v-next, not v1. |
| **Cloud IAM (AWS/GCP policy)** | **Explicit `Effect: Allow/Deny` (our action enum); determinism; document versioning (`Version: "2012-10-17"`)** — a direct precursor to our `version:`. The "default deny" idea → our mandatory `default`. | **Explicit-deny-overrides across an unordered rule set** and `Condition` operators (`StringLike`, `IpAddress`, `DateGreaterThan`) with ARN-level depth. Order doesn't matter for IAM (deny always beats allow), but that requires holding a conflict-resolution model in your head. We chose **order = priority** instead (easier to explain: "read top to bottom, first match wins"). IAM's rich condition language is a reference point for future operators (`min/max`, `in/not_in`), but we introduce them gradually as fields, not as expressions. |

Summary: **we take** declarativeness, YAML, versioning, named rules, a configurable default-deny; **we avoid** embedded code (rspamd/Lua), user-defined boolean expressions (Sigma's condition language), and unordered conflict resolution (IAM) — all three for the sake of one invariant: "understandable by a business user."

---

## 7. Extensibility without breaking v1

### 7.1 Schema versioning

- `version:` — the **major** version of the format (integer). The v1 engine accepts `version: 1`. A higher `version` (e.g. `2`) on an old engine → **a clear error** ("policy requires format version 2, this build supports up to 1; upgrade Attachra"), and the policy is not applied (safe). This guards against silent misinterpretation.
- **Minor, backward-compatible additions** (new optional fields inside `when`/`then`) **do not bump** `version`. Compatibility rule: when the v1 engine encounters an **unknown field where the document didn't reserve one**, it errors out (catching typos); but fields from the **reserved list** (§7.2) are known to it by name and are treated as "I recognize this name, but this build may not support the functionality yet." This creates a path forward: new concepts are added as new keys that were pre-declared reserved, and the old engine gracefully ignores/reports them instead of crashing.
- Practical takeaway: **v1 → v1.x is field additions, `version` stays 1.** `version: 2` is reserved for an **incompatible** semantic change (e.g. replacing first-match-wins with a different model) — hopefully never needed.

### 7.2 Reserved fields (declared now, implemented later)

The v1 parser **knows these names** and does not treat them as typos; the behavior is either "accept and ignore" or "implemented":

- Top level: `metadata` (arbitrary pack/author data), `defaults` (inherited action-parameter values).
- Inside `when.sender`/`when.recipient`: `group` (LDAP/AD group membership, §7.4), `header_from`/`header_to` (matching on headers rather than the envelope), `geo` (§7.3).
- Inside `when`: `time` (§7.5), a new top-level section.
- Inside `when.attachment`: `tag` (storage/classification tags), `content` (future DLP/content matching).
- Inside `then`: `link` (extended link parameters: password, watermark), `notify` (notifications).
- Inside `then` for download-count policies: `on_download_limit` (§7.6).

Implemented vs reserved-only fields are distinguished by a flag in the schema; the validator may emit a **warning** for a reserved-but-not-implemented field ("field `geo` is reserved but not supported in this build — ignored"), so the author understands the rule won't behave as expected yet.

### 7.3 geography (future)

Added as fields inside the address sections, without breaking v1:

```yaml
when:
  recipient:
    geo:
      not_in: ["EU"]        # in / not_in operators over countries/regions
```

Scenario (e) is rewritten by replacing the explicit EU domain list with `geo.not_in: ["EU"]` — **the rule structure and `then` don't change**. Resolving "address → country" is the engine/plugin's job; the format only supplies the field.

### 7.4 LDAP/AD groups (future, Identity Pack)

```yaml
when:
  sender:
    group: ["finance", "executives"]     # membership from LDAP/AD data
```

Scenario (b) (finance) is rewritten from `pattern: ["*@finance.example.com"]` to `group: ["finance"]` — more reliable than a subdomain. Membership resolution is the Identity Pack (an Enterprise plugin, ADR-003/Vision); the format stays the same. Key point: this does **not** change the `when` grammar (still AND across sections, OR within lists).

### 7.5 time (future)

A new section inside `when` (alongside sender/recipient/attachment), preserving the "sections = AND" rule:

```yaml
when:
  time:
    days: ["mon","tue","wed","thu","fri"]
    hours: { from: "09:00", to: "18:00" }
    timezone: "Europe/Berlin"
```

"Large outbound files during business hours → pass, otherwise → replace" is expressed by adding `time` to existing rules without breaking anything.

### 7.6 download count (future)

Download count as a **condition** relates to the state of an already-created link (not to the moment of sending), so this is mostly a Link Engine/revocation-policy feature rather than message matching. In the format it's reserved as an action parameter/post-condition:

```yaml
then:
  action: replace
  max_downloads: 3
  on_download_limit: revoke     # what to do once the limit is reached: revoke | notify | extend
```

`max_downloads` already exists in v1; `on_download_limit` and richer download policies are reserved.

### 7.7 storage tags (future)

Classification/tags from the storage layer or a classifier:

```yaml
when:
  attachment:
    tag: ["confidential", "pii"]     # tags set by an upstream plugin
```

Added as a field inside `attachment`; the grammar does not change.

**Extensibility invariant:** every future concept enters either as (1) a new field in an existing section, (2) a new section inside `when` (always AND with the rest), or (3) a new parameter in `then`. None of them changes: first-match-wins, the mandatory `default`, per-attachment evaluation, worst-case across recipients, or the AND-section/OR-list grammar. So v1 files stay valid and evaluate identically on future engines.

---

## 8. Rejected alternatives and open questions

### 8.1 Rejected alternatives

1. **Scoring instead of first-match-wins (the rspamd model).** Rejected: opaque to a business user (ADR-006). You cannot look at a rule and predict the verdict without knowing all the weights and thresholds.
2. **A boolean condition language (the Sigma `1 of them`, `A and not B` model).** Rejected for v1: too high a barrier for a non-programmer; AND-sections plus OR-lists cover the realistic scenarios (§5). A restricted `any_of`/`all_of` is a v-next candidate, not v1.
3. **Embedded code/expressions (Lua/CEL/expr).** Rejected: directly contradicts ADR-006 and enlarges the security surface (executing untrusted code on the milter path — against "a message is sacred").
4. **An unordered rule set with explicit-deny-override (the IAM model).** Rejected: requires holding a conflict-resolution model in your head; order-as-priority is explained in one sentence.
5. **Per-recipient different message bodies (splitting into N deliveries).** Rejected for v1: the milter gives us one body; spawning N different deliveries from one transaction is unreliable and drags transport semantics into Core (against ADR-002). Possible as a future SMTP-proxy adapter feature, not a format feature.
6. **The unit of control being the message rather than the attachment.** Rejected: the product is an attachment policy engine; a per-attachment decision (§3.1) is more precise and intuitive ("files >10MB," not "messages containing a file >10MB").
7. **JSON/TOML/HCL instead of YAML.** Rejected: YAML is more readable for a non-programmer (comments, no brackets), matches the project's config format (T-1.1.5) and precedent (Sigma, k8s). YAML's risks (`no`/`yes` typing, indentation) are mitigated with a strict schema and validator.

### 8.2 Open questions (require team discussion)

1. **Does blocking a dangerous attachment mean blocking the whole message?** v1 blocks the whole message (§3.1). The alternative — "strip the dangerous attachment, deliver the rest" (partial delivery) — changes MIME semantics and sender expectations; needs a decision from product-lead + security (US-3.2 rewrites the body, but "remove an attachment and notify" is a separate feature). **Affects:** T-4.1.4, US-3.2.
2. **How does a single URL inserted into the body become personal for each recipient** with one shared milter body (§3.4). Options: (a) a shared URL plus recipient identification on the download service; (b) the body carries one "shared" token, personal tokens exist only for revocation/audit; (c) restrict personalization until the SMTP-proxy adapter exists. **Resolved in the Link Engine design (US-6.1/6.2), does not block the format.**
3. **Parameter conflicts under worst-case replace** (different `ttl`/`max_downloads` for different recipients of one message, §4). v1 proposes "the most restrictive value"; confirm this is the desired behavior and document it in the UI.
4. **Should a policy be able to override fail-open/fail-closed** (e.g. a `block` rule when storage is unavailable)? v1: no, the global config decides (technical invariant #3). Check whether a per-rule override is needed for security-critical rules. **Affects:** US-2.2.
5. **Matching on the envelope vs. headers by default** (§3.6). v1 matches the envelope. Needs confirmation with security that this doesn't create a bypass (a sender sets an innocuous From header while the real envelope-from differs) — and vice versa. Header matching is reserved, but implementation priority needs discussion.
6. **Should `block` be the global `default`** (a fail-safe "everything outbound is blocked until explicitly allowed") as a recommended Policy Pack — a question about the out-of-the-box default policy (a backlog open question, part of the M1 open-questions discussion).

---

## 9. Policy file: minimal valid template

```yaml
version: 1
name: "Policy name"
rules: []          # an empty list is allowed
default:
  action: pass
```

The full schema (a machine-readable JSON Schema for the validator) is a deliverable of task T-4.1.2; this document is its normative description and source of requirements.
