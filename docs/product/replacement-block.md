# Replacement block: anti-phishing text principles

> Part of the Recipient Trust Kit. This document records the
> principles behind the wording of the text/HTML replacement block a
> recipient sees when an attachment is removed and covers the current
> state of the built-in templates
> (`internal/core/rewrite/templates/en/block.{txt,html}.tmpl`, T-3.2.2).
> English-only: the ru locale was removed ahead of a future i18n story;
> there is currently one built-in locale (`en`, `rewrite.DefaultLocale`).

## Why this matters

The single biggest operational risk in this product category is
recipient-side distrust: a message that "used to have a PDF, now has a
link and a stranger's domain in it" is exactly the shape of a phishing
email, and enterprise mail security teams train users to be suspicious
of that shape. Two data points from `docs/research/competitors.md`
motivate treating this as a first-class design constraint rather than
copywriting polish:

- mxHERO — the SaaS product structurally closest to Attachra — lists
  recipient-side blocking/distrust as complaint #1 in customer
  feedback.
- Egress is described in market research as effectively "a phisher's
  dream" when a security-conscious recipient can't tell a legitimate
  attachment-replacement email from an attack.

A single instance of the replacement block looking like a phishing
template (in a company's own outbound mail, generated automatically by
software the company installed) does more damage to trust than almost
any other failure mode in this product, because it's visible to every
external recipient of every policed message.

## Anti-pattern checklist

Each row is a pattern common in real phishing/BEC templates and
anti-phishing security-awareness training material as a "red flag".
The block must not contain any of them.

| Pattern | Why it's a red flag | Attachra's rule |
|---|---|---|
| "Click here" / "Click now" / bare imperative link text | Standard phishing-training red flag #1 — legitimate transactional mail names what the link *is*, not commands the reader to act. | Link text is descriptive ("Download files"), never a bare imperative. |
| Urgency / scarcity language ("act now", "immediately", "your access expires today") | Urgency is the primary social-engineering lever phishing relies on to short-circuit the recipient's judgment. | The block states a factual expiry date/time if one applies (`ExpiresAt`) and nothing more — no framing that pressures the reader to act before reading it. |
| Requests to "verify", "confirm", "re-authenticate", or otherwise take an account action | This is the mechanism of credential-phishing specifically; a replacement block has no legitimate reason to ask for any of these. | The block only ever links to a download page. It never asks the recipient to log in, confirm identity, or take any account action. |
| Vague or missing sender attribution ("Someone shared a file with you") | Vagueness is a phishing-training red flag; legitimate systems name who did the thing. | `SenderName`, when available, is rendered as "Sent by: <name>" so the recipient can correlate the block with a known correspondent. |
| No indication of what the attachment actually was | Forces the recipient to click blind, which is itself a trained-against behavior. | File name and size (`Files`, rendered as `<name> (<size>)`) are listed as plain text before any link, so the recipient can decide from content alone whether the message makes sense — no click required to find out what it was. |
| Generic, unbranded "IT support" plausible-deniability tone | Ambiguity about which system generated the message is itself suspicious. | The block identifies the software plainly: "This message was processed by Attachra." — a named, verifiable product, not an anonymous "your mail system." |
| Mismatched or lookalike display text vs. actual URL (`<a href="evil.example">yourbank.com/login</a>`) | Classic link-spoofing technique. | The HTML template's anchor text ("Download files") never claims to *be* a URL or domain name; the actual `PackageURL` is the only link target and is not disguised. |
| Requests for personal/financial information in the message body | Direct data-harvesting attempt. | The block requests nothing — it is purely informational plus one link. |
| Link points at a raw IP address or a third-party URL shortener | Both are staples of phishing infrastructure — no legitimate reason to hide the real destination behind either. | `PackageURL` always resolves to the operator's own configured `public_base_url` domain (see `docs/integrations/recipient-trust.md`), never an IP literal or a shortener. |

## What the current templates already do right

Read against the checklist above, the current built-in `en` templates
(`internal/core/rewrite/templates/en/block.txt.tmpl` and
`block.html.tmpl`) pass every row without needing wording changes:

- Link text is "Download files" (HTML) / a plain URL after the label
  "Download link:" (plain text) — never "Click here".
- No urgency language; `ExpiresAt`, when set, is a plain factual date
  ("This link expires on ...").
- No account-action requests of any kind.
- `SenderName` ("Sent by: ...") is rendered when available.
- File name + human-readable size are listed per attachment before the
  link.
- "This message was processed by Attachra." names the software
  plainly.
- The HTML anchor's visible text is not a URL, so it cannot be used to
  disguise the real destination.

This review is a confirmation pass, not a rewrite: no
template text changes were needed. `internal/core/rewrite/templates_test.go`
and `internal/core/rewrite/block_test.go` already assert on key phrases
("available for download", "Download files") — those assertions are the
regression guard against a future edit accidentally reintroducing a
red-flag pattern; extend them if the wording changes.

## Recipient-admin note (`/about` link) — not yet wired into the templates

The Recipient Trust Kit design calls for a short note aimed at the
*recipient's* IT/security team ("this came from a legitimate
attachment-replacement system operated by \<sender's company\>; verify
at \<download-domain\>/about"), linking to an `/about` landing page on
the download domain. See the `/about` page on the download domain
(available from v0.3) for the recipient-admin-facing side of this —
what it explains and how to verify a message against it. The
replacement block templates themselves don't link to it yet:
`BlockData` has no `AboutURL` field, and adding a link to a page a
given deployment hasn't necessarily updated to yet would itself be a
red flag (a dead/placeholder link in a message that's already asking
the recipient to trust it). Wiring an `AboutURL` field through
`BlockData` and both templates, and extending the anti-pattern
checklist above with "admin verification link" as a positive-pattern
row (a legitimate, non-phishing link *to* the sending organization's
own domain, distinct from the file-download link), is a natural
follow-up once operators have had time to adopt the `/about` page.

## Overriding the templates

Operators can replace either template independently via
`rewrite.TemplateConfig.TextTemplatePath`/`HTMLTemplatePath`
(config keys under the message-processing section — see
`internal/config/config.go`). Anything in the anti-pattern checklist
above applies equally to operator-supplied overrides: an operator who
adds "Click here to view your file NOW" to a custom template has
reintroduced the exact risk this document exists to avoid, on their own
sending domain's reputation. This document is a good candidate to link
from operator-facing docs about template overrides, once those exist.

## Review

Anti-phishing pattern review: security review findings are recorded
via the standard code-review pipeline before merge, not restated here.
