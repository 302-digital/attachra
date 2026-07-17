# DKIM signing and Attachra milter order (T-3.2.4)

Attachra rewrites the message body (US-3.2: attachments are stripped
and replaced with a text/HTML block) and adds the `X-Attachra-Processed`
header. Any change to the message body or headers **after** it has
been DKIM-signed invalidates that signature, because DKIM's `body hash`
(`bh=`) covers the (canonicalized) body and its signed-headers set
typically includes headers Attachra may add or that sit near ones it
touches.

**Rule: Attachra must run before the DKIM-signing milter in Postfix's
milter chain**, so DKIM signs the final, already-rewritten message.
Signing before Attachra rewrites the body produces a message whose
DKIM signature no longer verifies at the receiving end — mail servers
that enforce DKIM (and especially DMARC with `p=reject`/`quarantine`)
may quarantine or reject it outright, and even lenient receivers will
show the signature as broken.

This is not an Attachra-specific quirk: it is the general rule for
**any** milter that modifies body or headers (content filters,
antivirus, disclaimers/footers) — they must all run before the
DKIM-signing milter. Attachra should be ordered alongside those, not
after.

## Verified live (T-3.2.4 spike, 2026-07-16)

The rule above was originally written from Postfix/DKIM protocol
documentation only (T-3.2.4), not exercised against a running
mail path. The spike built a disposable Postfix + Attachra +
rspamd/opendkim compose stack (not `deploy/dev/docker-compose.yml` —
a separate throwaway stack, torn down after the spike) and drove real
messages with an attachment through all four milter orderings below,
verifying each resulting message's DKIM signature independently with
`dkimpy` (a fake `dnsfunc` returned the spike's own test public key,
so verification did not depend on real DNS).

| # | Milter order (`smtpd_milters`) | Body actually rewritten? | DKIM result | How checked |
|---|---|---|---|---|
| A | `attachra, rspamd` (rspamd `dkim_signing`) | yes | **Valid** | live |
| B | `rspamd, attachra` (rspamd `dkim_signing`) | yes | **Invalid** — `body hash mismatch` | live |
| C | `attachra, opendkim` | yes | **Valid** | live |
| D | `opendkim, attachra` | yes | **Invalid** — `body hash mismatch` | live |

Orders A/C are the "Attachra before the signer" rule from this doc;
B/D are the reverse. In every rewritten-body case, `dkimpy`'s
`verify()` either returned `True` (A, C) or raised
`ValidationError: body hash mismatch` with the expected vs. computed
hash shown (B, D) — an unambiguous, reproducible confirmation of the
rule, not a plausibility argument. The underlying Postfix mechanism
this demonstrates — each milter's `eom` callback runs in
`smtpd_milters` order and sees the **cumulative** effect of every
milter that ran before it, including body/header rewrites — is
generic to Postfix's milter protocol, not specific to rspamd or
opendkim; having reproduced it with two independent signers (a
built-in rspamd module and a standalone opendkim milter) rules out an
implementation quirk of either one.

**This directly implicates the mxbox pilot's documented milter order.**
`docs/deploy/grommunio-debian.md` currently instructs operators to run
`smtpd_milters = inet:localhost:11332, inet:127.0.0.1:6785` — **rspamd
first, Attachra second** — matching failing order B above. On a host
where rspamd's `dkim_signing` module is active, any outbound message
that Attachra actually rewrites (attachment replaced with a link) will
carry a **DKIM signature that fails verification** at the receiving
end. See the warning in that guide and the tracked follow-up to audit/fix
the live mxbox milter order) for the operational remediation; this
document only fixes the guidance, not necessarily every already-
running deployment.

### A genuine ordering conflict: spam/AV scanning vs. DKIM signing

`docs/deploy/grommunio-debian.md`'s current order was not arbitrary —
it puts rspamd first so its spam/AV verdict (and reject decision) is
settled, and so rspamd's antivirus integration sees the **original**
attachment bytes, before Attachra uploads and removes them. That is a
reasonable goal on its own, but a single rspamd milter instance does
both spam/AV scoring **and** DKIM signing in the same `eom` callback —
so with only one rspamd milter in the chain, "scan before Attachra"
and "sign after Attachra" are mutually exclusive; simply moving
Attachra ahead of rspamd (fixing DKIM) means rspamd's AV/attachment
scanning now only ever sees Attachra's replacement-block text, never
the original attachment bytes.

There is no reordering of a *two*-milter chain that satisfies both
goals. The standard resolution is to split the two rspamd
responsibilities across the chain instead of reordering as a pair:

1. Keep rspamd first for spam/AV scoring and reject/quarantine
   decisions, but **disable its `dkim_signing` module**
   (`sign_authenticated`/`sign_local`/`sign_networks` all `false`, or
   remove the module's `domain { ... }` config) so it never signs.
2. Run Attachra second, as usual.
3. Add a **dedicated signer** last in the chain — either a standalone
   `opendkim` instance (as verified live above) or a second rspamd
   `rspamd_proxy` worker configured only for `dkim_signing` — so
   signing happens strictly after Attachra's rewrite.

This is the same three-stage shape already documented below (Attachra,
then rspamd for spam scoring, then `opendkim` last); it was already
correct guidance for the general case, it just wasn't cross-referenced
from the grommunio guide's two-milter default. Operators who don't run
outbound DKIM signing at all (mail relayed through an upstream
smarthost that signs, or DKIM not in use) are unaffected by any of
this — the conflict only exists when the same host does both
attachment rewriting and DKIM signing.

## Postfix milter order

Postfix invokes the milters listed in `smtpd_milters` /
`non_smtpd_milters` **in the order listed**. Put Attachra before
rspamd (if rspamd or another milter is the one adding the DKIM
signature, e.g. via `opendkim` chained through rspamd, or a standalone
`opendkim` milter) in that list:

```
# main.cf
milter_protocol = 6
milter_default_action = accept

# Attachra first (content/attachment rewriting), then rspamd/opendkim
# (spam filtering + DKIM signing) last, so DKIM signs the final body.
smtpd_milters = inet:127.0.0.1:6785, inet:127.0.0.1:11332
non_smtpd_milters = inet:127.0.0.1:6785, inet:127.0.0.1:11332
```

Where `inet:127.0.0.1:6785` is Attachra's milter listener (see
`docs/integrations/postfix.md`) and `inet:127.0.0.1:11332` is a
stand-in for whichever milter performs DKIM signing in your setup
(rspamd's own milter port, or a dedicated `opendkim` socket).

If DKIM signing happens via `opendkim` as a **separate** milter from
rspamd, the same rule applies to its position:

```
smtpd_milters = inet:127.0.0.1:6785, inet:127.0.0.1:12301, inet:127.0.0.1:8891
```

(Attachra, then rspamd for spam scoring, then `opendkim` last — any
ordering that keeps DKIM signing as the final step is correct;
Attachra does not need to run before rspamd specifically, only before
whichever milter signs.)

## Why this can't be worked around after the fact

- DKIM's `bh=` tag is a hash of the (canonicalized) body. Attachra
  removing MIME parts and inserting the replacement block changes the
  body bytes, so any signature computed over the pre-rewrite body no
  longer matches — verification fails, it is not merely "different".
- Re-signing after Attachra is the only fix; there is no way to keep a
  signature computed before rewriting and have it still validate.
- Attachra's own `X-Attachra-Processed` header, if added after DKIM
  signing and if that header were in the signed-headers set on a
  future signature, would similarly break signatures for the reverse
  ordering mistake (DKIM before Attachra, then something re-adds a
  header afterward) — another reason Attachra belongs before the
  signer, not spliced in after.

## Verifying the fix in practice

Use [mail-tester.com](https://www.mail-tester.com) (or any DKIM/DMARC
checker) after configuring milter order:

1. Send a test outbound message containing at least one attachment
   that a configured Attachra policy replaces, addressed to the
   mail-tester.com address it gives you.
2. Open the resulting report. Look for the **SPF**, **DKIM**, and
   **DMARC** checks.
3. DKIM should show as passing/valid, with the signing domain matching
   your sending domain. If DKIM instead shows as failing/invalid
   despite a correctly configured signer, re-check milter order first
   — a body-hash mismatch here is the classic symptom of signing
   before an attachment-rewriting or disclaimer-adding milter runs.
4. Confirm the attachment was actually replaced in the delivered
   message (the report shows the raw message you can inspect), so you
   are testing the DKIM signature over the *rewritten* body, not a
   pass-through message that never exercised Attachra's rewrite path.

## Summary

| Milter order | DKIM result | Live-verified (2026-07-16) |
|---|---|---|
| Attachra → rspamd (`dkim_signing`) | Correct: signature covers final body | yes |
| rspamd (`dkim_signing`) → Attachra | Broken: signature covers a body that no longer exists | yes |
| Attachra → opendkim | Correct: signature covers final body | yes |
| opendkim → Attachra | Broken: signature covers a body that no longer exists | yes |

Configure `smtpd_milters` (and `non_smtpd_milters`, if used) with
Attachra listed before the milter that performs DKIM signing. If the
same signer (e.g. rspamd) also does spam/AV scoring you want to run
*before* Attachra, see "A genuine ordering conflict" above — split
scoring and signing across two chain positions rather than reordering
the pair.
