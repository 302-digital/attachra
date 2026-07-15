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

| Milter order | DKIM result |
|---|---|
| Attachra → DKIM signer | Correct: signature covers final body |
| DKIM signer → Attachra | Broken: signature covers a body that no longer exists |

Configure `smtpd_milters` (and `non_smtpd_milters`, if used) with
Attachra listed before the milter that performs DKIM signing.
