# Postfix integration (T-2.1.6)

Attachra plugs into Postfix as a milter (mail filter), the same way
products like Rspamd or amavisd do. Postfix streams each outgoing
message's envelope and body to Attachra over the milter protocol;
Attachra either accepts it unmodified, rewrites it (replaced body /
added headers), or rejects/temp-fails it, and Postfix acts on that
response.

This document covers the operator-facing `main.cf` configuration. See
`docs/architecture/spike-milter-library.md` for the library/protocol
rationale and `deploy/dev/postfix/main.cf` for the working dev-compose
configuration this doc is based on.

## Minimal configuration

Add to `main.cf` (adjust the listen address to match
`milter.listen` in Attachra's own config):

```
milter_protocol = 6
milter_default_action = accept
smtpd_milters = inet:127.0.0.1:6785
non_smtpd_milters = inet:127.0.0.1:6785
```

- `smtpd_milters` applies to mail arriving via SMTP (the common case:
  MUA submission, relayed mail).
- `non_smtpd_milters` applies to mail injected locally (e.g. via
  `sendmail(1)`/cron/local scripts). Include it if you need Attachra
  to see that mail too; omit it if only SMTP-submitted mail should be
  policed.
- `milter_protocol = 6` selects the milter protocol version Attachra's
  adapter negotiates (see the spike doc); Postfix will automatically
  fall back to what the milter actually offers during negotiation, but
  setting it explicitly avoids relying on Postfix defaults changing
  across versions.

## Listen address syntax

Attachra's `milter.listen` config field and Postfix's
`smtpd_milters`/`non_smtpd_milters` both use the same syntax:

- `inet:host:port` — TCP, e.g. `inet:127.0.0.1:6785`.
- `unix:/path/to/socket` — Unix domain socket, e.g.
  `unix:/var/run/attachra/milter.sock`. Preferred when Postfix and
  Attachra run on the same host: avoids exposing a TCP port and
  removes a network hop.

Whichever you choose, the **same string** (module the `inet:`/`unix:`
prefix Postfix expects, which Attachra's adapter also understands)
should be used on both sides.

## `milter_default_action` and Attachra's own fail-open/fail-closed

These are two different, complementary failure modes and it's easy to
conflate them:

- **`milter_default_action`** (Postfix-side) governs what Postfix does
  if it **cannot reach Attachra at all** (connection refused, milter
  process down, timeout during negotiation). `accept` (the default)
  lets mail flow when Attachra itself is unreachable; `tempfail`
  queues/retries instead. This is a coarse, Postfix-level safety net.
- **`milter.failure_mode`** (Attachra-side, US-2.2) governs what
  Attachra's milter adapter does when it **is** reachable but hits an
  internal error while processing a specific message (processor
  error, panic, storage failure, oversized message, etc.): `open`
  accepts the message unmodified, `closed` returns a 4xx tempfail so
  Postfix retries later. See
  `docs/security/requirements-for-backlog.md` (SR-116-1).

For a coherent policy, set both to the same philosophy, e.g.
`milter_default_action = accept` + `milter.failure_mode: open` for a
"never block mail" deployment, or `milter_default_action = tempfail` +
`milter.failure_mode: closed` for a "never let unpolicied mail through"
deployment.

## Timeouts

Postfix enforces its own milter timeouts independent of Attachra's
`limits.milter_timeout`; if Attachra takes too long to respond,
Postfix applies `milter_default_action` regardless of what Attachra's
own session timeout is configured to do. Relevant `main.cf` settings
(see `postconf(5)`):

- `milter_connect_timeout` (default `30s`)
- `milter_command_timeout` (default `30s`) — applies per milter
  command, including `EndOfMessage`; if Attachra's policy processing
  (e.g. uploading large attachments to S3) can take longer than this,
  raise it accordingly, or lean on milter protocol v6 progress
  notifications (not yet used by Attachra's adapter — see the spike
  doc's risk #5) to avoid a spurious timeout.
- `milter_content_timeout` (default `300s`) — the overall budget for
  header/body/end-of-message processing.

Keep Postfix's timeouts comfortably larger than
`limits.milter_timeout` (Attachra's own per-session cap) so Attachra's
own timeout fires first and produces a deliberate fail-open/fail-closed
response, rather than Postfix unilaterally giving up first.

## Archiving/journaling milter order

If your environment also runs a compliance/journaling archiver (a
separate milter, e.g. MailArchiva in its milter mode, or an
`always_bcc`-style BCC copy), where you put it relative to Attachra in
`smtpd_milters` decides **which version of the message it sees**:
the original with the attachment still attached, or Attachra's
rewritten version (attachment stripped, replacement block + download
link inserted).

Postfix invokes milters in `smtpd_milters` strictly in list order —
each milter sees whatever the previous ones already changed. There is
only one queue file per message, so an `always_bcc`/`sender_bcc_maps`/
`recipient_bcc_maps` copy always reflects the state *after every
milter in the chain has run*, regardless of where Attachra sits; to
capture the message *before* Attachra rewrites it, the archiver must
be a milter of its own, positioned earlier in the list.

### Scenario A: archive before Attachra (archiver sees the original)

```
# main.cf
smtpd_milters = inet:127.0.0.1:8092, inet:127.0.0.1:6785
non_smtpd_milters = inet:127.0.0.1:8092, inet:127.0.0.1:6785
```

(`inet:127.0.0.1:8092` stands in for the archiving milter; adjust to
its actual listen address.) The archive gets a complete, self-contained
copy of the message with the attachment still present — it does not
depend on Attachra's storage, retention, or revoke state staying
available for as long as the archive is required to exist. The
trade-off is storage: the attachment is now duplicated between the
archive and Attachra's own storage, which is exactly the "attachments
everywhere" problem Attachra otherwise avoids.

### Scenario B: archive after Attachra (archiver sees the rewritten message)

```
# main.cf
smtpd_milters = inet:127.0.0.1:6785, inet:127.0.0.1:8092
non_smtpd_milters = inet:127.0.0.1:6785, inet:127.0.0.1:8092
```

Equivalently, a plain `always_bcc`/`*_bcc_maps` archiver (no milter of
its own) always lands in this scenario, because it only ever sees the
final queue file. The archive gets the replacement block and a link,
not the file. This avoids duplicating storage, but makes the archive's
completeness depend on Attachra's `storage.retention` policy covering
the same (or longer) retention window the archive is legally required
to meet, and requires that legal-hold-flagged messages have revoke
blocked by policy — otherwise the archived "record" can outlive the
file it points to.

### Recommendation

- **Environments with a WORM/immutable-archive or long-term
  recordkeeping obligation** of their own: use **Scenario A**. This is the only option where the
  archive's completeness does not depend on Attachra staying up,
  correctly configured, and un-revoked for the archive's entire
  retention window.
- **Everything else** (the common self-hosted case, no archiver-specific
  recordkeeping obligation): Scenario B is the reasonable default —
  it keeps Attachra's "don't duplicate attachments" value proposition
  intact — provided retention/legal-hold is configured per the note
  above.
- This is entirely an operator-side `smtpd_milters` decision — Attachra
  has no visibility into whether an archiving milter exists or where it
  sits in the chain, and cannot enforce either scenario. Whether your
  archive needs to be self-contained (Scenario A) or can safely point
  at Attachra's storage (Scenario B) usually comes down to a retention
  or recordkeeping obligation specific to your organization/industry —
  this document only covers the Postfix mechanics, not what any given
  obligation requires; check with your own compliance/legal function for
  that determination.

This is a separate concern from [DKIM signing order](dkim.md) (which
has one non-negotiable rule: Attachra before the signer, always) and
from the [grommunio pilot's rspamd-then-Attachra
order](../deploy/grommunio-debian.md#how-mail-flows-on-grommunio) (a
spam/AV milter ordering decision, unrelated to archiving). rspamd (or
whichever milter does spam/AV scanning) must still run before Attachra
regardless of archiving order: Attachra uploads attachments to storage
and hands out a public `/p/` download link, so scanning has to happen
first — running rspamd after Attachra would mean an infected or
spam-flagged attachment already left the mail system before it was
scanned. A given `smtpd_milters` list typically has to satisfy all
three orderings at once — e.g. `archiver, rspamd, attachra, opendkim`
for Scenario A on a DKIM-signing host that also runs rspamd. In that
combined example rspamd's `dkim_signing` module must be **disabled**
(`enabled = false` in `local.d/dkim_signing.conf`) — opendkim is the
signer and runs after Attachra; leaving `dkim_signing` enabled makes
rspamd sign before Attachra rewrites the body, which breaks the
signature. See [DKIM signing order](dkim.md).

## Verifying the integration

1. Confirm Postfix can reach Attachra's listen address:
   `postfix status` plus a manual `nc`/`socat` probe of the configured
   `inet:`/`unix:` address.
2. Send a test message through Postfix and confirm it is delivered
   (see `hack/sendmail-test` for a local test message generator).
3. Check Attachra's logs for a milter session log entry correlated by
   queue ID (Postfix logs the same queue ID in `maillog`/`journalctl
   -u postfix`), confirming the message was actually seen by the
   adapter and not silently skipped.

## Known gaps (not yet validated)

- Real interop testing against a live Postfix instance (chunked
  `ReplaceBody` beyond 64 KiB, macro negotiation quirks) is tracked as
  T-2.1.5 and requires the Docker-based compose environment
  (`deploy/dev/docker-compose.yml`); it has not been run in this
  environment (Docker unavailable). `test/e2e/e2e_test.go` already
  contains a skeleton that skips itself when the compose stack is not
  reachable.
- Progress-notification support (milter protocol v6) for long-running
  attachment processing is not implemented; long-running `EndOfMessage`
  work should be kept under `milter_command_timeout`/
  `milter_content_timeout` until it is.
