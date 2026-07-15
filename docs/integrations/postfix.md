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
  Postfix retries later. See `docs/Attachra_Backlog.md` (US-2.2) and
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
