# Storage retention and the background sweep

This is the operator-facing reference for Attachra's storage-retention
cleanup job (US-5.3, `internal/core/retention`): what it does,
how to size/tune it, what its Prometheus metrics mean, and what to
expect after upgrading from a release that predates it. For the
security-relevant residual limitations of this design (not bugs — known,
accepted trade-offs), see
[docs/security/threat-model.md](../security/threat-model.md) §3, threat
T3.5.

## What retention is, and how it differs from a link's TTL

Every `replace`d attachment has two independent lifetimes:

- **The link's TTL** (`ttl` in a policy rule, or `links.default_ttl_seconds`
  in config) — how long the *download link* stays usable. Once it
  expires, the link 404s, but the underlying object may still exist in
  storage.
- **The attachment's retention** (`retention` in a policy rule, or
  `links.default_retention_seconds` in config) — how long the *storage
  object itself* is kept before the background sweep deletes it.

A link must never outlive the object it points to, so retention is
always resolved to be at least as long as ttl — see
[docs/architecture/policy-format-v1.md §2.4](../architecture/policy-format-v1.md)
for the full clamping rules and the warning log that surfaces it
when it fires.

## Configuration

```yaml
links:
  default_ttl_seconds: 2592000        # 30d — link lifetime fallback
  default_retention_seconds: 2592000  # 30d — object lifetime fallback; must be >= default_ttl_seconds (config load fails otherwise)

retention:
  enabled: true
  interval_seconds: 3600  # how often a sweep pass runs
  chunk_size: 200         # attachments fetched per DB round trip within a pass (ADR-011's "chunked DELETE" guidance)
```

`links.default_retention_seconds` shorter than `links.default_ttl_seconds`
is rejected at config load time (a global misconfiguration is caught up
front, not silently patched at runtime) — this is different from a
*per-policy-rule* `retention` shorter than that rule's `ttl`, which is
allowed by the policy format (see below) and clamped, not rejected, since
policy-file authoring is expected to be more exploratory than a global
config default.

## Observability: Prometheus metrics

The sweep exposes two counters under `/metrics` (namespace `attachra`):

- **`attachra_retention_cleanups_total{result="deleted"|"held_skipped"|"error"}`**
  — one increment per attachment the sweep actually processed in a pass,
  labeled by outcome. There is no separate "scanned" counter: the total
  number of attachments a pass looked at is the sum across all three
  labels (`sum(attachra_retention_cleanups_total)`), so a dedicated
  scanned counter would only duplicate that sum under a different name.
- **`attachra_retention_expired_links_total`** — a plain counter (no
  labels) of `Link` rows marked expired by the sweep's `ExpireStaleLinks`
  step. This is a distinct population from the attachment-level counter
  above: a link typically expires (its own `ttl` elapses) well before its
  underlying attachment's separate, longer `retention` deadline is
  reached, so it cannot be derived from `retention_cleanups_total`.

Example PromQL for a dashboard panel:

```promql
# Attachments the sweep is currently failing to purge (investigate storage backend health)
sum(rate(attachra_retention_cleanups_total{result="error"}[5m]))

# Attachments protected by legal hold across recent sweeps
sum(rate(attachra_retention_cleanups_total{result="held_skipped"}[1h]))

# Total attachments scanned per sweep interval
sum(increase(attachra_retention_cleanups_total[1h]))
```

Every attachment deletion (and hold-skip, and error) is also individually
recorded as a `retention_cleanup` audit event (`attachra audit export`
or the `/api/v1/audit` resource), which is the authoritative,
per-attachment trail; the metrics above are for alerting/dashboards, not
for reconstructing exactly which attachment was deleted when.

## Upgrading from a pre-retention release: the legacy sentinel

Migration `000004_attachments_retention` adds the `retain_until` column
with `DEFAULT ''`. Every attachment row created **before** that migration
ran — i.e. anything uploaded by a pre-US-5.3 release — keeps that empty
string. The sweep's queries (`ListExpiredAttachments`,
`CountHeldExpiredAttachments`) deliberately treat an empty `retain_until`
as "no retention recorded" and exclude those rows from cleanup entirely,
rather than treating the empty value as "already expired, delete it now"
(which would have deleted a stranger's old attachments the instant the
new binary started, with no chance to review).

**Practical consequence:** after upgrading a long-running deployment,
whatever attachments were uploaded before the upgrade are never
automatically deleted by the sweep, no matter how old they get. This is
by design (a fail-safe default, not a bug), but it is a real operator
surprise if unaccounted for — both a storage-volume concern (those
objects sit in the bucket/filesystem indefinitely) and a GDPR
data-minimization concern (art. 5(1)(e): storage limited to what is
necessary) if the deployment's retention policy assumes everything is
being swept.

To check whether this affects your deployment, count the legacy rows
directly against the metadata DB (sqlite):

```sql
SELECT COUNT(*) FROM attachments WHERE retain_until = '';
```

A non-zero count means there are pre-upgrade attachments that will never
be swept by the background job. **A one-time backfill/admin command to
set `retain_until` on these legacy rows was considered during an earlier
review and deliberately deferred, not built**: at the time of
writing, every known deployment (including the grommunio pilot) is
recent enough that this population is small or empty, so building a
dedicated backfill tool ahead of an actual operator need was judged
premature scope. If your deployment has a large legacy population and
needs this, please open an issue — it is a well-understood, bounded
addition (an admin CLI/API call that sets `retain_until = now +
configured_default_retention` for every row where `retain_until = ''`,
gated the same way other destructive-adjacent admin operations are)
rather than an open design question.

## See also

- [docs/architecture/policy-format-v1.md](../architecture/policy-format-v1.md)
  §2.4 — the `ttl`/`retention` policy fields and the clamp/warning rules.
- [docs/security/threat-model.md](../security/threat-model.md) T3.5 — the
  accepted residual risks around this design (legacy sentinel, an
  audit-less deletion on a mid-purge crash, and a narrow hold-observability
  gap), and T5.2 for the audit `Details` field's trust-boundary
  convention.
- Legal hold's interaction with retention cleanup: events tied to a
  held message survive truncation regardless of age (see the legal-hold
  guarantees in [docs/architecture/audit-retention.md](../architecture/audit-retention.md)).
