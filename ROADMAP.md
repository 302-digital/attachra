# Roadmap

This is where Attachra is going. It is grouped into three release
horizons. **It is directional, not a commitment** — nothing here is a
promise of scope or date, and priorities shift as we learn from real
deployments. For what has actually shipped, see
[CHANGELOG.md](CHANGELOG.md). For live progress, see the issues labelled
[`roadmap`](https://github.com/302-digital/attachra/labels/roadmap) and
the [milestones](https://github.com/302-digital/attachra/milestones).

Attachra is usable today at `v0.1.0`, but **at your own risk**: config,
policy, and API formats are not frozen until `v1.0.0` (SemVer). Each
horizon below moves us closer to that stability commitment.

## v0.2 — Production hardening

Make Attachra safe to run on a busy, multi-node mail host. A PostgreSQL
metadata backend unlocks HA and horizontal scaling (Community forever —
reliability is infrastructure, not a paid feature). Alongside it:
tamper-evident audit checkpoints, correct client-IP handling behind a
reverse proxy, and tighter inline-attachment protection based on real
deployment findings. Formats may still change.

## v0.3 — Operable product

Turn the working pipeline into something you operate without reading Go.
The Community admin web UI arrives on top of the existing REST API
(dashboard, search, revoke, policy and audit views), together with an
official Helm chart, a proper documentation site, and the deliverability
insights view. All of this is Community-forever surface. Formats are
still not frozen.

## v1.0 — Stable formats & supply chain

The stability commitment. The policy file, REST API, and config formats
freeze under SemVer — breaking changes only in a future major. Releases
are signed and verifiable (cosign), the project meets a recognised
open-source security baseline, and recipient-facing text becomes fully
translatable. This is where "at your own risk" is retired for the frozen
surfaces.

---

Attachra is open-core (AGPL-3.0 core + commercial capability packs). The
line between what is free forever and what is sold is a public promise —
see the [open-core boundary](docs/product/open-core-boundary.md). Nothing
on this roadmap moves an existing Community capability behind a paywall.
