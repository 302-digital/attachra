# Attachra — Community / Enterprise Boundary (v1)

> Author: atr-product-lead · Date: 2026-07-04
> Status: **approved by the founder on 2026-07-06** (including OQ-1, OQ-2, OQ-4, OQ-6 —
> the recommended options were adopted; OQ-3 and OQ-5 remain open until their
> own deadlines). Recorded as ADR-015 in the internal ADR registry.
> Publication to the outside world happens together with the repository showcase.

## Summary (10 lines)

1. **The boundary rule (ADR-004):** Community = production-ready forever; Enterprise = **additional value**, not withheld features. We never move a feature from Community into the paid tier (the MinIO relicensing precedent directly killed that project's community trust).
2. **What must be entirely in Community** (otherwise we cannot be recommended as "the Rspamd of attachments", ADR-010): the full cycle of **replace + revoke + audit + Web UI + REST API + CLI + Policy Engine** for a single administrator / single domain.
3. **What is sold in Enterprise:** the compliance story for regulated companies — **reporting, integrations (identity/SIEM), ready-made Policy Packs, multi-domain management** — things a solo admin doesn't need but a regulated company must have.
4. **What is never monetized:** infrastructural capabilities (HA, the Postgres backend, scaling, reliability) — that's architecture, not a feature. You cannot charge for "the right to run reliably."
5. **The separation mechanism is plugins (ADR-003), not a separate binary (ADR-003, Vision).** One AGPL binary; Enterprise packs are proprietary WASI plugins under a commercial license (ADR-012).
6. **Postgres is Community (opt-in infrastructure).** See the dedicated breakdown below. Recommendation: it stays free, including the HA configuration.
7. **Enterprise packs v1 (from the Vision doc):** Identity, Compliance, Security, Cloud, Notification, AI. For v1, the priority is **Compliance + Identity** (that's where the regulated-segment money is, per pre-MVP customer discovery interviews).
8. **Upgrade triggers are event-based, not paywalls:** an auditor requested a standards report; the company is rolling out SSO; the SIEM team wants a connector; a second/third mail domain appears. The product surfaces this gently (an empty state + "available in the pack"), with no nagging and no limits.
9. **Contested questions with a decision deadline** are captured in the "Open Questions" section — the founder closes them before the public release (a blocker for the repository showcase).
10. **This is a public promise.** The list of "things we will never do" (the "Anti-patterns" section) is published as a commitment to the community and builds trust more than the license text alone.

---

## 1. Capability-to-edition table

Legend:
- **Community forever** — free, open-source (AGPL), production-ready, will never move to the paid tier.
- **Enterprise pack: <name>** — a proprietary plugin under a commercial license.
- **Decide later (deadline)** — contested, requires a founder decision by the stated date.
- Packs (per the Vision doc): **Identity / Compliance / Security / Cloud / Notification / AI**.

### 1.1 Pipeline core (a solo admin's pain — entirely in Community)

| Capability | Backlog | Edition | Rationale |
|---|---|---|---|
| Postfix Milter adapter | E2 | **Community forever** | The product's entry point; without it there is no "Rspamd for attachments." |
| fail-open / fail-closed | US-2.2 | **Community forever** | Reliability on the mail-delivery path is a base invariant, not a feature. |
| Attachment MIME detection (magic bytes, RFC 2231/2047) | E3 | **Community forever** | Without reliable detection, policies are meaningless. |
| MIME rewrite → link replacement block (template, RU/EN) | US-3.2 | **Community forever** | The core "attachment → link" value. |
| Policy Engine (declarative YAML: sender/recipient/attachment; replace/pass/block; priority; default) | E4 | **Community forever** | ADR-006: a business user changes rules without touching code. The engine is free. |
| Hot reload + policy dry-run | US-4.2 | **Community forever** | Operational safety; expected in any serious tool. |
| Storage: S3 / MinIO / Ceph / Filesystem | E5, ADR-007 | **Community forever** | S3 compatibility is baseline; four drivers out of the box. |
| Retention policies (file storage lifetime) | US-5.3 | **Community forever** | See the breakdown below — this is data hygiene, not an enterprise feature. |
| Link Engine: personal link per (attachment × recipient), TTL, download limit, ≥128-bit token | E6 | **Community forever** | The core differentiator; personal links = targeted revocation. |
| Recipient file download (streaming, error pages, accounting) | US-6.2 | **Community forever** | The product doesn't work without this. |
| **Revoke** (link / message / sender, cascading) | US-6.3 | **Community forever** | **The strongest and least-solved pain point, per pre-MVP customer discovery interviews.** Taking it away would be suicidal — it kills both adoption and the compliance story. We sell the *report about* revocation, not revocation itself. |

### 1.2 Management and observability (a solo admin — entirely in Community)

| Capability | Backlog | Edition | Rationale |
|---|---|---|---|
| Audit log (processing/decision/download/revoke) | US-7.1 | **Community forever** | Basic audit is part of the admin's pain and the compliance foundation. The log itself is free; standards-formatted reports are Enterprise (see below). |
| Audit export (JSON lines) | T-7.1.3 | **Community forever** | Raw export — yes. Formatting for a specific standard/signature — the Compliance Pack. |
| Prometheus metrics + health/readiness | US-7.2 | **Community forever** | Observability is operational hygiene, not a paid feature. |
| Aggregated statistics (by day/policy) | T-7.2.2 | **Community forever** | Needed by a solo admin for a dashboard. |
| REST API (OpenAPI, messages/links/policies/stats/audit, token auth, admin/viewer roles) | E8 | **Community forever** | Core Principle: API-first. Cutting the API means cutting the product. |
| CLI `attachractl` (policy/links/stats/audit, `--json`) | E9 | **Community forever** | An admin and scripting tool; dogfoods the API. |

### 1.3 Web UI (a solo admin — entirely in Community; contested features below)

| Capability | Backlog | Edition | Rationale |
|---|---|---|---|
| Dashboard (volumes, recent events) | US-10.1 | **Community forever** | **The MinIO lesson: stripping the admin Web UI out of Community is fatal.** The UI is part of "production-ready." |
| Search for a message/attachment/link + revoke from the UI | US-10.2 | **Community forever** | Reacting to an incident from the UI is core value for an admin. |
| Viewing policies + the audit log in the UI | US-10.3 | **Community forever** | Configuration visibility; read-only viewing is baseline. |
| **Compliance dashboards/reports in the UI** (ready-made views for GDPR/HIPAA/PCI) | — (post-MVP) | **Enterprise pack: Compliance** | This isn't "a UI" in general — it's a specialized reporting layer on top. The UI shell is Community; the ready-made compliance views are a plugin. |
| **RBAC beyond admin/viewer** (custom roles, delegation by domain/group) | — | **Enterprise pack: Identity** | admin/viewer are in Community. Fine-grained RBAC matching an org structure is an enterprise need. |

### 1.4 Contested capabilities (explicit breakdown)

| Capability | Edition | Rationale |
|---|---|---|
| **SSO / OIDC / SAML** (admin/UI authentication) | **Enterprise pack: Identity** | A classic open-core boundary. A solo admin is well served by API tokens + admin/viewer (Community). SSO becomes necessary once a company has an IdP — and that is exactly the signal of a paying customer. OIDC/SAML/LDAP plugins are already scoped as enterprise in the Vision doc. |
| **LDAP / Active Directory** (user directory) | **Enterprise pack: Identity** | Same reasoning. Community doesn't need a directory; AD integration is enterprise identity infrastructure. |
| **Policies matched on AD groups** | **Enterprise pack: Identity** | Requires the AD integration (the pack itself). The Community Policy Engine already matches on sender/recipient/domain/mask — that's enough for a solo admin. Matching on AD groups is an identity layer on top. |
| **Compliance reports** (ready-made GDPR/HIPAA/PCI/NIS2 reports, audit-ready formatting, signing/integrity) | **Enterprise pack: Compliance** | **This is literally "selling the compliance story."** Raw audit + JSONL export is Community; a report "formatted for a standard, for an auditor" is Enterprise. We're not taking data away, we're adding packaging. |
| **Policy Packs** (GDPR, PCI DSS, HIPAA, NIS2, Finance, Gov, Healthcare, Legal) | **Enterprise pack: Compliance** (marketplace: Official/Verified tiers are paid; Community tier is free) | The policy engine is Community (ADR-006). Ready-made, **certified** templates for specific regulations are Enterprise/marketplace (ADR-005). The community can write and share its own packs for free. |
| **SIEM integrations** (Splunk, Elastic, Wazuh, QRadar) | **Enterprise pack: Security** | Audit export (JSONL) and Prometheus are Community — anyone can pull the logs. A ready-made **connector** for a specific SIEM with field mapping/CEF is an enterprise integration. Trigger: the customer has a SOC/SIEM team. |
| **Retention policies** | **Community forever** | Breakdown: this is data hygiene and often a **mandatory** non-accumulation mechanism (GDPR data minimization). Taking it away would mean charging people to comply with the law for free — an anti-pattern. **Setting** the retention period is Community. Enterprise adds a **compliance report** about retention (Compliance Pack), not the capability itself. |
| **Multi-domain support** (one installation serving N mail domains with separate policies/audit/tenant isolation) | **Enterprise pack: Identity** (multi-tenant) — but see the deadline below | One domain / one org is Community (matches the "installation = one mail domain" model, ADR-011). Managing many domains from one installation with isolation is an MSP/enterprise scenario. **The boundary of "how many domains count as one" needs a decision (see Open Questions).** |
| **HA / Postgres backend** | **Community forever (infrastructure)** | **Already architecturally opt-in (ADR-011). This cannot be paid for — it's infrastructure, not a feature.** Full breakdown in section 4. |
| **Multi-domain compliance reports / cross-tenant audit** | **Enterprise pack: Compliance** | A consequence of multi-domain support; reporting across many tenants is enterprise. |

### 1.5 Enterprise packs v1 — final line-up (from the Vision doc)

| Pack | What's inside (v1) | Who we sell it to | v1 priority |
|---|---|---|---|
| **Identity** | SSO (OIDC/SAML), LDAP/AD, AD-group policy matching, RBAC beyond admin/viewer, multi-tenant | Companies with an IdP/AD; MSPs | **High** (the "rolled out SSO" funnel) |
| **Compliance** | Ready-made reports (GDPR/HIPAA/PCI/NIS2), certified Policy Packs, a retention compliance report, standards-ready audit | Regulated companies (healthcare/finance/legal/gov) | **High** (where the money is, per pre-MVP customer discovery interviews) |
| **Security** | SIEM connectors (Splunk/Elastic/Wazuh/QRadar), YARA/ICAP/VirusTotal hooks (future inbound work) | Companies with a SOC/SIEM | Medium |
| **Cloud** | Azure Blob / GCS / Wasabi / Backblaze drivers | Multi-cloud enterprises | Medium (S3/MinIO/Ceph/FS are already in Community) |
| **Notification** | Slack / Teams / Telegram alerts for events/incidents | Companies with ChatOps | Low |
| **AI** | Attachment classification, anomaly detection, policy authoring assistance | Post-MVP | Low (post-MVP) |

> The principle behind every pack: **it adds value around the core, it never withholds a core function.** Remove any pack and Community remains a fully functional product for a solo admin.

---

## 2. Upgrade triggers (event-based, no paywalls, no nagging)

An upgrade happens not when "the limit runs out" (there are no limits), but when **an event happens in the organization's life** that creates an enterprise need. The product recognizes the moment and **gently** surfaces the relevant pack — once, in context, with no repeated nagging.

| Trigger event | Natural need | Pack | How the product shows it (gently) |
|---|---|---|---|
| **An auditor requested a standards report** (GDPR/HIPAA/PCI/NIS2) | A ready-made standards report, not raw JSONL | Compliance | The "Audit" section has a "Compliance reports" tab with an empty state: "Ready-made GDPR/HIPAA/PCI reports are available in the Compliance Pack. Raw export is available here → [Export JSONL]." Data is never locked away. |
| **The company is rolling out SSO / a corporate IdP appears** | Admin login via OIDC/SAML instead of tokens | Identity | On the "Users/Access" page: "Using Okta/Azure AD/Keycloak? Single Sign-On is available in the Identity Pack." admin/viewer + tokens keep working for free. |
| **Active Directory appears / group-based policies are needed** | Policy matching on AD groups, a directory | Identity | In the policy editor, where sender/recipient is chosen: "Want a condition based on an AD group? → Identity Pack." Domain/address conditions stay free. |
| **The SIEM team asks for a connector** (Splunk/Elastic/QRadar/Wazuh) | A ready-made connector with field mapping | Security | Under "Integrations": "Sending audit data to a SIEM? Ready-made connectors are in the Security Pack. For now: JSONL export / Prometheus / webhook." |
| **A second/third mail domain appears** | Separate policies/audit/isolation per installation | Identity (multi-tenant) | When adding a second domain: "Managing multiple domains from one installation is in the Identity Pack. Everything is free for a single domain." |
| **A regulator requires cross-domain reporting** | Consolidated audit across tenants | Compliance | A continuation of the multi-domain scenario. |
| **Slack/Teams alerts are needed on incidents** | ChatOps notifications | Notification | In event settings: "Slack/Teams/Telegram notifications are in the Notification Pack. A webhook is available for free." |

Display principles (mandatory, part of the promise):
- **We never block an existing free feature just to "show off" a pack.** There is always a free path (JSONL/webhook/Prometheus/tokens).
- **An empty state, not a nag modal.** The information lives where the user already is, working on their own task.
- **Once, no repeats.** No pop-up "buy Enterprise" on every login.
- **Honest value statements**, not FOMO: exactly what the pack adds and what is already free.

---

## 3. Anti-patterns — a public promise of "things we will never do"

This is a commitment to the community (published in the README / docs / trademark policy). Breaking any of these destroys trust faster than a license change would (the MinIO relicensing precedent).

1. **We will never move an existing Community feature into the paid tier.** What became free stays free (ADR-004). Especially: the admin Web UI, revoke, audit, the Policy Engine, the REST API, the CLI.
2. **We will never introduce volume limits in Community:** number of messages, attachments, links, domains-as-a-volume-metric, storage gigabytes, audit events — none of these are artificially capped.
3. **We will never introduce user/seat limits in Community.** No "free for up to N admins."
4. **We will never make reliability/HA/scale paid.** Postgres, replication, horizontal scaling of stateless layers — that's infrastructure, not a feature (ADR-011, section 4).
5. **We will never force telemetry.** Telemetry is **opt-in only**, off by default, and the product works fully without it. No "enable telemetry to unlock X."
6. **We will never ship a separate "crippled" Community binary.** One binary for everyone (ADR-003, Vision); Enterprise is added plugins, not a different build.
7. **We will never lock a user's own data behind a paywall.** Audit, metrics, and configuration are always exportable in open formats (JSONL, Prometheus, YAML) from Community.
8. **We will never put a "time-bomb"/delayed-open-source license (BUSL/FSL) on the core.** The core is AGPL, OSI-approved, now and forever (ADR-012).
9. **We will never nag with paywalls.** Upgrades are surfaced event-based and once (section 2), with no blocking modals and no repeating banners.
10. **We will never break "15 minutes from install to the first rewritten message" for the sake of monetization.** Community time-to-value is an untouchable product parameter.

---

## 4. Contested question: the Postgres backend (ADR-011) — Community or Enterprise?

**Recommendation: the Postgres backend, including the HA configuration, stays in Community forever. This is infrastructure, not a monetizable feature.**

### Why this is contested at all
Postgres unlocks horizontal scaling and HA (stateless download/API/milter layers behind a load balancer against a shared Postgres — ADR-011). "HA" is a classic enterprise label, and the temptation to charge for it is real.

### Why it cannot be paid (the arguments)

1. **ADR-004, "no artificial limits."** Forcing a large self-hosted installation to either live with single-node SQLite or pay just for the right to use a different DB backend is exactly the kind of artificial limit ADR-004 forbids. The DB backend is a deployment detail, not consumer value.
2. **HA is also needed by large self-hosted non-paying users.** This was stated explicitly during scoping: a university, a large nonprofit, or an infrastructure enthusiast running 5,000 mailboxes has every right to fault tolerance without buying a license. Selling them "reliability" means saying "your mail may lose availability unless you pay" — which undermines invariant #3 (a message can never be lost) and our reputation on the delivery path.
3. **Architecturally, this is already opt-in, not a "feature."** ADR-011: Postgres is selected via config (`database.driver: postgres`), using the same portable SQL logic and the same guarded UPDATE. There is no separate enterprise functionality in the code — there is a second repository driver. Selling a "config switch" would be absurd and technically dishonest.
4. **AGPL and open-core mechanics.** The core is AGPL (ADR-012). The Postgres driver lives in the core (`internal/core`/the store adapter), not in a proprietary WASI plugin. Monetizing AGPL core code via a paywall in the same binary isn't possible without an artificial "community/enterprise build" split — which anti-pattern #6 directly forbids.
5. **Precedent.** None of our reference projects (Rspamd, Grafana) charge for choosing a storage backend — that's hygiene, not a product.

### What gets monetized nearby (without taking HA away)
- **Enterprise Postgres operations as a service/support offering**, not as a code feature: SLAs, help with Patroni/RDS/Cloud SQL, managed hosting — but that's a **support business** (the Rspamd model), not an in-product paywall.
- **Multi-tenant on top of Postgres** (multi-domain support, cross-tenant reporting) — that's the Identity/Compliance Pack, and customers pay for **tenant isolation and consolidated reporting**, not for Postgres itself. HA for a single domain is free.

### Bottom line
Postgres (and the HA topology built on it) is **Community forever**. This confirms and reinforces ADR-011 ("Postgres as an opt-in backend"): opt-in means a configuration choice, not an edition choice. We monetize **around** it (support, multi-tenant, compliance), but never **the right to run reliably itself**.

---

## 5. Open questions — founder decisions from 2026-07-06

**Decided:**
- **OQ-1 → (c):** Community does not limit the number of domains; tenant
  isolation (separate policies/audit/admins per domain) is the Identity Pack.
- **OQ-2 → (b):** 1–2 fully functional free Policy Pack examples, plus freedom
  for the community to share its own; certified packs mapped to specific
  standard clauses, with updates, are the Compliance Pack.
- **OQ-4 → (b):** Community ships three roles — admin / viewer / auditor
  (read-only audit). Fine-grained RBAC/delegation is the Identity Pack.
  **→ a requirement carried into E8.**
- **OQ-6 → (a):** S3/MinIO/Ceph/FS are Community; Azure Blob/GCS/Wasabi are the Cloud Pack.

**Still open (non-blocking):** OQ-3 (generic webhook — tied to the notifications
epic), OQ-5 (the "pack/add-on" wording — tied to the repository showcase, with atr-content).

Original options table (for the record):

| # | Question | Options | Recommendation | Decision deadline |
|---|---|---|---|---|
| OQ-1 | **Multi-domain boundary:** how many domains count as "one" (Community)? One mail domain? One tenant? Do aliases/subdomains count? | (a) exactly 1 primary domain; (b) 1 org with any aliases/subdomains; (c) no limit on the number of domains, but no tenant isolation — isolation is Enterprise | **(c)**: Community does not limit the number of domains (no limits, anti-pattern #2), but **isolation/separate tenant management** is the Identity Pack. "Many domains" ≠ "multi-tenant." | Before the repository showcase — affects the public promise |
| OQ-2 | **Certified Policy Packs vs free templates:** exactly where does the line fall between "a sample GDPR policy (Community)" and "a certified Compliance Pack (Enterprise)"? | (a) any template is free, we only charge for reports; (b) basic examples are free, "certified turnkey" ones are paid | **(b)**, but with 1–2 free, real (not toy) examples so the engine is clearly fully functional. | Before M4/the marketplace; does not block the MVP |
| OQ-3 | **Webhook notifications in Community:** ship a basic generic webhook for free (with Slack/Teams/Telegram as the Notification Pack)? | (a) yes, generic webhook is Community; (b) all notifications are a pack | **(a)**: a generic webhook is Community (otherwise the "need alerts" trigger becomes a withheld feature). Ready-made connectors are the pack. | Before the notifications epic (post-MVP) |
| OQ-4 | **RBAC boundary:** only admin/viewer in Community, or also a simple third role (e.g. read-only auditor)? | (a) strictly admin/viewer; (b) + auditor (read-only audit) | Leaning toward **(b)** — a read-only auditor is cheap and covers the base separation-of-duties pain; fine-grained custom RBAC is the Identity Pack. | Before E8 locks down the API roles |
| OQ-5 | **Boundary naming/marketing:** avoid the word "Enterprise" reading as "cut down"? Pack wording in the UI. | — | Phrase packs as "an add-on for X," emphasize "Community is production-ready." Align with atr-content/devrel. | Before the showcase |
| OQ-6 | **Cloud Pack vs Community storage:** S3/MinIO/Ceph/FS are Community; Azure/GCS/Wasabi are the Cloud Pack. Will this read as "they took the clouds away"? | (a) as now (the S3 family is free, proprietary clouds are a pack); (b) all storage is free, Cloud Pack = managed features only | **(a)** is defensible: S3 compatibility (including self-hosted MinIO/Ceph) fully covers the self-hosted case; Azure/GCS are about cloud enterprises, not the self-hosted pain point. But re-check the wording (OQ-5). | Before the E5 driver documentation |

---

## Appendix: relationship to accepted decisions

- **ADR-003** (plugins, not a separate binary) — the Community/Enterprise separation mechanism.
- **ADR-004** (open core, no artificial limits) — the overriding rule behind this boundary.
- **ADR-005** (marketplace: Official/Verified/Community) — the distribution channel for packs and free policy packs.
- **ADR-010** (the "as good as Rspamd" success metric) — why the core must fully cover a solo admin's pain.
- **ADR-011** (SQLite default + Postgres opt-in) — Postgres is Community infrastructure, not an edition.
- **ADR-012** (AGPL core + commercial packs) — the legal basis: the core is AGPL, packs are commercial WASI plugins.
- **The market** (per competitive analysis and pre-MVP customer discovery interviews) — the money is in the regulated segment (compliance/identity/integrations); a solo admin's pain (revoke+audit+UI) must be free for adoption.
