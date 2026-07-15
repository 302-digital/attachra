# Attachra

[![CI](https://github.com/302-digital/attachra/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/302-digital/attachra/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/302-digital/attachra)](go.mod)
[![Latest Release](https://img.shields.io/github/v/release/302-digital/attachra)](https://github.com/302-digital/attachra/releases)

**Open Attachment Gateway** — a self-hosted policy engine that governs how
files leave your organization by email.

Attachra is not a mail server. It sits next to one (Postfix today) and
handles a problem your MTA and your spam/AV stack don't: what happens to
*outbound attachments*.

> **Status: v0.1.0 released.** The full pipeline — Postfix milter → MIME
> parsing → policy engine → S3/filesystem storage → personal download link →
> MIME rewrite → audit trail — works end to end and has been **tested in
> production on a live [grommunio](https://grommunio.com/) (Postfix-based)
> mail deployment**. It's usable today — **at your own risk**: config,
> policy-file, and API formats are not yet frozen and may change in a minor
> or patch release. Format stability is guaranteed starting at `v1.0.0`
> (SemVer). See [CHANGELOG.md](CHANGELOG.md) for what shipped in each
> release and [Roadmap](#status--roadmap) for what's next.

---

## The problem

If you run your own mail infrastructure (Postfix, Mailcow, iRedMail,
Mail-in-a-Box, grommunio...), outbound attachments are an unsolved
governance gap:

- **No control over what leaves.** Anyone can attach anything to anyone,
  any size, any sensitivity level. There's no policy layer between "user
  hits send" and "file is gone."
- **Large attachments break email.** You either reject them at the MTA or
  let people paste links to random cloud-drive shares you don't manage
  and can't audit.
- **No revocation.** Once an attachment is sent, it's sent. If a file was
  shared by mistake, or an employee leaves, or a recipient's inbox gets
  compromised, there is nothing you can do.
- **No audit trail.** Who sent what, to whom, when, and who downloaded it —
  answering that today usually means grepping mail logs, if you log
  bodies at all (you shouldn't).

Rspamd solved this for spam. ClamAV solved this for viruses. Nobody has
solved it for attachments — so it's usually "solved" with SaaS DLP
products that require sending your mail metadata (or the mail itself) to
a third party. If you're self-hosting your mail specifically to avoid
that, those products aren't an option.

## What Attachra does

Attachra intercepts outbound mail via a Postfix milter, evaluates each
attachment against your policies, and — where policy says so — replaces
the attachment with a link to a file held in your own S3-compatible
storage. The recipient gets a normal-looking email with a download link
instead of a payload. You get a policy engine, an audit trail, and the
ability to revoke access after the fact.

```
                ┌──────────┐  milter protocol   ┌────────────┐
 Outbound mail  │          │───────────────────▶│  Attachra  │
───────────────▶│ Postfix  │                    │  (milter   │
                │          │◀───────────────────│  adapter)  │
                └──────────┘  rewritten MIME    └─────┬──────┘
                              (attachment → link)     │
                                                      ▼
                                              ┌───────────────┐
                                              │ Policy Engine │
                                              │ (sender, size,│
                                              │  recipient,   │
                                              │  storage...)  │
                                              └───────┬───────┘
                                                      │
                        ┌─────────────────────────────┼──────────────────────────────┐
                        ▼                             ▼                              ▼
               ┌────────────────┐             ┌───────────────┐              ┌───────────────┐
               │ Storage Engine │             │  Link Engine  │              │     Audit     │
               │ (S3 / MinIO /  │             │ (per-recipient│              │ (who sent /   │
               │  Ceph / FS)    │             │  signed link, │              │  downloaded   │
               │                │             │  revocable)   │              │  what, when)  │
               └────────────────┘             └───────────────┘              └───────────────┘
```

The core policy/storage/link/audit logic has no knowledge of Postfix or
milters — it's built to support other mail transports (SMTP proxy,
Exchange, Exim, Stalwart) as adapters later, without touching the core.

## Status & roadmap

**v0.1.0 is released.** The architecture and scope decisions are recorded in
[`docs/Attachra_ADR.md`](docs/Attachra_ADR.md); the milestone breakdown and
what's planned next live in [`ROADMAP.md`](ROADMAP.md) and the repo's
issues and milestones.

1. **M0 — Foundation**: repo layout, CI, local dev environment. Done.
2. **M1 — End-to-end pipeline**: milter → policy → storage → link →
   rewritten MIME. Done (`v0.1.0`).
3. **M2 — Management**: REST API, CLI (`attachractl`), audit, revoke,
   statistics. Done.
4. **M3 — Product**: Web UI, broader OS packaging, public documentation
   site. In progress.

Nothing above is a committed date. Follow [CHANGELOG.md](CHANGELOG.md) and
the repo's issues/milestones for current progress.

## Quickstart

Attachra ships as a Debian package for a native install, or you can try the
whole pipeline locally with Docker Compose. Both paths assume you already
have a Postfix instance (or a Postfix-based mail suite, e.g. grommunio) to
attach the milter to.

### Option A: Debian package + systemd (recommended for a real host)

1. **Download the package.** Every tagged release publishes `.deb` packages
   (linux/amd64 + linux/arm64) and a `SHA256SUMS` checksum file to the
   [GitHub Releases](https://github.com/302-digital/attachra/releases) page.
   On your Debian 13 mail server:

   ```sh
   version=0.1.0   # match the release you want
   curl -LO https://github.com/302-digital/attachra/releases/download/v${version}/attachra_${version}_amd64.deb
   curl -LO https://github.com/302-digital/attachra/releases/download/v${version}/SHA256SUMS
   sha256sum -c SHA256SUMS --ignore-missing
   sudo apt install ./attachra_${version}_amd64.deb
   ```

   Or use the convenience installer (read it first — it only downloads
   the release `.deb`, verifies checksums and runs `apt`):

   ```sh
   curl -fsSL https://attachra.org/install | sudo bash
   ```

   Or build it yourself — no Debian tooling is required to build it, only
   to install it, since Attachra is a cross-compiled static binary
   ([ADR-001](docs/Attachra_ADR.md#adr-001-language)): `make build-deb`
   produces the same `dist/attachra_<version>_amd64.deb`.

   Either way, this installs `/usr/bin/attachra` and `/usr/bin/attachractl`, config
   templates under `/etc/attachra/`, and a systemd unit that's enabled but
   **not started yet**.

2. **Configure it.** The fastest way is the interactive wizard:

   ```sh
   sudo attachra setup
   ```

   It asks for your sending domain(s), public URL, storage backend and
   listen addresses (with live port checks), validates the generated
   config with the same code the daemon uses, and recommends starting
   in **dry-run mode** — decisions are logged to the audit trail but no
   mail is modified until you flip the switch.

   Prefer files? Edit `/etc/attachra/attachra.yaml`: set
   `public_base_url` to the hostname recipients will use to fetch
   attachments (the default storage driver is local filesystem, under
   `/var/lib/attachra/files` — no S3 bucket required to start). Edit
   `/etc/attachra/policy.yaml`: replace the `example.com` placeholder with
   your real sending domain — every other domain passes through
   unmodified by default.

3. **Wire it into Postfix.** Append Attachra to your existing milter chain
   (keep any spam/AV milter, e.g. rspamd, first):

   ```sh
   sudo postconf -e 'smtpd_milters = <your existing milters>, inet:127.0.0.1:6785'
   sudo postconf -e 'non_smtpd_milters = <your existing milters>, inet:127.0.0.1:6785'
   sudo systemctl reload postfix
   ```

   See [`docs/integrations/postfix.md`](docs/integrations/postfix.md) for
   the full `smtpd_milters`/`milter_default_action`/timeout reasoning.

4. **Start it and check health.**

   ```sh
   sudo systemctl start attachra
   curl -s http://127.0.0.1:18080/healthz
   ```

5. **Publish the download page.** Put a reverse proxy in front of
   `http.listen` (default `127.0.0.1:18080`) that exposes only the `/p/`
   path over TLS to the outside world — never `/api/v1` or `/metrics`
   publicly. If you're running grommunio specifically,
   [`docs/deploy/grommunio-debian.md`](docs/deploy/grommunio-debian.md)
   walks through the whole install end to end, including a ready-made
   nginx snippet and the exact rspamd-then-Attachra milter chain.

### Option B: Docker Compose (try it locally, no real Postfix needed)

```sh
git clone https://github.com/302-digital/attachra
cd attachra/deploy/dev
docker compose up --build
```

The prebuilt image behind this compose file is also published on its own
as `ghcr.io/302-digital/attachra` (tagged `vX.Y.Z` per release), if you'd
rather pull it directly than build it locally.

This brings up Postfix (SMTP relay on `localhost:2525`), MinIO
(S3-compatible storage), and Attachra itself, wired together with a
"replace everything" dev policy. Send it a test message with the included
test utility:

```sh
go run ./hack/sendmail-test --smtp localhost:2525 \
    --from sender@attachra-dev.local --to recipient@attachra-dev.local \
    --attach ./somefile.pdf
```

Then watch `docker compose logs -f attachra` to see the milter session,
the policy decision, the upload to MinIO, and the rewritten MIME body with
its download link. This environment is for exploration only — for a real
deployment, use Option A.

## Open-core: what's free, forever

Attachra is open-core. Per [ADR-004](docs/Attachra_ADR.md#adr-004-open-core)
and [ADR-015](docs/Attachra_ADR.md#adr-015-community-and-enterprise-boundary),
the **Community edition covers the complete single-admin product,
forever**:

- the full pipeline: milter adapter, attachment detection, MIME rewrite,
  the declarative policy engine (including hot reload and dry-run);
- per-recipient download links with TTL and download limits, **revocation**,
  the full audit log and its export;
- the admin **Web UI**, **REST API** (admin/viewer/auditor roles) and **CLI**;
- S3-compatible storage (AWS S3, MinIO, Ceph) and filesystem drivers;
- retention policies, Prometheus metrics, SQLite *and* PostgreSQL
  backends including HA topology — reliability is infrastructure,
  not a feature we sell;
- no limits on volume, seats, or number of mail domains.

Enterprise value ships as **additional capability packs** (plugins on
top of the same binary — there is no separate Enterprise build):
Identity (SSO/SAML, LDAP/AD, fine-grained RBAC, tenant isolation),
Compliance (certified policy packs and auditor-ready reports; free
community policy examples stay free), Security (SIEM connectors),
Cloud (Azure Blob / GCS drivers), notifications and AI features.

The rule behind the boundary: **paid packs add value around the core;
they never take capability away from Community.** Pricing isn't final
yet; the shape of the deal is.

## Contributing

The repository structure, coding standards, and PR process are documented
in [CONTRIBUTING.md](CONTRIBUTING.md). Architectural changes go through the
ADR process described there and in
[`docs/Attachra_ADR.md`](docs/Attachra_ADR.md). Participation is governed
by our [Code of Conduct](CODE_OF_CONDUCT.md).

Found a security issue, or thinking about one (milter input handling,
the download endpoint, storage, auth)? Please read
[SECURITY.md](SECURITY.md) before opening a public issue.

For everything else — bugs, feature ideas, questions — use the issue
templates in `.github/ISSUE_TEMPLATE/`.

## License

The Attachra core is licensed under the **GNU Affero General Public
License v3.0 or later** — see [LICENSE](LICENSE)
([ADR-012](docs/Attachra_ADR.md#adr-012-licensing-model)).

- **Core (this repository): AGPL-3.0-or-later.** Run it, modify it,
  self-host it freely; if you offer a modified version as a network
  service, share your modifications with its users.
- **Enterprise packs** are distributed separately as sandboxed plugins
  under a commercial license, for organizations that need the packs or
  the right to keep private modifications.
- **The plugin SDK and plugin ABI** will be published under
  **Apache-2.0**, so third-party plugins — including proprietary ones —
  are not subject to the core's copyleft.

Contributions to the core will require a CLA that includes a binding
pledge: every contribution remains available under an OSI-approved
license, forever. The CLA text is being finalized (legal review) and
will be published before external contributions open.

---

*Attachra aims to be for attachment lifecycle management what Rspamd is
for spam and ClamAV is for antivirus: the thing self-hosted mail admins
install because it's obviously the right tool, not because anyone sold
them on it.*
