# Installing Attachra on a grommunio host (Debian 13)

This guide installs Attachra natively (Debian package + systemd unit,
`deploy/deb/`) alongside an existing [grommunio](https://grommunio.com/)
mail server on Debian 13 (trixie), so outbound attachments from a chosen
sending domain get replaced with revocable, auditable download links.

Attachra is not a mail server and does not replace anything grommunio
already does (rspamd for spam/AV, gromox/Postfix for delivery). It adds
one more milter to the existing chain and one more nginx location for
the download page.

## How mail flows on grommunio

Understanding this matters because it determines exactly which Postfix
settings Attachra needs to hook into, and why both of them:

- **Outbound mail from grommunio's own users** is composed and queued by
  gromox, which hands it to the local Postfix instance over SMTP
  (`smtp:25` on `localhost`) for actual delivery. This traffic goes
  through `smtpd_milters`.
- **Outbound mail submitted directly by an MUA** (a mail client
  configured to send via grommunio, rather than through gromox's own
  composer) arrives on the MSA submission port, `587`, tagged with
  `milter_macro_daemon_name=ORIGINATING`. This also goes through
  `smtpd_milters` — Postfix does not distinguish it at the milter-chain
  level.
- **Mail injected locally** (`sendmail(1)`, cron jobs, system
  notifications) bypasses `smtpd` entirely and goes through
  `non_smtpd_milters` instead.

A stock grommunio host already has **rspamd** wired into both milter
chains (typically `inet:localhost:11332`) for spam/AV filtering. Attachra
is appended after rspamd, not swapped in for it: rspamd's verdict should
be settled — and the message rejected if it's spam/malware — before
Attachra spends effort uploading attachments and rewriting the message.
Both chains get Attachra appended, since either one can carry outbound
mail with attachments depending on how it entered the system. See
`deploy/deb/examples/postfix-milter.cf` for the exact `postconf`
settings this implies.

## Prerequisites

- Debian 13 (trixie) host running grommunio.
- Root or sudo access.
- The domain(s) whose outbound mail you want Attachra to police (e.g.
  `example.com`).
- `postconf -n smtpd_milters non_smtpd_milters` output from this host,
  so you can append to the real values rather than guess them.

## 1. Install the package

Build the `.deb` from the Attachra source tree (on any machine — the
build is cross-compiled, no Debian tooling required to *build* it, only
to *install* it):

```sh
make build-deb
```

This produces `dist/attachra_<version>_amd64.deb`. Copy it to the
grommunio host and install it:

```sh
sudo apt install ./attachra_<version>_amd64.deb
```

`apt` resolves and installs the (minimal — attachra is a static
binary, ADR-001) dependency closure automatically. The package:

- installs `/usr/bin/attachra` and `/usr/bin/attachractl` (static
  linux/amd64 binaries, no runtime dependencies of their own);
- installs `/etc/attachra/attachra.yaml` and `/etc/attachra/policy.yaml`
  as dpkg conffiles (your edits survive future upgrades);
- installs and **enables but does not start**
  `/lib/systemd/system/attachra.service` — see below for why;
- installs integration examples under `/usr/share/attachra/examples/`.

After install, `apt`/dpkg prints a reminder (from the package's
postinst) that the service is enabled but not started yet, and what to
do before starting it. That's exactly the next three steps.

## 2. Configure Attachra

### Option A: `attachra setup` (recommended)

`attachra setup` is an interactive wizard that generates both
`/etc/attachra/attachra.yaml` and `/etc/attachra/policy.yaml` for you —
sender domain(s), public hostname, storage backend, listen addresses,
failure mode — and starts the policy in dry-run mode by default (logs
would-be decisions without touching mail, so you can verify behavior
before enforcing it):

```sh
sudo attachra setup
```

It refuses to overwrite an existing `attachra.yaml`/`policy.yaml`
unless you pass `--force`, and validates everything it generates
(`config.Load` + `policy.Parse`, the same checks the running binary
itself applies) before printing next steps — a failed run leaves no
half-written config directory behind. For a scripted/unattended
install, pass `--non-interactive` with the equivalent flags instead of
answering prompts:

```sh
sudo attachra setup --non-interactive \
    --domains example.com \
    --public-base-url https://mail.example.com \
    --storage fs
```

Run `attachra setup --help` for the full flag list (S3 storage,
listen addresses, failure mode, `--dry-run=false` to start enforcing
immediately instead of dry-run). Once it completes, skip ahead to
[step 3](#3-start-attachra) — `attachra setup` already did everything
Option B below does by hand.

### Option B: edit the YAML by hand

Prefer to see and edit every field yourself, or need something the
wizard doesn't ask about (rate limits, retention tuning, etc.)? Edit
the packaged templates directly instead of running `attachra setup`.

#### `/etc/attachra/attachra.yaml`

Open it and set `public_base_url` to your grommunio host's real,
publicly reachable hostname (whatever your grommunio TLS certificate
covers) — this becomes the link recipients click to retrieve an
attachment:

```yaml
public_base_url: "https://mail.example.com"   # <- your real hostname
```

Everything else in the template is already laid out for this host:

- `milter.listen: "inet:127.0.0.1:6785"` — Attachra's own milter
  listener; port 6785 is free on a stock grommunio host.
- `http.listen: "127.0.0.1:18080"` — **not 8080.** grommunio-admin's
  own nginx already listens on `0.0.0.0:8080` (and `8443`) for its
  admin UI on a stock host, so 8080 is taken. If your host's port
  layout differs, verify with `ss -ltnp | grep -E ':(8080|18080)\b'`
  and adjust both this file and the nginx snippet in step 4 together.
- `storage.fs.base_dir: /var/lib/attachra/files` and
  `database.path: /var/lib/attachra/attachra.db` — both under
  `/var/lib/attachra`, matching the systemd unit's
  `StateDirectory=attachra` (the `/var/lib/attachra` directory itself is
  created and owned automatically by `DynamicUser=yes` on every start;
  see `deploy/deb/systemd/attachra.service`). The `files/` subdirectory
  underneath it is created by the `fs` storage driver on first start if
  missing — you don't need to `mkdir` it yourself.

If you later want S3-compatible storage instead of the local
filesystem driver, switch `storage.driver` to `s3` and fill in
`storage.s3.*` — but do **not** put the access/secret key directly in
this file: it's a world-readable conffile (readable by any local user,
because the daemon runs under `DynamicUser` and the runtime UID isn't
knowable at package-install time). Instead:

1. Reference the secret via `${ENV_VAR}` substitution, e.g.:
   ```yaml
   storage:
     driver: s3
     s3:
       secret_key: "${ATTACHRA_S3_SECRET_KEY}"
   ```
2. Put the actual value in `/etc/attachra/attachra.env` (create it
   yourself — it is not packaged), mode `0600`, owned by root:
   ```sh
   printf 'ATTACHRA_S3_SECRET_KEY=...\n' | sudo tee /etc/attachra/attachra.env
   sudo chmod 0600 /etc/attachra/attachra.env
   ```
   `systemd` (running as PID 1/root) reads this file before dropping
   privileges to the service's dynamic user, via the unit's
   `EnvironmentFile=-/etc/attachra/attachra.env` — the secret never
   needs to be readable by the unprivileged service UID.

There is no standalone `attachra config validate` subcommand. After
editing, `systemctl restart attachra` and check `journalctl -u attachra
-e`: an invalid file makes the process exit immediately, before binding
any listener, with a specific error.

#### `/etc/attachra/policy.yaml`

Replace the `example.com` placeholder with your real sending domain(s):

```yaml
rules:
  - name: "example.com senders: replace attachments with a download link"
    when:
      sender:
        domain: ["example.com"]        # <- your real domain(s)
    then:
      action: replace
      ttl: "7d"
      retention: "30d"

default:
  action: pass
```

Every sender domain **not** listed here passes through untouched — this
is the deliberately conservative default so installing the package on a
shared/multi-domain grommunio host doesn't affect mail you haven't
opted in yet.

Validate before reloading:

```sh
attachra policy validate /etc/attachra/policy.yaml
```

Exit code `0` means valid; `1` means it has errors (printed to
stderr); `2` (only with `--strict`) means valid but with warnings.

Full policy grammar (attachment size/mime/extension conditions,
recipient matching, multiple domains, etc.):
`docs/architecture/policy-format-v1.md`.

## 3. Start Attachra

```sh
sudo systemctl start attachra
sudo systemctl status attachra
sudo journalctl -u attachra -f
```

It is already `enable`d (from step 1's install), so it will also start
automatically on future boots.

Quick health check while it's running:

```sh
curl -s http://127.0.0.1:18080/healthz   # liveness — always 200 once the process is up
curl -s http://127.0.0.1:18090/readyz    # readiness — checks DB/storage/policy (admin listener)
```

`/readyz` moved off the `http.listen` port (`18080`) onto a separate
admin listener (`admin.listen`, default `127.0.0.1:18090`) so it never
shares a listener with anything that could end up internet-facing
(`/p/`) — its response body names which dependency is failing, which is
internal topology, not something to put on a public port. `/healthz`
stays on `18080`: it is a static "ok" with no dependency detail, so
there is nothing to protect there, and existing health-check tooling
(this guide, `attachra doctor`, container/orchestrator probes) already
targets that port for it. `attachra doctor` checks both `/healthz` and
`/readyz` on their respective listeners automatically — see
`admin.listen` in `attachra.yaml` (`man attachra.yaml`) if you need to
change the admin address, e.g. because `18090` is already in use on
your host. (The default is deliberately not `9090` — that is
Prometheus's own default listen port, the most likely co-located
neighbor, and binding it here would risk colliding with a local
Prometheus server.)

## 4. Publish the download page through nginx

Attachra's `/p/<token>` package/download page needs to be reachable from
the outside world (recipients click the link in their email); nothing
else on Attachra's HTTP listener should be.

```sh
sudo cp /usr/share/attachra/examples/nginx-grommunio.conf \
        /etc/grommunio-common/nginx/locations.d/attachra.conf
sudo nginx -t && sudo systemctl reload nginx
```

grommunio-common includes every `*.conf` under
`/etc/grommunio-common/nginx/locations.d/` inside its own main HTTPS
`server{}` block (port 443, grommunio's own TLS certificate) — that's
why the shipped snippet is a bare `location /p/ { ... }` block with no
`server{}` wrapper of its own; adding one would conflict with
grommunio's. If a future grommunio release moves this include
directory, `nginx -T | grep locations.d` shows you where it's actually
being pulled in from on your host.

**Do not** publish `/api/v1` through this or any other public-facing
proxy — it is meant to stay reachable only on `127.0.0.1:18080` directly.
It is Bearer-token authenticated but still not something to expose
publicly without a specific reason. `/metrics` and the
dependency-detailed `/readyz` are not even reachable on
`18080` by default — they live on the separate admin listener
(`admin.listen`, default `127.0.0.1:18090`, no authentication at all by
design, for a local Prometheus scraper) — so there is nothing to
accidentally publish for them here either; do not add a location block
for that address regardless.

### Trusting nginx's forwarded-IP headers

Every request Attachra sees now goes through nginx over loopback, so
without further configuration Attachra's audit log and per-IP rate
limiter both see `127.0.0.1` (nginx's own peer address) as the client
for **every** download — forensics ("who downloaded this attachment?")
is blind, and the per-IP anti-enumeration budget (SR-125-7) degenerates
into one shared, global bucket for all recipients combined.

The shipped `attachra.yaml` template already sets:

```yaml
http:
  trusted_proxies:
    - "127.0.0.1/32"
    - "::1/128"
```

This tells Attachra it may trust `X-Real-IP`/`X-Forwarded-For` **only**
when the direct TCP connection came from one of these addresses — i.e.
only from nginx itself, which is co-located on this host per step 4's
snippet. A client that connects to `127.0.0.1:18080` directly (bypassing
nginx entirely) cannot spoof its IP by sending these headers itself:
Attachra ignores them unless the peer is a trusted address. If you ever
move nginx to a different host, or put another proxy/load balancer in
front of it, update `trusted_proxies` to match — and if you remove
nginx from the path entirely, remove `trusted_proxies` too so
Attachra falls back to trusting only the direct peer address.

Verify it after step 4: fetch a package page from a real remote client
and confirm the resulting audit event (`attachra audit export --type
download | tail -n 1 | jq .details.remote_ip`, or `GET /api/v1/audit`
— see step 6) shows that client's real address, not `127.0.0.1`.

## 5. Wire Attachra into the Postfix milter chain

Apply this through `postconf -e` rather than hand-editing `main.cf`:
`postconf -e` is idempotent (safe to re-run), and it's the same
mechanism grommunio-admin itself uses to manage `main.cf`, so it
disturbs the file as little as possible — no diff noise, no risk of a
stray edit elsewhere in the file.

**Step 1 — see what's really configured on this host.** Do not skip
this: grommunio's exact milter values (rspamd's address in particular)
can differ by version/install.

```sh
postconf -h smtpd_milters non_smtpd_milters
```

You should see rspamd already there on both lines, e.g.
`inet:localhost:11332`.

**Step 2 — append Attachra, keeping rspamd first.** Substitute your
host's actual current value in place of `inet:localhost:11332` below
if step 1 showed something different — the point is to *append*
`, inet:127.0.0.1:6785` to whatever is already there, not to replace
it. Attachra must run **after** rspamd (its spam/AV verdict should be
settled — and the message rejected if it's spam/malware — before
Attachra spends effort uploading attachments and rewriting the
message):

```sh
sudo postconf -e 'smtpd_milters = inet:localhost:11332, inet:127.0.0.1:6785'
sudo postconf -e 'non_smtpd_milters = inet:localhost:11332, inet:127.0.0.1:6785'
sudo systemctl reload postfix
```

> **Warning — breaks DKIM if rspamd signs outbound mail.** This order
> (rspamd, then Attachra) was live-tested against DKIM (T-3.2.4 spike): if
> rspamd's `dkim_signing` module is active on this host, every outbound
> message Attachra actually rewrites (attachment replaced with a link)
> will carry a **DKIM signature that fails verification** at the
> receiving end — rspamd signs the body *before* Attachra changes it.
> See `docs/integrations/dkim.md` for the live-verified matrix and the
> reason a straight reorder isn't enough here (rspamd does spam/AV
> scoring and DKIM signing in the same pass, so this two-milter chain
> can't get both "scan before Attachra" and "sign after Attachra" at
> once). If this host signs outbound DKIM through rspamd, either
> disable `dkim_signing` in rspamd and add a dedicated signer (e.g.
> `opendkim`) **after** Attachra in the chain, or accept that rspamd's
> AV/attachment scanning will only see Attachra's replacement text
> (reorder to `inet:127.0.0.1:6785, inet:localhost:11332` instead).
> Verify with a real DKIM/DMARC checker (see
> `docs/integrations/dkim.md`'s "Verifying the fix in practice") after
> whichever change you make — do not assume either default is correct
> for your host's signing setup.

`milter_default_action = accept` and `milter_protocol = 6` are already
set correctly on a stock grommunio host (grommunio ships them for
rspamd) — leave them as is, no `postconf -e` needed for either.
`milter_default_action=accept` matters for Attachra too: if the milter
connection to Attachra can't be established at all, Postfix delivers
the mail unmodified rather than queuing or rejecting it, matching
`attachra.yaml`'s `milter.failure_mode: open` (mail must never be lost
because Attachra is down).

**`grommunio-setup` may regenerate `main.cf` and drop this.** If you
re-run `grommunio-setup` (or an equivalent grommunio provisioning step)
later, re-check with `postconf -h smtpd_milters non_smtpd_milters` and
re-apply the two `postconf -e` commands above if Attachra has fallen
out of the chain.

A reference copy of these commands (plus the commented-out
`main.cf` lines they produce, for operators who prefer to see the
whole picture at once) lives in
`/usr/share/attachra/examples/postfix-milter.cf` — it is documentation
only, not a file meant to be copied/included anywhere.

### Rollback

To remove Attachra from the milter chain without touching rspamd,
restore the pre-Attachra value from step 1's `postconf -h` output —
substitute your actual original value if it differed from the example
below:

```sh
sudo postconf -e 'smtpd_milters = inet:localhost:11332'
sudo postconf -e 'non_smtpd_milters = inet:localhost:11332'
sudo systemctl reload postfix
```

## 6. Create your first API token (optional, for `attachractl`/automation)

Attachra's REST API (`/api/v1`, on the same loopback listener,
`127.0.0.1:18080`) is deny-by-default: nothing works without a bearer
token, and the API cannot mint its own first one. Bootstrap it with the
CLI, which writes directly to the metadata store rather than calling
the API — but do this only **after** `systemctl start attachra` (step
3), i.e. with attachra already running, not before.

That ordering matters, not just as a formality: `attachra token
create` opens `/var/lib/attachra/attachra.db` directly, creating it if
it doesn't exist yet. The service itself runs as an unprivileged,
dynamically allocated UID (`DynamicUser=yes`) that only exists while
the unit is active. If you run `sudo attachra token create ...`
*before* the service has ever started, `sudo` creates
`attachra.db`/`-wal`/`-shm` as **root**, and the service — which never
runs as root — then cannot open or write its own database. Running it
after step 3 avoids this entirely: the files already exist, owned by
the service's dynamic UID, and `sudo attachra token create` (running
as root) can still read/write them because root can access any file
regardless of ownership — root writing to an *existing*
correctly-owned file is fine; root *creating* the file is the trap.

```sh
sudo attachra --config /etc/attachra/attachra.yaml \
    token create --name "admin-cli" --role admin --actor "you@example.com"
```

The raw secret is printed to stdout **exactly once** — capture it
immediately (e.g. redirect to a root-only file):

```sh
sudo attachra --config /etc/attachra/attachra.yaml \
    token create --name "admin-cli" --role admin --actor "you@example.com" \
    > /root/attachra-admin-token.txt
sudo chmod 0600 /root/attachra-admin-token.txt
```

Then drive the running instance with `attachractl`:

```sh
attachractl --url http://127.0.0.1:18080 \
    --token-file /root/attachra-admin-token.txt \
    stats summary
```

(`--url` takes plain `http://` here since this is a loopback connection
on the same host — no TLS termination is involved before nginx, which
never sees `/api/v1` at all per step 4.) See `attachractl --help` and
`api/openapi.yaml` for the full command surface (links, policies,
stats, audit export, token management).

## 7. Verify end to end

1. Send a test email **from** an address at your configured domain
   (`user@example.com`) with a small attachment, to any recipient.
2. In the delivered message, the attachment should be gone, replaced
   by a link under `https://<your-hostname>/p/...`. Opening it should
   show the package page and let you download the original file.
3. Send another test email from a **different** domain
   (`user@other-domain.test`) with an attachment. It should arrive
   completely unmodified — `policy.yaml`'s `default: action: pass`
   applies to every sender not explicitly matched.
4. Check the audit trail for both (`audit export` filters by
   `--from`/`--to`, RFC3339 timestamps — there is no relative
   `--since`):
   ```sh
   sudo attachra --config /etc/attachra/attachra.yaml audit export \
       --from "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)"
   ```
5. Watch `journalctl -u attachra -f` while you send the test emails from
   step 1 and 3. Every message the milter adapter finishes handling —
   whether it was rewritten, passed through untouched, or blocked —
   produces one `"milter: message processed"` INFO line, for
   example:
   ```json
   {"time":"2026-07-15T09:12:03Z","level":"INFO","msg":"milter: message processed","queue_id":"4W2xY30Zbnz1r7Sd","sender_domain":"example.com","decision":"rewrite","attachments_total":1,"attachments_replaced":1,"attachments_inline_protected":0,"attachments_body_protected":0,"duration_ms":42}
   ```
   `decision` is `pass`, `rewrite`, or `block`; `sender_domain` is the
   envelope sender's domain only, never the full address (the full
   address is in the audit trail, not the log stream). Seeing this line
   at all — for either test email — confirms Attachra actually saw and
   finished processing the message, independent of whether the audit
   trail or the rewritten attachment link look right.

## Troubleshooting

**Run `attachra doctor` first.** Before working through the specific
symptoms below, run:

```sh
attachra doctor
```

(it defaults to `--config /etc/attachra/attachra.yaml`, matching this
guide's install; pass `--config` explicitly for a non-standard path, or
`--skip-external` to skip the DNS/public-URL/SPF checks e.g. from a host
without outbound internet access). It reproduces most of the checks in
this section in one pass — config/policy validity, the DynamicUser
root-owned-file trap, whether the SQLite database opens, whether the
milter/HTTP listeners are actually up, whether the public download URL
and SPF records look right, and whether postfix is wired to the milter
— with a PASS/WARN/FAIL/SKIP table and a remediation hint next to every
non-PASS row. `--json` gives the same data as a JSON array, and the
process exit code is `1` if any check FAILs, `0` otherwise, so it is
also safe to script (e.g. attach its output when filing a bug on the
public repo). It never modifies your installation: every check is
read-only or, at most, writes and immediately removes a small probe
file to confirm a directory is writable.

- **I sent a message and `journalctl -u attachra` shows nothing.**
  Every message the milter adapter finishes handling —
  pass, rewrite, or block alike — logs one `"milter: message
  processed"` INFO line (see step 5 of "Verify end to end" above for an
  example). If you see genuinely nothing at INFO level for a message
  you know Postfix delivered:
  - Check `log.level` in `attachra.yaml` isn't set above `info` (e.g.
    `warn`/`error`), which would suppress this line along with all
    other INFO output.
  - Confirm the milter is actually in the chain at all — see the next
    bullet below (a message Attachra never received obviously can't be
    logged).
  - If you're running an older build (pre-0.1.1 line), this line doesn't
    exist yet; upgrade the package. Before that fix, the happy path was
    silent by design and the audit trail (`attachra audit export`) was
    the only record of a processed message — that's still true and
    still the authoritative source, but it required knowing to go
    looking rather than being visible from a plain `journalctl -f`.
- **Nothing is being rewritten, mail flows normally.** This is the
  fail-open default working as intended if Attachra itself is down or
  unreachable (`milter_default_action = accept` +
  `milter.failure_mode: open`) — check `systemctl status attachra` and
  `journalctl -u attachra -e` first. Also confirm `postconf -n
  smtpd_milters` actually includes `inet:127.0.0.1:6785` — a typo or a
  config that grommunio-admin reverted is the next most common cause.
- **`journalctl -u attachra` shows a config error and the service
  won't start.** `attachra.yaml` failed `config.Validate()` — the error
  names the specific offending field
  (`internal/config/config.go`). Common ones: an empty
  `public_base_url`, an unrecognized `storage.driver` value, or a
  `policy.path` pointing at a file that doesn't parse
  (`attachra policy validate` catches the latter ahead of time).
- **`systemctl start attachra` fails immediately with a permissions
  error.** Check `journalctl -u attachra -e` for
  `ProtectSystem=strict`/`DynamicUser` related denials — Attachra only
  needs to write under `/var/lib/attachra` (its `StateDirectory`); if
  you changed `storage.fs.base_dir` or `database.path` to point
  somewhere else, the sandboxed unit won't be able to write there. Keep
  both under `/var/lib/attachra/...` unless you also add a matching
  `ReadWritePaths=` to `deploy/deb/systemd/attachra.service` (and
  reinstall/re-apply it — it's not a conffile).
- **`journalctl -u attachra` repeatedly shows `fs: base_dir
  "/var/lib/attachra/files": stat: no such file or directory` and the
  service crash-loops.** `StateDirectory=attachra` only creates the
  top-level `/var/lib/attachra`, not the `files/` subdirectory
  `storage.fs.base_dir` points at underneath it; the `fs` storage
  driver now creates that subdirectory itself on start. If
  you still hit this, you're on an Attachra build older than that fix —
  upgrade the package, or work around it in place (matching
  `StateDirectory=attachra`'s own ownership, mode 0700):
  ```sh
  mkdir -p /var/lib/attachra/files
  chown "$(stat -c '%u:%g' /var/lib/attachra)" /var/lib/attachra/files
  chmod 0700 /var/lib/attachra/files
  systemctl restart attachra
  ```
- **`journalctl -u attachra` repeatedly shows `SQLITE_CANTOPEN` and the
  service crash-loops on a nested `database.path` (e.g.
  `/var/lib/attachra/db/attachra.db`).** Same class of gap as the
  `fs: base_dir` case above: `StateDirectory=attachra` only creates
  `/var/lib/attachra` itself, not a subdirectory `database.path` points
  at underneath it. The sqlite store now creates that directory itself
  on start. If you still hit this, you're on an Attachra build older
  than that fix — upgrade the package, or work around it in place
  (matching `StateDirectory=attachra`'s own ownership, mode 0700):
  ```sh
  mkdir -p "$(dirname /var/lib/attachra/db/attachra.db)"
  chown "$(stat -c '%u:%g' /var/lib/attachra)" "$(dirname /var/lib/attachra/db/attachra.db)"
  chmod 0700 "$(dirname /var/lib/attachra/db/attachra.db)"
  systemctl restart attachra
  ```
- **`GET /readyz` returns non-200.** It aggregates a database check
  and (if configured) a storage and policy check; the response body
  names which one failed. Query it on the admin listener
  (`127.0.0.1:18090` by default, not `18080` — see step 3).
- **Download link 404s.** Confirm the nginx include actually loaded
  (`nginx -T | grep -A3 'location /p/'`) and that `public_base_url` in
  `attachra.yaml` matches the hostname nginx is actually serving on.
- **`attachractl` connection refused.** It talks to
  `127.0.0.1:18080` directly (not through nginx, which never proxies
  `/api/v1` — see step 4) — run it on the grommunio host itself, or
  over an SSH tunnel if you need remote access; do not expose
  `/api/v1` publicly to avoid tunneling.
- **`journalctl -u attachra` shows `SQLITE_CANTOPEN` or "database is
  locked" right after install, and it was working before.** You (or a
  script) most likely ran `attachra token create` — or anything else
  that opens `attachra.db` — as root *before* `attachra.service` had
  ever started (see step 6): root created `/var/lib/attachra/
  attachra.db`/`-wal`/`-shm` owned by root, and the service's
  `DynamicUser` cannot write to root-owned files. Fix by handing
  ownership back to the dynamic UID/GID systemd already assigned to
  `/var/lib/attachra` itself (`StateDirectory=` makes that allocation
  persistent across restarts, so this stays correct on every future
  start too):
  ```sh
  chown "$(stat -c '%u:%g' /var/lib/attachra)" /var/lib/attachra/attachra.db*
  ```
  or, if there's no data in it worth keeping yet, simply delete the
  files and let the service recreate them correctly on next start:
  ```sh
  systemctl stop attachra
  rm -f /var/lib/attachra/attachra.db /var/lib/attachra/attachra.db-wal /var/lib/attachra/attachra.db-shm
  systemctl start attachra
  ```
  (the latter loses any links/audit history recorded so far — fine for
  a fresh install, not for a system that's already been processing
  real mail).

## Upgrading

```sh
sudo apt install ./attachra_<new-version>_amd64.deb
```

`attachra.yaml` and `policy.yaml` are dpkg conffiles: your edits are
preserved. If a new release ships a materially different template,
dpkg prompts you (or leaves a `*.dpkg-dist` file next to yours,
depending on how you've configured dpkg conffile handling) rather than
overwriting your configuration silently.

The package's postinst tells first install and upgrade apart (dpkg
passes it the previous version): on an upgrade it runs `systemctl
try-restart attachra` — restarting the new binary automatically **only
if attachra was already running**, and leaving it alone if you had
deliberately stopped it. No further action needed for the common case;
verify with `systemctl status attachra` afterwards. (A first install
never auto-starts — see step 1/postinst's own banner — so this
restart-on-upgrade behavior only ever applies from the second install
onward.)

## Rollback

```sh
sudo apt install ./attachra_<previous-version>_amd64.deb
```

or, to remove Attachra entirely while keeping its data
(`/var/lib/attachra`) for later:

```sh
sudo apt remove attachra
```

`apt purge attachra` additionally disables the service, but
deliberately still does **not** delete `/var/lib/attachra` (the
metadata database and any locally stored attachment payloads) or
`/etc/attachra/attachra.env` (if you created one) — those can be
audit-relevant or under legal hold, so removing them is left to an
explicit, separate `rm -rf /var/lib/attachra` if that's really what you
want.
