# Download-domain reputation (T-6.2.x)

Attachra's replacement block (`docs/product/replacement-block.md`)
links to a download page on the domain configured as `public_base_url`
(e.g. `https://dl.example.com` — see `internal/config/config.go`). That
domain is brand new the day you stand it up, and most corporate web
filters (Cisco Talos, Palo Alto Networks, Fortinet FortiGuard,
BrightCloud/Webroot, Netcraft) treat unrecognized domains as
suspicious by default — "uncategorized"/"newly seen domain" is itself
a block or warn condition in a lot of default web-filter policies,
independent of anything Attachra does correctly. This guide is the
third layer of the Recipient Trust Kit — the other two are the
[in-message replacement block text](../product/replacement-block.md)
and the recipient-facing `/about` landing page on the download domain
(available from v0.3, referenced below).

None of this is Attachra-specific hardening; it's the same reputation
groundwork any organization would do before sending mail with links
from a new domain. It matters more here than for a typical marketing
domain because every recipient of every policed outbound message sees
this domain, often without having chosen to receive mail from it.

## 1. Register the domain before production traffic

Reputation systems weight domain age and traffic history. Register
(or repurpose) the download domain and put a minimal, working page
behind it — TLS included — **before** the first production message
links to it, ideally weeks in advance rather than the same day. A
domain that has existed and served a stable, legitimate page for a
while starts from a materially better position with every filter in
this document than one that appears for the first time in an inbound
link.

Practical implication for the rollout sequence: do steps 2–3 below
*before* running `attachra setup` against production traffic, not
after. `attachra setup` defaults to dry-run mode specifically so this
kind of pre-production groundwork has time to happen (see the
Quickstart in `README.md`).

## 2. Publish `security.txt`

[RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) defines a
machine-readable way for security researchers (and, incidentally, some
reputation crawlers) to find a contact for a domain. Serve it at
`https://<download-domain>/.well-known/security.txt`:

```
Contact: mailto:security@example.com
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: en
Canonical: https://dl.example.com/.well-known/security.txt
```

- `Contact` should be a monitored address at the operating
  organization — not Attachra's own `security@attachra.org` (that's
  for vulnerabilities in the Attachra software itself, see
  `SECURITY.md` in this repository; a recipient investigating a
  suspicious-looking download link needs to reach *your* organization,
  not the vendor).
- `Expires` is required by the RFC; set it and update it — an expired
  `security.txt` is itself a minor trust signal against you, and some
  automated scanners flag it.
- Reverse-proxy this alongside the `/p/` download path (see step 4);
  it costs one more `location` block, not a second cert or listener.

## 3. Submit the domain for categorization proactively

Don't wait for a filter to see traffic and auto-categorize the domain
— that process is slow and the default category while "unrated" is
often a block or a warning interstitial. Submit for review directly,
requesting a category like "Business/Economy", "Computers & Internet",
or "File Storage/Sharing" (whichever taxonomy the vendor uses) rather
than leaving it to land in a generic bucket:

| Vendor | Submission | Notes |
|---|---|---|
| Cisco Talos Intelligence | [talosintelligence.com/reputation_center](https://talosintelligence.com/reputation_center) → "Submit a URL for review" | Also shows current reputation/category for the domain, useful to re-check after submitting. |
| Palo Alto Networks | [urlfiltering.paloaltonetworks.com](https://urlfiltering.paloaltonetworks.com) | "Request a category change"; used by PAN-OS URL Filtering / Advanced URL Filtering. |
| Fortinet FortiGuard | [fortiguard.com/webfilter](https://www.fortiguard.com/webfilter) | Category lookup + "Suggest a Rating" form. |
| BrightCloud (Webroot) | [brightcloud.com/tools/url-ip-lookup.php](https://www.brightcloud.com/tools/url-ip-lookup.php) | Also feeds several other vendors' filters (BrightCloud is licensed by multiple UTM products). |
| Netcraft | [report.netcraft.com](https://report.netcraft.com/) | Primarily phishing/threat reporting, but relevant if the domain is ever misclassified as such — worth knowing the dispute path before you need it. |

Submissions typically take a few days to a few weeks to process and
are not guaranteed to land in the exact category requested. Re-submit
if a category still looks wrong after a reasonable wait, and keep an
eye on it — a domain can be miscategorized later even after a good
initial submission (e.g. following a compromise on an unrelated
service sharing the same IP/registrar reputation).

## 4. Valid TLS

The download domain must present a valid, non-self-signed certificate.
Beyond the obvious (recipients get a scary browser warning on a link
from an email, which reads exactly like a phishing tell), an invalid
or self-signed cert is itself a negative signal to several of the
reputation systems above.

- Any ACME-issued certificate (e.g. Let's Encrypt, via `certbot` or
  your reverse proxy's built-in ACME client) is sufficient — there is
  no requirement for EV/OV certificates here.
- Terminate TLS in front of Attachra's `http.listen` (default
  `127.0.0.1:8080`, configurable — see `internal/config/config.go`)
  with a reverse proxy that exposes **only** the
  `/p/` path (and now `/.well-known/security.txt`) externally — never
  `/api/v1` or `/metrics`. See the nginx example in
  [`docs/deploy/grommunio-debian.md`](../deploy/grommunio-debian.md)
  for a working reference config.
- Set `public_base_url` in `attachra.yaml` to the `https://` form of
  this domain. Attachra's config validation accepts `http://` too
  (`internal/config/config.go`, `validatePublicBaseURL`) since that's
  useful for local/dev setups without a cert (see Quickstart Option B),
  but a production deployment should always use `https://` so every
  generated link matches the certificate's name.

## 5. Align the domain with the sending brand

A download link on a domain that looks unrelated to the sending
organization is itself suspicious, independent of reputation score —
this is the same instinct that makes `paypal-secure-login.net` read as
a phishing domain regardless of its actual reputation data. Prefer:

- A subdomain of the sending organization's own domain (e.g.
  `files.example.com` or `dl.example.com` for mail sent `@example.com`)
  over an unrelated domain.
- Consistent branding on the `/about` landing page on the download
  domain (available from v0.3) so a recipient who does click through
  sees the same organization identity as the `From` address, not a
  generic or unbranded page.
- Consistent WHOIS/registration details with the rest of the
  organization's domain portfolio where your registrar allows it —
  some reputation heuristics weight registrant consistency across an
  organization's domains.

## Summary checklist

- [ ] Domain registered and serving a stable page well before
      production mail links to it.
- [ ] `security.txt` published at `/.well-known/security.txt` with a
      monitored contact and a maintained `Expires` date.
- [ ] Submitted to Talos, Palo Alto Networks, FortiGuard, and
      BrightCloud for categorization; re-checked after a few weeks.
- [ ] Valid (non-self-signed) TLS certificate on the exact domain set
      in `public_base_url`.
- [ ] Domain name/branding aligned with the sending organization, not
      generic or unrelated to it.

## Related

- [`docs/product/replacement-block.md`](../product/replacement-block.md)
  — the in-message text this domain's reputation backs up.
- [`docs/integrations/postfix.md`](postfix.md) and
  [`docs/integrations/dkim.md`](dkim.md) — milter ordering, which
  affects how the rest of the message (not this domain) is perceived
  by receiving mail servers.
- `README.md` Quickstart, step 5 ("Publish the download page") —
  points here as a recommended step before taking a deployment into
  production.
