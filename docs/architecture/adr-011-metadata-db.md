# ADR-011 — Metadata Database

Status: Accepted (founder ack 2026-07-09)
Date: 2026-07-04 (proposed), 2026-07-09 (accepted)
Deciders: atr-architect (owner), atr-product-lead, atr-security, atr-devops
Tracking: internal issue tracker (blocks the link-schema and audit-schema follow-up work)
Related: ADR-001 (single static binary), ADR-004 (Community production-ready), ADR-007 (S3 storage)

---

## Decision (short form for the architecture decision registry)

Attachra uses **SQLite (pure-Go `modernc.org/sqlite`, WAL mode) as the default embedded
metadata store**, and supports **PostgreSQL as an opt-in production/HA backend**.

- One binary, zero external dependencies out of the box — `docker compose up` just works
  (ADR-001, ADR-004).
- The data-access layer is written against a **single SQL dialect discipline** from day one,
  so the Postgres driver is an added backend, not a rewrite.
- Postgres is the recommended backend for multi-node / HA deployments; **SQLite is
  single-node only** and this limitation is documented explicitly.

MVP ships SQLite only. Postgres backend lands in v0.2. The MVP code is written so that
adding Postgres does not touch domain logic — see «What we lock into MVP code».

---

## Context

Attachra needs a relational metadata store, separate from S3 object storage (ADR-007),
for the following data (per the link-schema and audit-schema work, epics E7 / E8):

- **links / messages / attachments / recipients** — the core graph: one message →
  N attachments → M recipients → per-(attachment,recipient) link with token hash,
  TTL, max-downloads (T-6.1.3).
- **audit events** — append-only journal: mail processed, policy decision, download,
  revoke (E7, US-7.1). Append-heavy, read for export/UI.
- **API tokens** — hashed admin/viewer tokens (E8, T-8.1.7).
- **download counters** — per-link counter with a **max-downloads limit that must be
  enforced under concurrency** (T-6.2.3): two simultaneous downloads of the same link
  must not both slip past `downloads < max`.

Two hard constraints shape the decision:

1. **ADR-001 — single static binary, cross-compiled linux/amd64 + linux/arm64.**
   Anything requiring CGO or a C toolchain per target arch is a direct threat to this
   invariant.
2. **ADR-004 — Community edition is production-ready.** The default path cannot be a
   degraded «toy» store that pushes serious users to a paid tier. Whatever we default to
   must survive a real small/medium installation.

Target audience & scale (installation = one mail domain / one org):

| Tier | Mailboxes | Order-of-magnitude write load |
|---|---|---|
| Small self-hosted | 50–200 | ~10²–10³ processed mails/day → a handful of writes/sec peak |
| Medium | 200–1000 | ~10³–10⁴ mails/day → tens of writes/sec peak |
| Large | 1000–5000 | ~10⁴–10⁵ mails/day → low-hundreds writes/sec peak, bursty |

Reality check on the numbers: even the large tier is **hundreds of writes/sec at burst**,
not thousands sustained. Each processed mail produces a bounded fan-out (1 message row,
a few attachment rows, links = attachments × recipients, a few audit rows). Reads (API/UI,
download-endpoint lookups) dominate volume but are simple indexed point queries. This is
squarely inside what a single embedded SQLite writer handles — the write path is the
constraint to reason about, not read throughput.

---

## Load profile analysis

**1. Write on every mail (links + audit).**
Synchronous with the milter path but *off the latency-critical hot path*: the milter must
return the rewritten body quickly; metadata persistence should be committed before we hand
back the link (the recipient must be able to download), but a message's worth of rows is a
single small transaction. Batched per-message insert (one tx: message + attachments +
recipients + links + audit) keeps write amplification low. At hundreds of mails/sec worst
case, a single SQLite WAL writer sustains this comfortably (WAL commit is one fsync per tx;
group-committable).

**2. Atomic download counter increment (concurrency-critical).**
The one genuinely contended operation. Correct enforcement is:

```sql
UPDATE links
   SET downloads = downloads + 1
 WHERE id = ? AND (max_downloads = 0 OR downloads < max_downloads);
-- rows-affected == 1 → grant; == 0 → limit reached / expired
```

The decision to serve the file is driven by **rows-affected of a single atomic UPDATE**,
never by read-then-write in application code. This is correct on both backends:
- **SQLite**: writes are globally serialized (single writer); the UPDATE is atomic by
  construction. No lost update possible.
- **Postgres**: the row-level write lock on the `WHERE`-matched row serializes concurrent
  increments; the guarded UPDATE is atomic.

Same SQL, correct on both. (We must *not* implement the limit as `SELECT count; if ok UPDATE`
— that races on both backends.)

**3. Reads for API/UI.**
List/search messages, links, audit with pagination; download-endpoint token lookup
(hot, must be a single indexed `WHERE token_hash = ?`). Read-heavy but trivial per-query.
SQLite readers do not block the writer in WAL mode; Postgres readers are MVCC-isolated.

**4. Retention cleanup.**
Background sweep deleting expired files' metadata (T-5.3.2) and optionally trimming old
audit. Bulk `DELETE ... WHERE expires_at < now()` in chunked transactions to avoid holding
the SQLite write lock too long. Low frequency, off-peak.

---

## Operational profile of the audience

- **Self-hosted admin — the primary persona (ADR-010).** Wants «`docker compose up` and it
  works». Every extra stateful service (a Postgres container, its volume, backups, version
  upgrades) is friction and a support-ticket source. **This is the strongest argument for an
  embedded default.** SQLite = the database is a file next to the binary; backup = copy the
  file; no connection string, no auth, no separate process.

- **Mailcow / iRedMail installations.** These stacks *already* ship MySQL/MariaDB or
  Postgres. An admin already running Postgres may prefer to point Attachra at it (one less
  moving part conceptually, unified backups). This is a real argument for *supporting*
  Postgres — but note their default is often **MySQL/MariaDB**, not Postgres. We deliberately
  scope external-DB support to **Postgres only** (see Trade-offs); we do not chase MySQL.

- **Enterprise.** Wants HA: no single point of failure, managed/replicated DB (RDS, Patroni,
  Cloud SQL), horizontal scaling of the stateless download/API tier behind a load balancer.
  SQLite cannot serve a multi-node deployment (see «HA & multi-node»). Enterprise ⇒ Postgres.

Mapping persona → backend:

| Persona | Backend | Why |
|---|---|---|
| Small/medium self-hosted | SQLite (default) | Zero-ops, single binary |
| Admin with existing Postgres | Postgres (opt-in) | Reuse infra, unified backups |
| Enterprise / HA / multi-node | Postgres (required) | Replication, LB'd stateless tier |

---

## SQLite specifics in Go (decisive for ADR-001)

**CGO vs pure-Go.** Two mature options:

- `mattn/go-sqlite3` — CGO binding to the C library. Fast, battle-tested, but **requires
  CGO** → a C cross-toolchain for every target arch, breaks `CGO_ENABLED=0` static builds,
  complicates the linux/amd64 + linux/arm64 matrix, and produces a dynamically-linked-to-libc
  binary unless statically linked with extra care.
- **`modernc.org/sqlite`** — a **pure-Go** transpilation of SQLite. `CGO_ENABLED=0`,
  trivially cross-compiles, single static binary. This is the ADR-001-aligned choice.

**Decision: `modernc.org/sqlite`.** The single-static-binary + clean cross-compile invariant
(ADR-001, technical invariant #2) outweighs the raw-throughput edge of the CGO driver. At our
write volumes we are nowhere near the point where the modernc performance delta matters.
The `mattn` driver's CGO requirement is, per the architect invariants, effectively a blocker
for the default path.

Trade-off to accept: `modernc.org/sqlite` is somewhat slower than the C library and has a
smaller (though solid) production track record. Acceptable at our scale; revisit only if a
benchmark shows a real bottleneck.

**Required SQLite configuration (enforced at open time):**

- `PRAGMA journal_mode=WAL` — readers don't block the writer; far better concurrency than
  the default rollback journal.
- `PRAGMA busy_timeout=5000` (or higher) — so a transient «database is locked» from the
  single-writer contends via wait-and-retry instead of an immediate error.
- `PRAGMA foreign_keys=ON` — enforce the message→attachment→link graph integrity.
- `PRAGMA synchronous=NORMAL` — safe with WAL, one fsync per checkpoint region; good
  durability/throughput balance. (`FULL` if an admin wants maximal durability.)
- **Single writer connection, pooled readers.** With `database/sql`, cap the write path.
  Practically: set `SetMaxOpenConns(1)` on the SQLite pool *or* route all writes through a
  serialized writer, and keep a separate read pool. This avoids self-inflicted
  `SQLITE_BUSY` from concurrent writers inside our own process.

**Behaviour under concurrent downloads.** SQLite serializes writes globally. Concurrent
download-counter UPDATEs on the *same* link are serialized (correct, no lost update);
concurrent UPDATEs on *different* links still serialize at the write-lock but each tx is
sub-millisecond, so throughput is fine at our scale. WAL + `busy_timeout` absorbs the
contention. The guarded-UPDATE pattern above is the correctness guarantee; single-writer
serialization is the mechanism.

---

## The «both backends» option

Supporting two backends has a real cost; the question is whether the abstraction is cheap
enough to be worth it *and* whether we have a committed second implementation (per architect
principle: don't abstract without a second implementation on the roadmap — here we do:
enterprise HA is a roadmap requirement, so the abstraction is justified).

**Cost of two dialects:**
- Two SQL dialects to keep in sync (autoincrement vs `BIGSERIAL`/identity, `?` vs `$n`
  placeholders, upsert syntax, `RETURNING`, timestamp types, `INTEGER` affinity vs strict
  typed columns).
- Two migration sets or one dialect-parameterized set.
- Doubled integration-test matrix (must run the suite against both).
- Discipline to never use a backend-specific feature in the hot path.

**Access-layer choice** (evaluated, not ORM-religion):

- **Raw `database/sql`** — full control, no magic, but hand-written scanning is tedious and
  error-prone across two dialects.
- **`sqlc`** — generates type-safe Go from SQL. Excellent, but it generates *per-dialect*
  code and the two dialects diverge enough that you effectively maintain two `.sql` query
  sets. Good, but front-loads the dual-dialect cost.
- **An ORM (GORM/ent)** — abstracts the dialect but hides the exact SQL of the
  concurrency-critical counter UPDATE, which is precisely the query we must control. Rejected
  for the hot path.

**Decision on the layer:** `database/sql` + an explicit thin **repository interface**
(`MetadataStore`) with two implementations, plus a migration tool that supports both dialects
(**`golang-migrate`**, per-dialect migration directories `migrations/sqlite/` and
`migrations/postgres/`). Keep queries hand-written and reviewed; the concurrency-critical
UPDATEs are identical portable SQL. Reconsider adding `sqlc` for the *read* queries later —
it does not need to be an MVP decision.

**Default backend: SQLite.** Postgres is selected by config (a DSN / driver switch).

---

## HA, scaling, and future multi-node (honest analysis)

This is where SQLite's limit is real and must not be sugar-coated.

- **Single-node, single-writer.** SQLite lives in a file on one host's local disk. It has no
  network protocol — you cannot point a second Attachra process on another host at the same
  database. WAL requires shared-memory (`-shm`) coordination between processes on the *same*
  machine; it does **not** work over NFS/network filesystems reliably.

- **The download endpoint is the horizontal-scaling pressure point.** T-6.2.1 streams files;
  it's otherwise **stateless** and the obvious candidate to run as N replicas behind a load
  balancer. But each download does a **write** (counter increment + download audit event).
  With SQLite, all N replicas would need to write to one file — impossible across hosts.
  **SQLite structurally blocks the multi-node download tier.** This is the single most
  important trade-off in this ADR.

- **Postgres removes the block cleanly.** A shared Postgres lets any number of stateless
  Attachra replicas increment counters and append audit against one authoritative store;
  the guarded UPDATE stays correct under cross-node concurrency (row lock). HA = replicated
  managed Postgres. The milter path (E2) is also stateless and scales the same way.

- **Consequence for roadmap.** Multi-node Attachra is a post-MVP / enterprise concern (not in
  the M0–M3 MVP scope), but it *is* on the trajectory (ADR-005 marketplace, enterprise HA).
  Because we know a networked backend is required later, abstracting the store now is a
  *justified* abstraction, not speculative gold-plating. We pay a small, bounded cost in MVP
  (the interface) to avoid a core rewrite later.

We explicitly do **not** pursue SQLite-replication hacks (LiteFS, rqlite, Litestream-for-HA)
for multi-node write. Litestream is fine as an *optional single-node backup/DR* convenience,
but the HA answer is Postgres. Keeping that boundary sharp avoids a confusing middle tier.

---

## Options considered

**Option A — Postgres only (mandatory external DB).**
+ One dialect, HA-ready from day one, no SQLite quirks.
− Kills «`docker compose up` and it works» — every install needs a Postgres service, volume,
  backup story. Violates the spirit of the zero-friction self-hosted persona (ADR-010) and
  raises the floor for the Community edition. **Rejected as default.**

**Option B — SQLite only (embedded, no external DB ever).**
+ Ultimate simplicity, perfect for the primary persona, single binary.
− Structurally blocks multi-node / HA (download tier cannot scale horizontally). Leaves
  enterprise with no answer and would force a painful retrofit later. **Rejected as sole
  option** — but adopted as the **default**.

**Option C — Both, via an abstraction layer; SQLite default, Postgres opt-in. (CHOSEN)**
+ Best of both: zero-ops default *and* a clean HA path; the abstraction is justified by a
  real roadmap requirement.
− Dual-dialect maintenance + doubled test matrix. Mitigated by: portable SQL discipline,
  a thin repository interface, `golang-migrate` per-dialect migrations, and CI running the
  suite against both backends.

---

## Recommendation & sequencing

**Recommendation: Option C. SQLite (`modernc.org/sqlite`, WAL) as the default embedded store;
PostgreSQL as an opt-in backend selected by config. SQLite ships in MVP; Postgres backend
ships in v0.2. Design the MVP data layer so adding Postgres never touches domain logic.**

Sequencing:

- **MVP (M1–M3):** SQLite only, in production-ready configuration (WAL, busy_timeout, FK on,
  single-writer). All of the link-schema and audit-schema work (E7 / E8) lands on it. This
  unblocks T-6.1.3 and E7 immediately — the whole point of this decision.
- **v0.2:** Add the Postgres implementation of `MetadataStore`, Postgres migration set, and
  a config switch (`database.driver: sqlite | postgres`, `database.dsn: ...`). Document
  Postgres as the recommended backend for HA/multi-node. Provide a one-shot
  **SQLite→Postgres migration command** (`attachractl db migrate --to postgres`) for admins
  who outgrow the embedded store.
- **Later / enterprise:** stateless download + API + milter tiers behind a LB against shared
  Postgres = horizontal scale and HA.

---

## What we lock into MVP code (so v0.2 is additive, not a rewrite)

Even though MVP ships SQLite only, the MVP code must already:

1. **Define a `MetadataStore` interface in `internal/core`** (repository pattern) covering all
   metadata operations — messages, attachments, recipients, links, audit, api-tokens,
   counters. Core depends on the interface, never on `*sql.DB` or any driver (aligns with
   ADR-002 core/adapter discipline). The SQLite implementation lives under
   `internal/core/store/sqlite/` (or `internal/adapters/store/`), selected by config.

2. **Write portable, dialect-neutral SQL** — no SQLite-only features on the write path.
   Enforce the download-limit as the single guarded atomic UPDATE (rows-affected semantics),
   never read-then-write. This query is byte-for-byte portable to Postgres.

3. **Use `golang-migrate` with a versioned migration set from commit #1**, structured so a
   `migrations/postgres/` sibling can be added without reworking the runner. Schema uses
   portable types (integer PKs, `TEXT`/`VARCHAR`, explicit UTC timestamps stored as
   integer-epoch or ISO-8601 text to avoid SQLite/Postgres datetime divergence).

4. **Route all writes through a single serialized writer path** for SQLite
   (`SetMaxOpenConns(1)` on the write pool or an explicit writer goroutine), separate read
   pool — so the concurrency model is explicit and the same repository code behaves correctly
   when swapped to a Postgres pool (where the pool can be wide).

5. **Never leak the token itself into the DB** — store only the hash (technical invariant #5,
   T-8.1.7). Applies identically to both backends.

If these five are respected, adding Postgres in v0.2 is: one new `MetadataStore` impl, one
migration directory, one config branch, and CI wiring — with **zero changes to domain logic**.

---

## Consequences

Positive:
- Community edition is genuinely zero-ops and production-ready (ADR-004) with a single binary
  (ADR-001).
- Clean, honest HA story for enterprise via Postgres, without a core rewrite.
- Concurrency-critical download counter is provably correct on both backends via the guarded
  UPDATE pattern.

Negative / costs to own:
- Dual-dialect maintenance and a doubled integration-test matrix from v0.2 onward.
- `modernc.org/sqlite` carries a modest performance and maturity discount vs the CGO driver
  (accepted; revisit only on evidence).
- We must hold the discipline of portable SQL and «no ORM on the hot path».

Follow-ups / new tickets:
- The link-schema and audit-schema work proceeds on SQLite now, using the portable
  types above.
- New task: define `MetadataStore` interface + SQLite impl + `golang-migrate` wiring (MVP).
- New task (v0.2): Postgres backend + config switch + `db migrate --to postgres` command +
  CI-against-both.
- Optional (single-node DR): document Litestream-based SQLite backup as a convenience — not
  an HA mechanism.
