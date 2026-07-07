---
name: operating-a-server
description: Use when administering a running quicSQL server — the /_admin control plane (create/detach/list databases, stats, sessions, kill, vault maintenance including the recipient-mode key lifecycle members/rewrap/rekey and encrypted snapshots), managing enrolled principals and minting single-use enrollment codes, online backup / in-place restore, WAL checkpoint, scraping /_metrics, configuring rate/concurrency limits and timeouts, and the slow-query log.
---

# Operating a quicSQL server

Runtime administration happens over HTTP, gated by admin identity. The control plane and its endpoints are opt-in.

## Enable the control plane

```yaml
control_plane:
  enabled: true
  admins: [tourist]        # server-admins: may administer ANY database
```

A **server-admin** (named in `control_plane.admins`) can run every op against any database. A principal holding an `admin`-level **grant** on one database may administer *that database only* (e.g. vault maintenance). Enabling the control plane requires at least one admin — it never opens wide.

## /_admin (admin-only)

Reached over any authenticated transport, as an admin principal:

- **Databases** — create a database at runtime, detach one, list them (filtered to what the caller may administer). A created database is persisted in the meta store and survives restart.
- **Introspection** — per-database stats, live sessions, and kill a session.
- **Vault maintenance** — offline **compact** (rewrite densely); online **compact_online** / **trim** / **compact_logical** (return freed blocks / the trailing run / rewrite to the logical footprint on the live handle); **reclaimable** (read-only probe of what compact_logical would free); **snapshot** (decrypted logical image to a data_dir path) / **snapshot_encrypted** (a re-sealed **encrypted** vault copy — no plaintext on disk; raw-key vaults only, reserves the db). For a **recipient-mode** vault: **members** (enumerate the keyslot), **rewrap** (re-wrap the data key to the configured `create:` membership — O(1), access-list only), **rekey** (fresh key, rewrites data — true revocation). All three reserve the db; the target membership is the vault's config.
- **WAL checkpoint** — `op: checkpoint`, `mode: passive|full|restart|truncate` on any WAL-mode database; bounds WAL growth without a restart and reports the frame counts.
- **Backup / restore** — `GET /<db>/backup` streams a standalone SQLite file with no size ceiling (online backup; read access). `POST /_admin/restore?database=<db>` with an image body swaps it into a **file** database in place (validate → reserve → atomic rename; server-admin only; back up first). Vaults restore out-of-band (see the administration guide).
- **Enrolled principals** (when `auth.enroll` is on) — `GET /principals` lists the runtime-enrolled identities (`u_…`), `POST /principals/delete {"name":"u_…"}` revokes one (key + grants together, and its provisioned db per `provision.on_revoke`); `POST /enroll/codes` mints a single-use enrollment code (when `auth.enroll.codes.enabled`). Server-admin only.

From the Go client, admin calls go through the same authenticated client (`client.Export`, `client.ApplyChangeset`, `BlobProvision`, and the control-plane helpers); over the wire they are ordinary authenticated requests to `/_admin/…`.

## Metrics and the slow log

```yaml
logging:
  slow_threshold: 200ms   # >0 enables the slow log at this duration
  expand_params: false    # redact bound params by default
  format: text            # json | text (default text) — log output format (json for a log pipeline)
```

- `GET /_metrics` — Prometheus text exposition (format 0.0.4); scrape it. Gauges include `active_sessions` (if it climbs and never falls, something opens Hrana streams without closing them — see the `transactions-and-hrana` skill).
- `GET /_health` — liveness, no auth.
- The slow-query log fires above `slow_threshold`; bound parameters are redacted unless `expand_params: true`.
- `logging.format: json` emits structured JSON logs (one object per line) to stderr; `text` (default) is human-readable.

Scrape it from Prometheus (a loopback listener with `auth: [none]` is the intended target — `/_metrics` has no capability check beyond the listener's auth):

```yaml
scrape_configs:
  - job_name: quicsql
    static_configs:
      - targets: ['127.0.0.1:7775']
    metrics_path: /_metrics
```

One alert worth having — a Hrana session leak shows up as `active_sessions` climbing and never falling (streams opened without `Close`):

```yaml
groups:
  - name: quicsql
    rules:
      - alert: QuicsqlSessionLeak
        expr: active_sessions > 100 and deriv(active_sessions[15m]) > 0
        for: 15m
        annotations:
          summary: "active Hrana sessions climbing without release (client not closing streams)"
```

## Limits (protect the server)

```yaml
limits:
  rate: { per_principal_rps: 100 }    # token bucket, per authenticated identity
  max_concurrent_per_db: 512          # admission cap per database
  statement_timeout: 30s              # interrupt a single runaway statement
  tx_idle_timeout: 30s                # reap an idle Hrana session (frees its pinned conn)
  max_tx_lifetime: 5m                 # hard cap on a session's age
  max_sessions_per_db: 64             # cap concurrent pinned sessions per db (reads + writes)
  idle_handle_timeout: 10m            # close a database handle idle this long (0 = keep open forever)
```

The session-related limits are the ones that protect against a client that opens a transaction and stalls — keep `tx_idle_timeout` short. Tuning rationale: the [Hrana guide](../../docs/hrana.md).

**`idle_handle_timeout` bounds the open working set.** Boot warms only the config-declared `databases:` seeds; every runtime-created database — the whole `auth.enroll`/`accounts` per-user fleet — opens **lazily on first request**, not at startup. With `idle_handle_timeout` set, a handle unused for that long closes, so the open set tracks *active* users rather than the total. Leave it unset with provisioning on and every per-user db stays open once touched (the server warns at startup).

## Meta store

The server's runtime registry + audit + idempotency state is a vault by default; set `server.meta_store.key` (a secret ref from a non-meta source) to encrypt it at rest. An unkeyed vault meta store is plain and warned at startup.
