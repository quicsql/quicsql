---
name: operating-a-server
description: Use when administering a running quicSQL server — the /_admin control plane (create/detach/list databases, stats, sessions, kill, vault maintenance), scraping /_metrics, configuring rate/concurrency limits and timeouts, and the slow-query log.
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
- **Vault maintenance** — offline **compact** (rewrite densely), online **reclaim** and **trim** (return freed blocks to the OS on the live handle), **snapshot**.

From the Go client, admin calls go through the same authenticated client (`client.Export`, `client.ApplyChangeset`, `BlobProvision`, and the control-plane helpers); over the wire they are ordinary authenticated requests to `/_admin/…`.

## Metrics and the slow log

```yaml
logging: { slow_threshold: 200ms, expand_params: false }   # redact params by default
```

- `GET /_metrics` — Prometheus text exposition; scrape it. Gauges include `quicsql_active_sessions` (if it climbs and never falls, something opens Hrana streams without closing them — see the `transactions-and-hrana` skill).
- `GET /_health` — liveness, no auth.
- The slow-query log fires above `slow_threshold`; bound parameters are redacted unless `expand_params: true`.

## Limits (protect the server)

```yaml
limits:
  rate: { per_principal_rps: 100 }    # token bucket, per authenticated identity
  max_concurrent_per_db: 512          # admission cap per database
  statement_timeout: 30s              # interrupt a single runaway statement
  tx_idle_timeout: 30s                # reap an idle Hrana session (frees its pinned conn)
  max_tx_lifetime: 5m                 # hard cap on a session's age
  max_sessions_per_db: 64             # cap concurrent pinned sessions per db (reads + writes)
```

The session-related limits are the ones that protect against a client that opens a transaction and stalls — keep `tx_idle_timeout` short. Tuning rationale: the [Hrana guide](../../docs/hrana.md).

## Meta store

The server's runtime registry + audit + idempotency state is a vault by default; set `server.meta_store.key` (a secret ref from a non-meta source) to encrypt it at rest. An unkeyed vault meta store is plain and warned at startup.
