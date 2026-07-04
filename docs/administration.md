# Administering and maintaining quicSQL

quicSQL ships a real control plane, not a config file you restart your way
around: databases are created, inspected, maintained, and detached **at
runtime** over `/_admin`, every change is persisted and reconciled on restart,
and privileged actions land in an audit log. This guide is the operator's tour —
the control plane, vault maintenance, the audit trail, health/metrics/slow-query
observability, and the limits that keep one bad client from hurting the rest.

Everything here was verified against a running server; the transcripts are real.

## Enabling the control plane

```yaml
server:
  data_dir: /var/lib/quicsql
  meta_store:                  # runtime registry + audit log
    backend: vault             # vault (default) | file
    path: _meta.vault          # default; relative to data_dir
    key: keys:metakey          # omit and the server WARNs: meta store not encrypted at rest

control_plane:
  enabled: true
  admins: [ops]                # REQUIRED non-empty; each must be a configured principal

auth:
  principals:
    - name: ops
      methods:
        - bearer: { token_hash: "keys:ops_token_sha256" }
```

Two rules anchor the security model:

- **A server-admin is a named principal** listed in `control_plane.admins` —
  config loading refuses `enabled: true` with an empty list, and **open mode
  never applies to `/_admin`**: an anonymous caller on a wide-open dev server
  still cannot create, detach, or kill anything.
- **A per-database `admin` grant is the lesser power.** It unlocks
  [maintenance](#vault-maintenance) and the filtered `databases`/`sessions`
  views *for that database only* — never create, detach, kill, or `info`.

The meta store opens **only when the control plane is enabled**. That switch
also carries persistence and auditing: with the control plane off, runtime
changes are impossible *and* nothing is audited.

## The life of a database at runtime

### Create

`POST /_admin/create` takes the same database object you'd write as a YAML
seed — any backend (`file`, `memory`, `memory-shared`, `mvcc`, `memdb`,
`vault`) — plus authoritative grants:

```sh
curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/create -d '{
  "database": {"name": "newdb", "backend": "file", "path": "newdb.db"},
  "grants":   [{"principal": "app", "level": "read-write"}]
}'
# → {"status":"created","database":"newdb"}
```

The server validates the spec with the same validator as config seeds, confines
`path` to `data_dir` (`"../evil.db"` → 400 *"database path must be relative and
within data_dir"*), **test-opens the database immediately** (a spec that won't
open is rolled back with a 400), persists it to the meta store, then applies
grants — revoking any stale grants stored under that name first, so a re-created
name never inherits privileges from a previous life. A duplicate name is a 409.

### List

```sh
curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/databases
# → {"databases":[{"name":"appdb","kind":"file","open":true,"refs":0}, …]}
```

The view is **filtered, not gated**: a server-admin sees everything, a
principal holding an `admin` grant sees its own databases, and everyone else
gets an empty list — a `200`, not a `403`. (`/_admin/stats` is the same
handler and the same output.)

### Detach

```sh
curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/detach \
  -d '{"database":"newdb"}'
# while a Hrana session holds it → 409 "database busy (has active users); retry when idle"
# once idle                      → {"status":"detached","database":"newdb"}
```

Detach closes the handle (checkpointing the WAL on the way out), **revokes
every grant for the name**, forgets its metrics series, removes it from the
meta store, and audits. **The file on disk is not deleted** — detaching is an
un-serve, not a drop.

### Restart semantics

On boot the server reconciles **config seeds ∪ meta-store entries**; on a name
collision the meta store wins (logged as *"meta-store database shadows a config
seed"*). Every persisted entry is re-validated — including path containment —
so a tampered meta store degrades to a warning and a skipped entry, never a
served database at an escaped path. Grants stored in the meta store count
toward open-mode detection, so a server with one persisted grant stays locked
down even under a bare YAML.

> [!WARNING]
> A `file` database whose file is missing at restart is **silently re-created
> empty** — `mode: rwc` is the default. Where an empty resurrection would be
> data loss in disguise, seed the database with `mode: rw` or `ro` so a missing
> file fails loudly instead.

## Introspection: info, sessions, kill

```sh
curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/info
# → {"uptime_seconds":27,"goroutines":10,"heap_bytes":2919568,
#    "databases":2,"open_databases":2,"active_sessions":0}       (server-admin only; 403 otherwise)

curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/sessions
# → {"sessions":[{"id":"jDEOADzUTqSxWtYybB1-3w","database":"appdb","principal":"app",
#                 "read_only":false,"in_flight":false,"age_seconds":12,"idle_seconds":3}]}

curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/kill \
  -d '{"session":"jDEOADzUTqSxWtYybB1-3w"}'
# → {"status":"killed","session":"jDEOADzUTqSxWtYybB1-3w"}
```

A killed session's transaction is rolled back, its pinned connection returns to
the pool, and the next use of its baton is a 400 *"invalid or expired baton"*.
Killing a session with a request **in flight** is refused (409) — the statement
timeout will end it instead. Sessions the reaper would collect anyway die on
its schedule: the reaper ticks every **15 seconds** (fixed), so an idle session
with `tx_idle_timeout: 2s` actually lives up to ~17 s. Treat idle timeouts as
granularity-15s.

## Vault maintenance

`POST /_admin/maintenance` with `{"database", "op", …}` — gated by server-admin
**or** an `admin` grant on that database:

| `op` | Backends | Online? | Effect |
|---|---|---|---|
| `compact` | vault | offline-in-place | dense rewrite of the container into minimal size |
| `compact_online` | vault | online | returns freed blocks to the OS; `"max_bytes"` caps the pass |
| `trim` | vault | online | releases only the trailing free run — cheapest |
| `snapshot` | **any** | online | serializes the whole logical database to `"dest"` |

```sh
curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"orders","op":"compact"}'
# → {"status":"compacted","database":"orders"}          (verified: 2 248 704 → 2 170 880 bytes)

curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"orders","op":"snapshot","dest":"orders-backup.db"}'
# → {"status":"snapshot","database":"orders","dest":"/var/lib/quicsql/orders-backup.db","bytes":2228224}
```

Offline `compact` does **not** require downtime in the scheduling sense: it
drains and reserves the idle handle in place (409 *"database busy"* if the
database has active users), and clients see a lazy re-open on their next
request. The reclaim ops run against the live handle.

> [!WARNING]
> A snapshot is written **decrypted** — it is the logical SQLite image, not the
> vault container. That's what makes it a usable backup, and what makes it
> dangerous if `data_dir` is replicated somewhere untrusted. Mitigations built
> in: `dest` is confined to `data_dir` (escapes → 400), the file is created
> `O_EXCL` mode 0600 (existing dest → 409), and the image is buffered in RAM —
> plan for database-sized memory during a snapshot.

## The audit log

Every control-plane mutation lands in the `audit` table of the meta store —
including **denied** and **failed** attempts:

```
at=1751628437 principal=admin action=create         db=newdb    detail="file"
at=1751628438 principal=app   action=create.denied  db=         detail="not server-admin"
at=1751628440 principal=admin action=kill           db=         detail="jDEOADzUTqSxWtYybB1-3w"
at=1751628444 principal=admin action=snapshot       db=orders   detail="/var/lib/quicsql/orders-backup.db"
at=1751628450 principal=admin action=detach.failed  db=newdb    detail="database busy"
```

Actions recorded: `create` / `detach` / `kill` / the maintenance ops, plus
`.denied` (authorization refused) and `.failed` (attempted but errored)
variants. Not recorded: read-only views, validation rejections that never
reach the action (duplicate names, dest-escapes), and — deliberately —
**anything on the data plane**. Per-statement logging is the slow-query log's
job, not the audit trail's.

> [!NOTE]
> There is currently **no HTTP endpoint for reading the audit log** — it lives
> in the meta store (`data_dir/_meta.vault`), which is a single-owner vault
> container: stop the server and read it with a small Go program via
> `quicsql.net/meta`. Writes are best-effort (a failed audit write logs an
> error but never fails the operation), and with the control plane disabled
> there is no audit at all.

## Health, metrics, and the slow-query log

**`GET /_health`** answers `{"status":"ok"}` with **no credentials** on any
listener — it is liveness only (no database checks) and is whitelisted through
authentication precisely so load balancers can probe it.

**`GET /_metrics`** serves Prometheus text (format 0.0.4). It sits behind the
listener's normal authentication but has **no capability check** beyond it —
any authenticated principal can read database names. The intended pattern is a
loopback listener with `auth: [none]` for the scraper. The complete surface:

```
# TYPE quicsql_requests_total counter
quicsql_requests_total{db="appdb"} 2
# TYPE quicsql_request_duration_seconds summary
quicsql_request_duration_seconds_sum{db="appdb"} 0.00038975
quicsql_request_duration_seconds_count{db="appdb"} 2
# TYPE quicsql_active_sessions gauge
quicsql_active_sessions 0
# TYPE quicsql_databases gauge
quicsql_databases 4
```

Labels carry the database only (principals are deliberately excluded — label
cardinality), a detached database's series is forgotten, and the counter counts
**served** requests: a 429/503 rejection appears in neither the counter nor the
duration summary. Watch rejections in the logs, not the metrics.

**The slow-query log** turns on with a threshold:

```yaml
logging:
  slow_threshold: 250ms   # log statements slower than this
  expand_params: false    # default: bound parameters are redacted
```

Slow statements go to the server log as `INFO quicsql/slow duration_ms=… sql=…`
with bound parameters shown as `?` unless you opt into `expand_params: true`.
Two properties to know: the hook is installed **once per process** (changing the
threshold means a restart), and an aggressive threshold will happily log the
server's own meta-store statements alongside yours.

## The safety rails, and what tripping them looks like

Requests pass gates in a fixed order — authenticate (`401`), authorize
(`403`), rate limit (`429`), per-database admission (`503`), then run under the
statement timeout (`504`):

| Config key | Default | When it trips |
|---|---|---|
| `limits.rate.per_principal_rps` | 0 (off) | `429 "rate limit exceeded"` — token bucket per principal, burst = max(rps, 1) |
| `limits.max_concurrent_per_db` | 0 (off) | `503 "database busy: too many concurrent requests"` |
| `limits.max_request_bytes` | 8 MiB | `413 "request body exceeds the maximum allowed size"` |
| `limits.statement_timeout` | 30s | `504 "statement timed out"` — the query is interrupted, not abandoned |
| `limits.max_rows` | 100 000 | `200` with rows clipped and `"truncated": true` |
| `limits.max_result_bytes` | 64 MiB | same `truncated` mechanism |
| `limits.tx_idle_timeout` | 30s | session reaped; its baton → `400 "invalid or expired baton"` |
| `limits.max_tx_lifetime` | 5m | absolute session cap, same reap path |
| `limits.max_sessions_per_db` | 64 | `503 "too many open sessions"` |
| `limits.max_blob_bytes` | 1 GiB | `413` on a streamed blob write |
| `limits.idle_handle_timeout` | 0 (off) | idle handle closed, reopened on demand — note an idle-reaped **memory** database loses its contents |

Full-database exports are additionally capped at 1 GiB with at most 4 running
concurrently (fixed). And one monitoring gotcha that catches everyone: **SQL
errors are HTTP 200** with an `{"error": {...}}` envelope — only policy,
timeout, and authorization failures map to 4xx/5xx. Alert on the error
envelope, not the status code alone.

## Administering from the command line

The [qsql CLI](https://github.com/quicsql/qsql) wraps this whole surface, with
the same connection security flags as its shell (`--cert/--key/--ca/
--ed25519-key`). The admin token goes in `?token=` — bearer auth has no
username, so `ops:token@…` userinfo is **not** a token (a `user:password@…`
URL is HTTP Basic instead):

```sh
qsql ping 'quicsql://db.example.com:7777?transport=h2&token=OPS_TOKEN'   # GET /_health
qsql admin databases   <url>                          # list served databases
qsql admin info        <url>                          # process internals
qsql admin sessions    <url>                          # live Hrana sessions
qsql admin kill        <url> <session-id>
qsql admin create      <url> -f spec.json             # spec file = the create request body
qsql admin detach      <url> <database>
qsql admin maintenance <url> <db> compact|compact_online|trim|snapshot [--max-bytes N] [--dest PATH]
qsql export <url> [file]                              # pull a full database image client-side
```

The `<url>` is **optional** on every command: set the admin server once as
qsql's default (`dsn:` in `config.yaml`, a named connection, or `QSQL_DSN`) and
manage it without repeating the URL — `qsql admin databases`,
`qsql admin kill <session-id>`, `qsql admin maintenance app compact`. The same
views are also available inside the interactive shell as `\admin` commands —
see [the qsql guide](https://github.com/quicsql/qsql#quicsql-server-operations).

## Related guides

- **[Auth & authorization](auth-and-authz.md)** — principals, methods, grants,
  and why the control plane only ever answers to named admins.
- **[Databases & backends](databases.md)** — everything a `create` spec can
  say: backends, pragmas, pools, vault shapes, secrets.
- **[The Hrana pipeline](hrana.md)** — the sessions that `sessions`/`kill`
  manage, batons, and per-session limits from the client's side.
- **[mTLS in production](mtls-production.md)** — locking the admin listener to
  certificates.
