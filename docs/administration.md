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
    key: keys:metakey          # vault backend only (a raw cipher key); ignored for backend: file.
                               #   Omit on a vault and the server WARNs: meta store not encrypted at rest

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
  [maintenance](#maintenance) and the filtered `databases`/`sessions`
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

## Enrolled principals: list, delete

When [device enrollment](auth-and-authz.md) is enabled, the runtime-enrolled
principals are managed here (server-admin only — per-database `admin` grants do
not extend to identity management; both routes 404 when enrollment is off):

```sh
curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/principals
# → {"principals":[{"name":"u_a3f9k2m8p1qxw7bn","key":"ssh-ed25519 AAAA…","created_at":1751666400}]}

curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/principals/delete \
  -d '{"name":"u_a3f9k2m8p1qxw7bn"}'
# → {"deleted":"u_a3f9k2m8p1qxw7bn"}          (404 for an unknown or config-defined name)

# Mint a single-use enrollment code (when auth.enroll.codes.enabled):
curl -s -X POST -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/enroll/codes
# → {"code":"ec_5f3k…","expires_at":1751752800}   (plaintext code shown once; hand it to one user)
```

`POST /_admin/enroll/codes` mints a one-time enrollment code — a per-user invite that works exactly once (consumed atomically when a new principal registers), the alternative to the shared static `tokens`. It `400`s if `auth.enroll.codes.enabled` is off, `404`s when enrollment is off.

Deletion revokes everything at once — the key stops authenticating and every
templated grant disappears — and is audited (`principals.delete`), as are
denied and failed attempts. Config-defined principals are not listed and cannot
be deleted here; they live in YAML.

One caveat if [session tokens](auth-and-authz.md) are also enabled: a session
token the deleted principal already minted is stateless and keyed by principal
name, so it keeps working until it expires (bounded by `auth.session.idle_ttl`,
or `max_ttl` for a renewable one). Its
*templated* grants are gone the instant you delete, but a `*` wildcard grant
would still apply to it for that window. Keep the session TTL short, or detach
the wildcard-granted database, if immediate cutoff matters.

## Maintenance

`POST /_admin/maintenance` with `{"database", "op", …}` — gated by server-admin
**or** an `admin` grant on that database:

| `op` | Backends | Online? | Effect |
|---|---|---|---|
| `compact` | vault | offline-in-place | dense rewrite of the container into minimal size |
| `compact_online` | vault | online | returns freed blocks to the OS; `"max_bytes"` caps the pass |
| `compact_logical` | vault | online | rewrites the live container down to its logical footprint (the O(live-data) reclaim after big deletes) |
| `trim` | vault | online | releases only the trailing free run — cheapest; `"max_bytes"` caps it too |
| `reclaimable` | vault | online (read-only) | reports `reclaimable_bytes` a logical compaction would free — a probe, not a mutation |
| `checkpoint` | **any WAL** | online | WAL checkpoint on the live handle; `"mode"` is `passive` (default) / `full` / `restart` / `truncate` |
| `snapshot` | **any** | online | serializes the whole logical database (**decrypted**, for a vault) to `"dest"` |
| `snapshot_encrypted` | vault | offline | re-sealed **encrypted** copy of the container to a separate `"dest"` — no plaintext on disk |
| `members` | vault (recipient) | offline | enumerate the keyslot membership (masters / writers / read-only members) |
| `rewrap` | vault (recipient) | offline | re-wrap the data key to the configured membership — **O(1)**, access-list only |
| `rekey` | vault (recipient) | offline | re-encrypt under a **fresh** data key + the configured membership — **O(size)**, true revocation |

```sh
curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"orders","op":"compact"}'
# → {"status":"compacted","database":"orders"}          (verified: 2 248 704 → 2 170 880 bytes)

curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"orders","op":"reclaimable"}'
# → {"database":"orders","reclaimable_bytes":131072}     (a probe — how much compact_logical would free)

curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"orders","op":"compact_logical"}'
# → {"status":"reclaimed","database":"orders","bytes_reclaimed":131072}

curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"users","op":"checkpoint","mode":"truncate"}'
# → {"status":"checkpointed","database":"users","mode":"truncate","wal_frames":0,"checkpointed_frames":0}

curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"orders","op":"snapshot","dest":"orders-backup.db"}'
# → {"status":"snapshot","database":"orders","dest":"/var/lib/quicsql/orders-backup.db","bytes":2228224}

curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"orders","op":"snapshot_encrypted","dest":"orders-backup.vault"}'
# → {"status":"snapshot_encrypted","database":"orders","dest":"/var/lib/quicsql/orders-backup.vault","bytes":2170880}
```

The online reclaim ops (`compact_online`, `trim`, `compact_logical`) report how
much they returned to the OS in `bytes_reclaimed`; `compact_online`/`trim` take an
optional `"max_bytes"` to cap a single pass. Use `reclaimable` first to see
whether a `compact_logical` is worth running. `checkpoint` bounds WAL growth
without a restart — `truncate` also zeroes the WAL file — and reports the WAL
frame counts; it needs a WAL-mode database (the `recommended` pragma preset
enables WAL).

Offline `compact` does **not** require downtime in the scheduling sense: it
drains and reserves the idle handle in place (409 *"database busy"* if the
database has active users), and clients see a lazy re-open on their next
request. The reclaim ops run against the live handle.

> [!WARNING]
> A `snapshot` is written **decrypted** — it is the logical SQLite image, not the
> vault container. That's what makes it a usable backup, and what makes it
> dangerous if `data_dir` is replicated somewhere untrusted. Mitigations built
> in: `dest` is confined to `data_dir` (escapes → 400), the file is created
> `O_EXCL` mode 0600 (existing dest → 409), and the image is buffered in RAM —
> plan for database-sized memory during a snapshot.
>
> For an encrypted vault, prefer **`snapshot_encrypted`**: it re-seals a
> standalone copy of the container so **no plaintext ever touches disk** (same
> `dest`-within-`data_dir` and no-clobber rules). It reserves the database (drains
> the idle handle — 409 if busy) for a consistent read and streams via a temp
> file, so it isn't RAM-bound like `snapshot`. Raw-key vaults re-seal in-band;
> a recipient/identity-mode vault carries no runtime recipients and can't be
> re-sealed this way (→ 500) — snapshot those out of band.

### Vault key lifecycle (recipient-mode vaults)

A vault encrypted **to recipients** (an `age`-style keyslot with masters, writers, and read-only members — not a raw `key`) can have its access list managed at runtime, without moving the data. The target membership is the vault's own **`create:` block**: edit the recipients/masters/writers in YAML, then reconcile the on-disk container.

```sh
# Who can open this vault? (masters may enumerate)
curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"secrets","op":"members"}'
# → {"database":"secrets","members":[{"role":"master","key":"ssh-ed25519 AAAA…"},{"role":"member","key":"ssh-ed25519 AAAA…"}]}

# Admit/drop recipients cheaply (re-wrap the data key to the configured set):
curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"secrets","op":"rewrap"}'
# → {"status":"rewrapped","database":"secrets"}

# True cryptographic revocation (new data key, rewrites every page):
curl -s -H "Authorization: Bearer $OPS" http://127.0.0.1:7775/_admin/maintenance \
  -d '{"database":"secrets","op":"rekey"}'
# → {"status":"rekeyed","database":"secrets"}
```

- **`rewrap`** re-wraps the *existing* data key to the new membership — **O(1)**, regardless of database size. Because the data key is unchanged, a party you *removed* who already learned that key can still decrypt data they previously read; rewrap manages the access list, not the cryptography.
- **`rekey`** generates a **fresh** data key and re-encrypts every page under it — **O(database size)** — so a removed party can no longer read anything even with the old key. This is the only way to truly revoke a master.

All three run **offline**: the database is reserved (its handle drained — `409` if it has active users) so the container is closed while the keyslot is rewritten, and reopens on the next request. **`members` is available to a per-database admin; the membership-changing `rewrap`/`rekey` require a server-admin** (they re-seal or re-encrypt, too heavy to reach through a per-database `*: admin` wildcard). The op also **seals the new keyslot before it commits**, so an unauthorized caller (a `by` that isn't a current master, per `create.sign_with`) fails cleanly *before* any data is touched. These ops apply only to recipient-mode vaults; a raw-`key` vault has no keyslot (rotate it by re-encrypting out of band). Config validation still holds: `create.sign_with` must resolve to a master identity.

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

### Reading the audit log

The reader must run **with the server stopped** (the meta store is a single-owner
vault) and resolve the **same `meta_store.key`** the server used — reuse the
server's `secrets` block so the reference resolves identically:

```go
package main

import (
	"fmt"
	"log/slog"

	"quicsql.net/config"
	"quicsql.net/meta"
	"quicsql.net/secret"
)

func main() {
	// The same secret sources the server runs with, so meta_store.key resolves.
	sec, err := secret.New([]config.SecretSource{
		{Name: "keys", Type: "file", Dir: "/var/lib/quicsql/keys"},
	})
	if err != nil {
		panic(err)
	}

	// The same server.meta_store config: backend, path (relative to data_dir), key.
	store, err := meta.Open(config.MetaStore{
		Backend: "vault",           // "file" if you configured that
		Path:    "_meta.vault",     // relative to data_dir
		Key:     "keys:metakey",    // omit for an unencrypted meta store
	}, sec, "/var/lib/quicsql", slog.Default())
	if err != nil {
		panic(err) // fails if the server is still running (single-owner) or the key is wrong
	}
	defer store.Close()

	entries, err := store.AuditEntries(100) // newest first; a limit <= 0 defaults to 100
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		fmt.Printf("at=%d principal=%s action=%s db=%s detail=%q\n",
			e.At, e.Principal, e.Action, e.DB, e.Detail)
	}
}
```

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
  format: text            # json | text (default text) — the log output format
```

`logging.format` selects the log output format: `json` emits structured JSON (one
object per line, for a log pipeline), `text` (the default) emits slog's
human-readable text. Both go to stderr. Slow statements go to the server log as
`quicsql/slow duration_ms=… sql=…` with bound parameters shown as `?` unless you
opt into `expand_params: true`. Two properties to know: the slow-log hook is
installed **once per process** (changing the threshold means a restart), and an
aggressive threshold will happily log the server's own meta-store statements
alongside yours.

> [!NOTE]
> The top-level `wire_compression` and `observability` sections are **parsed but
> not yet wired** — don't build tooling on them. They parse, and the daemon logs a
> `present but not active yet` warning at startup, but nothing consumes them.

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
| `limits.max_export_bytes` | 1 GiB | `413` on a full-database `/export` that exceeds it |
| `limits.max_restore_bytes` | 4 GiB | `413 "restore image exceeds the size cap"` on a `/_admin/restore` upload (`<0` = no cap) |
| `limits.idle_handle_timeout` | 0 (off) | idle handle closed, reopened on demand — note an idle-reaped **memory** database loses its contents |

Full-database copies are additionally capped: `/export` at `limits.max_export_bytes`
(default 1 GiB, since it materializes in RAM), `/backup` at no size (it streams),
and `/_admin/restore` at `limits.max_restore_bytes` (default 4 GiB, streamed to
disk; `<0` removes it). `/export` and `/backup` share one pool of **at most 4
running concurrently** (fixed); over that is a `503`. And one
monitoring gotcha that catches everyone: **SQL
errors are HTTP 200** with an `{"error": {...}}` envelope — only policy,
timeout, and authorization failures map to 4xx/5xx. Alert on the error
envelope, not the status code alone.

## Running as a service

The daemon is a single static binary with no runtime dependencies: run it under
any supervisor as an **unprivileged user that owns `data_dir`**. A minimal,
hardened systemd unit:

```ini
# /etc/systemd/system/quicsql.service
[Unit]
Description=quicSQL server
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=quicsql
Group=quicsql
# systemd creates /var/lib/quicsql and chowns it to the service user; point
# server.data_dir at it. StateDirectory keeps it writable under ProtectSystem.
StateDirectory=quicsql
ExecStart=/usr/local/bin/quicsql --config /etc/quicsql/quicsql.yaml
NoNewPrivileges=true
ProtectSystem=strict
# SIGTERM (systemd's default stop signal) starts the graceful drain; give it
# more than the 10s drain window so a busy shutdown isn't SIGKILLed mid-flight.
TimeoutStopSec=20s
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Three behaviors make this safe:

- **Non-root, owner-only files.** Run as a dedicated user; `data_dir` (databases,
  WAL sidecars, the meta store, snapshots) must be writable by it. The daemon
  additionally hardens its own umask to **0600** at startup, so those files are
  created owner-only rather than world-readable under the common `umask 022` —
  they can hold plaintext data and the audit log. (This is a daemon-only step;
  an in-process `serverd.Run` embedder keeps its own umask.)
- **Graceful shutdown on SIGINT/SIGTERM.** `Ctrl-C` or `systemctl stop` triggers
  a drain bounded at **10 seconds**: in-flight requests finish within that
  window, then shutdown proceeds in order — **listeners → sessions → registry →
  meta store**: stop accepting, roll back open transactions and return their
  pinned connections, checkpoint the WAL on each handle close, then close the
  meta store. Nothing closes a resource still in use.
- **Fail-fast start.** A bad config or a seed database that won't open aborts
  startup with a non-zero exit (seed databases are opened eagerly, with a 30s
  warm timeout, so a wedged backend fails loudly instead of hanging) — the
  process never serves a half-initialized instance, so `Restart=on-failure` is
  safe.

## Running in Docker

The shipped image (`ghcr.io/quicsql/quicsql`) is `distroless/static` **nonroot**
(uid `65532`) — the CGo-free static binary needs no libc and **no shell**. It
declares a `/data` volume and exposes the canonical ports, TCP **and** UDP:

```sh
docker run \
  -v quicsql-data:/data \
  -v ./quicsql.yaml:/etc/quicsql/quicsql.yaml:ro \
  -v ./keys:/etc/quicsql/keys:ro \
  -p 7775:7775 -p 7777:7777 -p 7777:7777/udp \
  ghcr.io/quicsql/quicsql
```

- **Persist `/data`.** Point `server.data_dir` at `/data` (the image's `WORKDIR`,
  so relative database `path`s resolve there). The meta store and every vault /
  file container live under it — a fresh container with an empty volume starts
  with no runtime-created databases and no audit history.
- **Mount config and secrets read-only.** The default config path is
  `/etc/quicsql/quicsql.yaml`; mount yours there (`:ro`). Mount any `file`
  secret source's directory read-only too.
- **Publish every port you enable — including `7777/udp`.** HTTP/3 rides QUIC
  over UDP; publishing only `7777/tcp` silently drops h3 while h2 still works.
  The image `EXPOSE`s `7775-7777/tcp` and `7777/udp`.
- **No shell to exec into.** Debug from outside — the logs, `/_health`,
  `/_metrics` — not `docker exec`. That absence is the hardening, not a gap.

## Backup and restore

**Three backup artifacts**, all the **decrypted logical SQLite image** (not the
on-disk container): the [`snapshot`](#maintenance) maintenance op (writes the
image to a `dest` within `data_dir`), [`GET /<db>/export`](clients/http-api.md)
(streams the whole image, materialized in RAM, capped at 1 GiB), and
[`GET /<db>/backup`](clients/http-api.md) (a **streaming online backup** with no
RAM ceiling and no size cap — prefer it for anything large). **Read access** is
enough for both `/export` and `/backup`, and the two draw from one server-wide
pool of 4 concurrent copies (`503` beyond it). For a vault database all three are
**decrypted** — usable as a plain backup, but handle them as sensitive.

**Restore into a file database, in place:** `POST /_admin/restore?database=<db>`
with the SQLite image as the raw body (server-admin only). The server validates
the image (magic header + it opens + `PRAGMA integrity_check`) *before* touching
anything, then reserves the database (409 if it has active users), removes the
stale `-wal`/`-shm` sidecars, and swaps the validated image in with an **atomic
rename**; the handle reopens on the next request. Back up first — the previous
contents are discarded. The upload is bounded by **`limits.max_restore_bytes`
(default 4 GiB**, streamed to disk; `413` if larger) — raise it to restore a
bigger image in place, or set it **below 0** to remove the cap entirely. `/backup`
itself has no ceiling, so you can also place a large file under `data_dir` out of
band (stop the server and swap it, or serve a freshly-placed copy via
`POST /_admin/create`; see the end of this section).

```sh
curl -s -X POST -H "Authorization: Bearer $OPS" --data-binary @backup.sqlite \
  http://127.0.0.1:7775/_admin/restore?database=orders
# → {"status":"restored","database":"orders","bytes":2228224}
```

The Go client wraps it as `AdminRestore(ctx, db, io.Reader)` (streamed);
`BackupTo` on one server and `AdminRestore` on another is a clone in two calls.

**Vaults restore out-of-band** — a plain image can't be swapped into an encrypted
container, so `/_admin/restore` rejects a vault backend (400). Reintroduce a vault
backup one of two ways:

- **Load a logical image into a fresh vault over SQL.** Serve the snapshot/export
  as a `file` database, provision a new `vault` database, and copy the data across
  with SQL; then cut clients over to the vault.
- **From a cold copy of the `.vault` container.** A byte-for-byte `cp` taken
  **while the server was stopped** (the vault is single-owner; never copy a live
  one) restores as the *same* vault database — put it back at its `path` and serve
  it with the same `key`/identity (the keyslots travel inside the container). This
  is the only artifact that stays encrypted end to end.

Swapping files under `data_dir` requires the server **stopped**; serving a
freshly-placed file through `POST /_admin/create` works while it runs.

## Protecting the meta store

The meta store — a vault container at `data_dir/_meta.vault` by default — holds
two things the YAML config cannot: the databases **created at runtime** through
the control plane, and the **audit log**. `server.meta_store.key` encrypts it at
rest (a keyless vault meta store is plaintext and warned at startup). It is
**raw-key mode only** — a single cipher key, not the recipient/`identities` mode
a vault *database* offers — and it must resolve from a secret source that isn't
the meta store itself (env, a keys file, or a `kms` command hook), since the
store can't decrypt its own key. That key is load-bearing:

- **Losing the key aborts startup.** With the control plane enabled, a meta store
  that won't open (missing or wrong key) fails `serverd.Run` and the daemon exits
  non-zero — it will not serve without its registry and audit trail.
- **And it orphans every control-plane-created database.** Those live *only* as
  rows in the meta store; without the key they are never reconciled, so they stop
  being served even though their container files still sit under `data_dir`. Your
  config `databases:` seeds don't depend on the meta store — but you can't reach
  them until either the key is restored or the control plane is disabled, and
  disabling it drops every runtime-created database.

So: **back up `meta_store.key`** (it resolves from a secret source — commonly a
file under the keys directory) alongside the meta store container and the vault
databases it points at. The meta store is single-owner and there is **no
key-rotation story yet** — choose the key once, and guard it like the vault keys
it protects.

## Administering from the command line

Two different binaries — don't confuse them. The **`quicsql` daemon** (the server
this guide is about) is not an admin tool: it takes only `--config` (default
`quicsql.yaml`) and `--version`, has **no subcommands**, and does its work by
serving. Everything above is driven over HTTP against `/_admin`, or with the
separate `qsql` client below.

```sh
quicsql --config /etc/quicsql/quicsql.yaml   # the only meaningful invocation
quicsql --version                            # prints "quicsql <version>" and exits
```

The version string is stamped at release time (`dev` in a local build). There is
no `quicsql serve`/`quicsql admin` — the brand-named binary leaves room for
future subcommands, but today the daemon's whole CLI is those two flags.

The [qsql CLI](https://github.com/quicsql/qsql) is the admin client: it wraps
this whole surface, with the same connection security flags as its shell
(`--cert/--key/--ca/--ed25519-key`). The admin token goes in `?token=` — bearer
auth has no username, so `ops:token@…` userinfo is **not** a token. In the
external `qsql` CLI a `user:password@…` URL is HTTP Basic instead. (The in-repo
`quicsql://` `database/sql` driver is stricter: it **rejects all URL userinfo**
and reads credentials only from query params — `?token=` or `?user=&password=`.)

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

The HTTP `/_admin` surface leads the CLI: the newer maintenance ops
(`compact_logical`, `reclaimable`, and `checkpoint` with its `--mode`) and
in-place `restore` are always reachable over HTTP (the [maintenance
table](#maintenance) above) and the Go client even if a pinned `qsql` build
doesn't yet expose a flag for them.

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
