# The native JSON API

The zero-dependency way to query quicSQL from any language: one endpoint per
database, one JSON shape in, one out. This page is the reference; the
per-language guides show idiomatic wrappers.

## The endpoint

```
POST /<db>/query
Content-Type: application/json
Authorization: Bearer <token>        (or any other configured auth method)
```

The body is **either** a single statement:

```json
{ "sql": "SELECT name, balance FROM users WHERE id = ?", "args": [7] }
```

**or** a batch, which runs as **one explicit transaction — all-or-nothing**:

```json
{ "statements": [
    { "sql": "INSERT INTO users(name, balance) VALUES (?, ?)", "args": ["ada", 100] },
    { "sql": "UPDATE counters SET n = n + 1 WHERE k = ?", "args": ["users"] }
] }
```

Setting both `sql` and `statements` is a 400. Statements are always
parameterized with positional `?` placeholders; `args` is a JSON array.

## Responses

A single statement returns one result object:

```json
{
  "columns": ["name", "balance"],
  "rows": [["ada", 70], ["bob", 130]],
  "rows_affected": 0,
  "last_insert_id": 0
}
```

A batch returns one result per statement, in order:

```json
{ "results": [ { "columns": [], "rows": [], "rows_affected": 1, "last_insert_id": 3 }, … ] }
```

- `rows` is always present (possibly `[]`), each row an array in column order.
- `rows_affected` / `last_insert_id` are meaningful for writes.
- `truncated: true` appears when the server's row/byte caps cut a result short
  — narrow the query or raise the configured cap.

## Values on the wire

| SQLite type | JSON encoding |
|---|---|
| `INTEGER` | JSON number, **exact** — 64-bit values are not rounded through floats |
| `REAL` | JSON number |
| `TEXT` | JSON string |
| `BLOB` | `{"base64": "<data>"}` — both directions (pass the same shape in `args`) |
| `NULL` | `null` |

## Errors

Transport-level problems use HTTP status codes: `400` (malformed request —
invalid JSON, an unknown field, or setting both `sql` and `statements`), `401`
(bad/missing credentials), `403` (authorization denied — e.g. a write from a
read-only principal), `404` (unknown database), `405` (wrong method — `/query`
is POST-only), `413` (body too large), `429` (the caller hit its rate limit),
`503` (the database is momentarily busy — the per-database concurrency cap, or a
database briefly unavailable during a control-plane operation), and `504`
(statement timeout). The [Hrana](../hrana.md) pipeline and cursor endpoints add
`501` when interactive sessions are disabled on the server. The body always
carries the envelope:

```json
{ "error": { "message": "no such table: userz", "code": 1, "extended_code": 1 } }
```

**One subtlety:** a batch whose statement fails at the SQL level returns
**HTTP 200** with the error envelope plus the index of the failing statement —
the transaction has been rolled back:

```json
{ "error": { "message": "UNIQUE constraint failed…", "code": 19, "extended_code": 2067 },
  "failed_index": 1 }
```

So clients should treat "response contains `error`" as the failure signal, not
just the HTTP status. `code` / `extended_code` are SQLite result codes.

## What this API is — and isn't

The native API is **stateless**: every request autocommits (a batch is one
transaction, but state never spans requests), which is exactly what makes it
simple and load-balancer-friendly. If you need an **interactive transaction**
spanning round trips — `BEGIN`, decisions in application code, `COMMIT` — use
the [Hrana pipeline](../hrana.md) (what the libSQL SDKs use), or the SDK for
your language which wraps it.

Beyond `/query`, each database also serves `/export` (a full in-memory database
snapshot), `/backup` (a streaming online backup with no size ceiling),
`/changeset/*` (SQLite session changesets), `/blob/*` (streamed large objects),
and `/changes` (a live Server-Sent-Events change feed) — specified
[below](#beyond-query). Server-scoped endpoints live elsewhere: `/_health`
(unauthenticated liveness), `/_auth/challenge` (the keyring nonce), and
`/_auth/session` (mint/renew/revoke a short-lived session token) are in the
[auth guide](../auth-and-authz.md), and `/_metrics` (Prometheus) and `/_admin/*`
(the control plane, including in-place `restore`) are in
[administration](../administration.md). Browser callers additionally need the
server's `cors:` block enabled — also covered in the auth guide; note a `*`
origin is refused unless authentication is configured.

## Beyond `/query`

The same per-database URL prefix carries more endpoints for work the single-shot
JSON path can't express: a full-database snapshot, SQLite session changesets,
streamed large objects, and a live change feed. They share the auth, routing, and
admission (`429`/`503`) behavior of `/query`; each adds its own body shape and
status codes.

### `/export` — a full database snapshot

```
GET /<db>/export
Authorization: Bearer <token>
```

Returns the entire database as one SQLite file image
(`application/octet-stream`) — the same bytes a file-level backup would hold —
with `Content-Disposition: attachment; filename="<db>.sqlite"`. **Read access is
enough:** a principal who can read every row via SQL gains nothing extra from a
bulk copy. A vault (encrypted) database is serialized **decrypted**, exactly as
its readers already see it — the client can't ask for the on-disk form. It is
GET-only (`405` otherwise), and there is no companion per-database `/import`
endpoint; bulk restore is a control-plane op (`POST /_admin/restore`, server-admin
only — see [administration](../administration.md#backup-and-restore)).

The image is materialized whole in RAM before it streams, so two limits guard
the process:

- A database whose image exceeds the export cap (default **1 GiB**,
  `limits.max_export_bytes`) is refused with `413`.
- At most **4** exports run at once across the whole server (independent of the
  per-database concurrency cap, since each holds a full image in memory). A
  request beyond that waits for a slot; if its own request context is cancelled
  or times out while waiting, it returns `503` ("too many concurrent exports").

### `/backup` — a streaming online backup

```
GET /<db>/backup
Authorization: Bearer <token>
```

Same idea as `/export` — a standalone SQLite file (`application/octet-stream`,
`Content-Disposition: attachment`) any SQLite tool can open — but produced by the
SQLite **online-backup API**: it page-copies the live database into a temp file
with **bounded memory** and streams that, so there is **no RAM ceiling and no
size cap**, and it doesn't block writers (the backup restarts any page rewritten
mid-copy). Read access is enough, and a vault database backs up to its decrypted
logical image, exactly like `/export`. Prefer `/backup` for anything large;
`/export` remains for the simple in-memory-image case. GET-only. Concurrent
backups share the export slot pool (`503` beyond it).

### `/changeset/*` — SQLite session changesets

These move **changesets** — the binary diff SQLite's
[session extension](https://www.sqlite.org/sessionintro.html) records — between
databases, the backbone of a simple logical-replication or undo workflow. All
three are POST.

| Endpoint | Access | Request body | Response |
|---|---|---|---|
| `POST /<db>/changeset/apply` | write | raw changeset bytes | `{"status":"ok"}` |
| `POST /<db>/changeset/invert` | read | raw changeset bytes | inverted changeset (`application/octet-stream`) |
| `POST /<db>/changeset/concat` | read | JSON `{"a":"<base64>","b":"<base64>"}` | concatenated changeset (`application/octet-stream`) |

Mind the **body-format asymmetry**: `apply` and `invert` take the changeset as
the **raw request body** (the exact bytes); `concat` takes a **JSON** object
whose two changesets are **base64-encoded** — it carries two of them, so it
can't use a raw body. `apply` requires **write** access (it mutates the database
on a fresh connection); `invert` and `concat` are pure transforms that read and
write nothing, so **read** access suffices.

Errors beyond the shared codes: an empty body is `400` ("empty changeset"); a
malformed `concat` body is `400` (bad JSON, or a value that isn't valid base64);
a changeset SQLite rejects (wrong schema, corrupt) is `422`; a body over the
shared request-body cap (`limits.max_request_bytes`, default 8 MiB — not the
larger blob cap) is `413`.

**The capture → apply flow (replication).** You *capture* a changeset over
[Hrana](../hrana.md): open a stream, send a `session_start` request (optionally
naming the tables to track), run your writes, then send `session_changeset`,
which returns the accumulated changeset as **base64**. To replicate it onto
another database (or another server), base64-**decode** it and POST the raw
bytes to that database's `/changeset/apply`. `invert` yields a changeset's undo;
`concat` merges two captures into one.

### `/blob/*` — streamed large objects

For objects too big to round-trip through a `BLOB` column, quicSQL exposes
gosqlite's **blobstore**: chunked, optionally compressed and deduplicated
objects, each addressed by a numeric **id** inside a named **store**. A blob
write and read **stream**, so a single object is bounded by the large-object cap
(default **1 GiB**, `limits.max_blob_bytes`), not the small JSON body cap.

Every call takes `?store=<name>` (a valid identifier — invalid or missing is
`400`); the per-object ops also take `?id=<n>` (missing → `400 "missing ?id="`,
non-numeric → `400 "invalid ?id="`).

| Endpoint | Method | Access | Query | Response |
|---|---|---|---|---|
| `/<db>/blob/provision` | POST | write | `?store=` + options | `{"status":"ok"}` |
| `/<db>/blob/create` | POST | write | `?store=` | `{"id":<n>}` |
| `/<db>/blob/write` | POST | write | `?store=&id=` | `{"size":<n>}` |
| `/<db>/blob/read` | GET | read | `?store=&id=` | raw bytes (`application/octet-stream`) |
| `/<db>/blob/size` | GET | read | `?store=&id=` | `{"size":<n>}` |
| `/<db>/blob/delete` | POST | write | `?store=&id=` | `{"status":"ok"}` |

The typical lifecycle: `provision` a store once with the layout you want,
`create` to mint an id, `write` the bytes (the body streams; a rewrite that
shrinks the object truncates it to the new length), then `read`/`size` as needed
and `delete` when done. `create`/`write`/`delete` need write access;
`read`/`size` need only read; wrong method is `405` (writes POST, reads GET). A
store that was never provisioned is created with defaults on first write, so
`provision` is optional — but reading from a store that doesn't exist is `404`.

**Provisioning options** are query params on `/blob/provision`; they fix the
store's storage layout, and every object created in it afterward honors them:

| Param | Values | Effect |
|---|---|---|
| `chunk` | positive integer | chunk size, in bytes |
| `compress` | `fastest` `fast` `default` `better` `best` | per-chunk compression level |
| `dedup` | `1` | deduplicate identical chunks |

**Status codes:** `400` (invalid/missing `?store=` or `?id=`); `403` (a write
from a read-only principal); `404` (unknown database; a store that doesn't exist
on a read; or an unknown object id); `405` (wrong method); `413` (a write over
`max_blob_bytes`); `422` (the blobstore operation itself failed — a provision,
store open on a write, create, write, read, size, or delete error). The shared
`429`/`503` admission codes apply as everywhere.

### `/<db>/changes` — the live change feed (SSE)

```
GET /<db>/changes?since=<seq>&tables=<a,b>
Authorization: Bearer <token>
Accept: text/event-stream
```

A [Server-Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
stream of **committed row changes** — the LISTEN/NOTIFY quicSQL's single-owner
architecture makes exact. It is off until the server enables [`changefeed:`](../change-feed.md),
and only databases with a stable on-disk path (`file`, `vault`) are observable.
**Read access** is required.

Each event carries `{seq, table, op, rowid}` — **never column values** — so the
feed tells a subscriber *what to re-read* and can never leak a column it
shouldn't see. The stream opens with a `ready` (or `reset`) event, then one
`change` event per committed row (`id:` = its sequence):

```
event: ready              ← or `reset`: your horizon left the buffer / server restarted — refetch, then follow
data: {"seq":41}

id: 42
event: change
data: {"seq":42,"table":"orders","op":"insert","rowid":7}

: ping                    ← keepalive comment every 25s
```

Resume after a disconnect with `?since=<seq>` (or the standard `Last-Event-ID`
header) and you continue exactly where you left off; if the gap outgrew the
replay ring you get a `reset` instead (refetch, then follow). `?tables=a,b`
filters server-side. A single huge transaction that overflows the per-commit
buffer publishes one `reset` in place of per-row detail. Beyond
`changefeed.max_subscribers` concurrent streams the server returns `503`. A
slow consumer is disconnected (it resumes by sequence) rather than allowed to
stall the commit path. Full narrative, sizing, and the `@quicsql/client`
`subscribe()` wrapper are in the [change-feed guide](../change-feed.md).
