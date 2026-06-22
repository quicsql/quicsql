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

Transport-level problems use HTTP status codes: `401` (bad/missing
credentials), `403` (authorization denied — e.g. a write from a read-only
principal), `404` (unknown database), `413` (body too large), `504`
(statement timeout). The body always carries the envelope:

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

Beyond `/query`, each database also serves `/export` (a full database
snapshot), `/changeset/*` (SQLite session changesets), and `/blob/*` (streamed
large objects) — see the [server docs](../databases.md). Server-scoped
endpoints (`/_health`, `/_metrics`, `/_admin/*`) are documented in the
[auth guide](../auth-and-authz.md).
