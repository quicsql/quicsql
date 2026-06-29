# Using Hrana with quicSQL in production

quicSQL speaks **Hrana**, libSQL's HTTP protocol for running SQL over a network, in addition to its plain native-JSON endpoint. Hrana is what you reach for when a single autocommit statement per request is not enough: **interactive transactions** (a `BEGIN … COMMIT` pinned to one server-side connection), **batches** (many statements in one round trip), and **changeset capture**. This guide explains the model and shows the production-ready ways to use it — mostly through the quicSQL Go client, and at the end over the raw wire for other languages.

## Native query vs Hrana pipeline — which to use

quicSQL gives you two request shapes. Pick by what the work needs:

| | Native query | Hrana pipeline |
| --- | --- | --- |
| Endpoint | `POST /<db>/query` | `POST /<db>/v3/pipeline` (also `v2`) |
| Statements per request | one | many |
| State | stateless (autocommits, runs on any pooled connection) | a **session**: statements share one pinned connection |
| Use it for | simple reads/writes, highest fan-out | transactions, batches, `SAVEPOINT`, changeset capture |
| Go client | `Query` / `Exec` | `OpenStream` (transactions) / `Batch` (throughput) |

The rule of thumb: if each statement stands alone, use the native path — it load-balances across the pool and is the simplest thing. The moment statements must run **together** (a transaction) or you want to avoid **per-statement round trips** (a batch), use Hrana.

## The session model (batons)

A pipeline request carries a **baton** — an opaque, signed session token:

```
open:     POST /app/v3/pipeline   { "baton": null, "requests": [ … ] }
              ↳ server pins a connection, runs the requests, returns a fresh baton
continue: POST /app/v3/pipeline   { "baton": "<the baton>", "requests": [ … ] }
              ↳ same connection resumes; baton rotates again
close:    include { "type": "close" } as the last request
              ↳ connection returns to the pool; no baton comes back
```

Everything on one baton runs on the **same server-side connection**, which is exactly what a transaction needs. Two properties matter in production:

- **A baton is bound to its database and its principal.** Resuming with a baton minted for a different principal is refused (`403`), and a wrong or expired baton is refused (`400`) — so a leaked baton cannot be used by someone else, and it cannot invalidate the owner's session.
- **A read-only principal's session is read-only for its whole life.** The pinned connection carries `query_only` plus a write-denying authorizer, so a read-only identity's transaction physically cannot write, even mid-transaction.

You rarely touch batons directly — the Go client threads them for you. But understanding them explains the one rule you must follow: **always close a stream** (below), or its pinned connection lingers until the idle reaper collects it.

## 1. Transactions — the primary use (Go client)

`OpenStream` gives you a session; run `BEGIN`, your statements, then `COMMIT` or `ROLLBACK`, and always `Close`:

```go
c := client.H2TLS("db.example.com:7777", false, client.WithRootCA(pool), client.WithClientCert(cert))
defer c.Close()

st := c.OpenStream("app")
defer st.Close(ctx) // releases the pinned connection even on an early return / error

if _, err := st.Exec(ctx, "BEGIN", nil); err != nil {
	return err
}
if _, err := st.Exec(ctx, "UPDATE accounts SET balance = balance - ? WHERE id = ?", []any{100, 1}); err != nil {
	_, _ = st.Exec(ctx, "ROLLBACK", nil)
	return err
}
if _, err := st.Exec(ctx, "UPDATE accounts SET balance = balance + ? WHERE id = ?", []any{100, 2}); err != nil {
	_, _ = st.Exec(ctx, "ROLLBACK", nil)
	return err
}
if _, err := st.Exec(ctx, "COMMIT", nil); err != nil {
	return err
}
```

`SAVEPOINT` / `RELEASE` / `ROLLBACK TO` work the same way — they are just statements on the stream. Two hard rules:

- **`defer st.Close(ctx)`.** The pinned connection is a scarce resource; closing returns it to the pool immediately. If you forget, the session survives until `tx_idle_timeout` reaps it (below) — a leak that shows up as connection exhaustion under load.
- **A stream is single-goroutine.** Drive one stream from one goroutine, exactly like a `database/sql` transaction. For concurrency, open multiple streams (or use the stateless `Query`/`Exec` for independent statements).

## 2. Batches — throughput (Go client)

When you have N independent statements and do not need a transaction, `Batch` runs them all in **one HTTP request** — one authentication, one round trip:

```go
results, err := c.Batch(ctx, "app", []client.Statement{
	{SQL: "INSERT INTO events(kind, at) VALUES (?, ?)", Args: []any{"login", now}},
	{SQL: "INSERT INTO events(kind, at) VALUES (?, ?)", Args: []any{"click", now}},
	{SQL: "UPDATE counters SET n = n + 1 WHERE k = ?", Args: []any{"events"}},
})
```

The statements run in order on one connection, each autocommitting; you get one `Result` per statement. **A batch is not atomic** — a failing statement does not roll back the earlier ones, and `Batch` returns the first error tagged with its index. For all-or-nothing, make the first and last statements `BEGIN` and `COMMIT`, or use a transaction stream. `Batch` is also the answer to the keyring method's per-request challenge cost: N statements share one authentication instead of N.

## 3. Transparent transactions via database/sql (the driver)

Most applications never call the Hrana client directly — they use the `database/sql` driver, which uses the native endpoint for autocommit statements and **transparently opens a Hrana session for `BeginTx`**:

```go
import _ "quicsql.net/client/sqldriver"

db, _ := sql.Open("quicsql", "quicsql://db.example.com:7777/app?transport=h2&token="+tok)

tx, err := db.BeginTx(ctx, nil)          // ← opens a Hrana session under the hood
if err != nil {
	return err
}
if _, err := tx.ExecContext(ctx, "UPDATE …"); err != nil {
	tx.Rollback()                        // ← closes the session
	return err
}
return tx.Commit()                       // ← commits and closes the session
```

For mTLS or keyring auth (which a DSN cannot express), build a `*client.Client` as in the [mTLS guide](mtls-production.md) and pass it to `sqldriver.OpenConnectorClient(c, "app")`, then `sql.OpenDB(...)`. Everything above works identically. LiteORM's transactions ride this same path — see the LiteORM-over-quicSQL example.

## Auth over Hrana

Hrana requests go through the **same** authentication middleware as everything else, so all the methods in the [auth guide](auth-and-authz.md) apply unchanged. Two notes for production:

- **Prefer a zero-per-request method for high transaction volume** — bearer, or better mTLS, which authenticates at the TLS handshake and costs nothing per pipeline request. The keyring method costs one challenge fetch, now cached and reused within its window, so a busy transaction pays it roughly once per minute rather than per statement.
- **The baton binds to the principal that opened it.** You cannot open a session as one identity and resume it as another; the resume is rejected. This is enforced server-side, independent of the transport.

## Production limits and tuning

These `limits` govern Hrana sessions directly. Set them deliberately — the defaults are conservative, and sessions hold real connections:

| Setting | What it protects | Guidance |
| --- | --- | --- |
| `tx_idle_timeout` | a client that opens a transaction and stalls | The reaper closes a session idle this long, freeing its connection. Keep it short (seconds to a minute) so a hung client can't pin a connection indefinitely. |
| `max_tx_lifetime` | a transaction that runs forever | Hard cap on total session age, regardless of activity — a backstop against a long-held writer blocking WAL checkpoints. |
| `max_sessions_per_db` | pinned-connection pressure | Each interactive session pins one connection (reads and writes alike); cap concurrent sessions per database so excess ones get a clear "too many sessions" instead of exhausting the pool. |
| `statement_timeout` | a single runaway statement | Interrupts any one statement that exceeds it (native or Hrana). |
| `max_concurrent_per_db` | overload | Admission cap on in-flight requests per database. |

```yaml
limits:
  tx_idle_timeout: 30s
  max_tx_lifetime: 5m
  max_sessions_per_db: 64
  statement_timeout: 30s
  max_concurrent_per_db: 512
```

Because SQLite has a single writer, the shape of good Hrana usage is: **keep transactions short**, do the reads you can outside the transaction (stateless `Query`), and open the write transaction only around the writes. Long-open write streams are the main way to hurt throughput.

## Error handling

Hrana preserves SQLite's **extended result codes** across the wire, so the client can classify errors precisely — a unique-constraint violation and a busy database come back distinguishable, not as an opaque "error string." In a batch, each statement's error is reported in its own result slot; the Go client's `Batch` returns the first one with its index. LiteORM's sentinels (`ErrUniqueViolation`, etc.) rely on exactly this fidelity and work unchanged remotely.

## Talking Hrana from other languages (raw wire)

The pipeline is plain JSON over HTTP, so any language can drive it. A pipeline that inserts a row and reads a count, then closes the session, is one request:

```sh
curl https://db.example.com:7777/app/v3/pipeline \
  --cacert server-ca.crt --cert svc.crt --key svc.key \
  -H 'content-type: application/json' \
  -d '{
        "baton": null,
        "requests": [
          { "type": "execute", "stmt": { "sql": "INSERT INTO t(v) VALUES (?)",
                                          "args": [ { "type": "text", "value": "hello" } ] } },
          { "type": "execute", "stmt": { "sql": "SELECT count(*) FROM t", "want_rows": true } },
          { "type": "close" }
        ]
      }'
```

The response mirrors the request — one result per entry, in order:

```json
{
  "baton": null,
  "results": [
    { "type": "ok", "response": { "type": "execute",
        "result": { "cols": [], "rows": [], "affected_row_count": 1, "last_insert_rowid": "1" } } },
    { "type": "ok", "response": { "type": "execute",
        "result": { "cols": [ { "name": "count(*)" } ], "rows": [ [ { "type": "integer", "value": "1" } ] ] } } },
    { "type": "ok", "response": { "type": "close" } }
  ]
}
```

Arguments use Hrana's **tagged value** form: `{"type":"integer","value":"7"}` (integers are strings), `{"type":"text","value":"…"}`, `{"type":"float","value":1.5}`, `{"type":"blob","base64":"…"}`, `{"type":"null"}`. To run a transaction, omit the trailing `close`, take the `baton` from the response, and send it back in the next request's `"baton"` field; send `close` when you commit. Authentication is the same header you would use anywhere (`Authorization: Bearer …`, a client certificate, or the keyring challenge headers). Beyond `execute` and `close`, the server also accepts the Hrana `batch`, `sequence`, `describe`, `store_sql`, `close_sql`, and `get_autocommit` requests, plus quicSQL's `session_start` / `session_changeset` extensions for changeset capture. `describe` prepares the statement server-side and returns its real shape — the parameter list, the result columns with declared types, `is_explain`, `is_readonly` — without executing it; libSQL SDKs use exactly this to route a statement as a query or an execute.

The `batch` request also has a **streaming variant**: `POST /<db>/v3/cursor` takes `{"baton": …, "batch": {"steps": […]}}` and answers with newline-separated JSON — first a prelude carrying the next baton, then one entry per line (`step_begin` with the step's columns, a `row` per result row, `step_end` with `affected_row_count` / `last_insert_rowid`, or `step_error` for a failed step) — so a large result arrives incrementally instead of as one document. Cursor requests share the pipeline's sessions and batons, honor the same step conditions, and are what Turso's `@tursodatabase/serverless` JavaScript driver speaks.

## Observability

Open sessions are visible operationally: the `quicsql_active_sessions` gauge on `/_metrics` tracks how many are live, and `/_admin` (admin only) lists sessions per database and can kill one. If that gauge climbs and does not fall, something is opening streams without closing them — check for a missing `defer st.Close(ctx)`.
