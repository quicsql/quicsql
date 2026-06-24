---
name: transactions-and-hrana
description: Use when running interactive transactions (BEGIN…COMMIT, savepoints) or batching many statements in one round trip against a quicSQL server, via the database/sql driver, the client's OpenStream / Batch, or the raw Hrana pipeline for other languages.
---

# Transactions and batching (Hrana)

quicSQL has two request shapes: the stateless **native** path (one autocommit statement per request) and the **Hrana pipeline** (many statements per request, or a session-pinned connection for a transaction). Reach for Hrana when statements must run *together* or you want to avoid per-statement round trips. Full narrative: the [Hrana guide](../../docs/hrana.md).

## Transactions — via database/sql (transparent)

The driver uses the native path for autocommit and opens a Hrana session automatically for `BeginTx`:

```go
tx, _ := db.BeginTx(ctx, nil)        // opens a session-pinned connection
tx.ExecContext(ctx, "UPDATE accounts SET balance = balance - ? WHERE id = ?", 100, 1)
tx.ExecContext(ctx, "UPDATE accounts SET balance = balance + ? WHERE id = ?", 100, 2)
tx.Commit()                          // (or tx.Rollback())
```

Every statement in the transaction runs on the same server-side connection; `SAVEPOINT` nesting works.

## Transactions — via the client (OpenStream)

```go
st := cl.OpenStream("app")
defer st.Close(ctx)                  // ALWAYS close — releases the pinned connection
st.Exec(ctx, "BEGIN", nil)
st.Exec(ctx, "INSERT INTO t(v) VALUES(?)", []any{"a"})
st.Exec(ctx, "COMMIT", nil)
```

A stream is **single-goroutine** (like a `database/sql` tx). Forgetting `Close` leaks the pinned connection until `tx_idle_timeout` reaps it — the main way to hurt throughput. A read-only principal's stream is read-only for its whole life.

## Batching — many statements, one round trip

When statements are independent and you don't need a transaction, `Batch` runs them all in **one HTTP request** (one authentication, one round trip):

```go
res, err := cl.Batch(ctx, "app", []client.Statement{
    {SQL: "INSERT INTO events(kind) VALUES(?)", Args: []any{"login"}},
    {SQL: "UPDATE counters SET n = n + 1 WHERE k = ?", Args: []any{"events"}},
})
```

One `Result` per statement, in order. A batch is **not atomic** — a failing statement doesn't roll back earlier ones, and `Batch` returns the first error tagged with its index. For all-or-nothing, make the first/last statements `BEGIN`/`COMMIT`, or use `OpenStream`. Batch also collapses the keyring method's per-request challenge cost to one — see the `pitfalls` skill.

## Raw wire (other languages)

The pipeline is plain JSON: `POST /<db>/v3/pipeline` with `{"baton": null, "requests": [ {"type":"execute","stmt":{"sql":"…","args":[…]}}, {"type":"close"} ]}`. Omit `close` and thread the returned `baton` back to continue a transaction. Args use Hrana's tagged form (`{"type":"integer","value":"7"}`, `{"type":"text","value":"…"}`, `{"type":"blob","base64":"…"}`, `{"type":"null"}`). A batch can also stream: `POST /<db>/v3/cursor` with `{"baton": …, "batch": {"steps": […]}}` answers with newline-separated JSON — a baton prelude, then `step_begin`/`row`/`step_end`/`step_error` entries per executed step — on the same sessions and batons as the pipeline. Auth is the same header as any request. The [Hrana guide](../../docs/hrana.md) has a full curl example and the session-limit tuning (`tx_idle_timeout`, `max_tx_lifetime`, `max_write_sessions_per_db`).
