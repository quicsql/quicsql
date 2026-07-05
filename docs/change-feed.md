# The change feed

quicSQL can stream **committed row changes** to subscribers over Server-Sent Events: `GET /<db>/changes`. It is the LISTEN/NOTIFY quicSQL's single-owner architecture makes trivial — every write flows through the one process that owns the database, so ordering is exact and nothing is missed.

## Enabling

```yaml
changefeed:
  enabled: true
  buffer: 1024            # per-database replay ring (default 1024 events)
  max_subscribers: 128    # per-database concurrent streams (default 128)
```

Only databases with a stable on-disk path (`file`, `vault`) are observable; private in-memory backends are skipped with a startup warning. Databases created through the control plane become observable immediately; detaching one closes its subscribers.

## What an event is — and isn't

Events are published **only when a transaction commits** and carry `{seq, table, op, rowid}` — never column values. That is deliberate: the feed tells you *what to re-read*, and it can never become an accidental data-exfiltration channel or leak a column a subscriber shouldn't see. `seq` is a per-database monotonic sequence. Changes to `WITHOUT ROWID` tables are not reported (SQLite's preupdate hook does not fire for them).

A full `ROLLBACK` publishes nothing. One caveat: **`ROLLBACK TO SAVEPOINT` is not currently subtracted** — rows written inside a savepoint that is later rolled back can still be reported at the enclosing commit. Because events carry no values and every subscriber re-reads by rowid, the only effect is a spurious re-read that finds the row unchanged or absent; treat every event as "this rowid *may* have changed." (Full savepoint accounting is a planned refinement.)

If a single transaction changes an enormous number of rows (a bulk `DELETE`/`UPDATE`), the per-transaction buffer is capped: past the cap the commit publishes one `reset` event instead of per-row detail, and subscribers refetch — the same `reset` they'd get after a long disconnect.

## The wire

```sh
curl -N -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:7775/app/changes?since=0&tables=orders,items"
```

```
event: ready          ← or `reset` (your horizon left the buffer / server restarted: refetch, then follow)
data: {"seq":41}

id: 42
event: change
data: {"seq":42,"table":"orders","op":"insert","rowid":7}

id: 43                 ← a mid-stream `reset` (a bulk write overflowed the buffer): refetch, then keep following
event: reset
data: {"seq":43}

: ping                ← keepalive comment every 25s
```

Read capability on the database is required. Resume with `?since=<seq>` (or the standard `Last-Event-ID` header); `?tables=a,b` filters server-side. A silently closed stream means you lagged too far (the server drops rather than blocks) or it is shutting down — reconnect with your last `id` and you resume exactly, or receive `reset` if the gap outgrew the buffer.

## From JavaScript

`@quicsql/client` wraps all of this — reconnect, resume, reset — behind one call (it streams over `fetch`, so every auth mode works, unlike a bare `EventSource` which cannot send an `Authorization` header):

```ts
const stop = db.subscribe({
  tables: ["orders"],
  onChange: (e) => refetchOrder(e.rowid),
  onReset: () => refetchEverything(),
});
```

## Sizing notes

A subscriber that cannot keep up is disconnected (it resumes by sequence) — a slow consumer can never stall the commit path. The replay ring bounds reconnect cheapness: size `buffer` to a few seconds of your peak write rate. Each subscriber holds one HTTP stream; `max_subscribers` caps the per-database total (503 beyond it).
