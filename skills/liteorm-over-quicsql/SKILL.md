---
name: liteorm-over-quicsql
description: Use when connecting an ORM (LiteORM) to a remote quicSQL database — the one-line wiring that points LiteORM's ORM, query builder, search, changeset, and large-object APIs at a quicSQL server instead of a local file. Covers the quicSQL connection only; LiteORM's own skills cover using the ORM.
---

# LiteORM over quicSQL

[LiteORM](https://liteorm.org) is a Go data layer built on gosqlite; its SQLite backend can talk to a **remote quicSQL server** instead of a local file. This skill is the wiring — only the DSN changes. For the ORM, query builder, search, migrations, and error sentinels themselves, use **LiteORM's own skills** (`using-liteorm`, `sqlite-search`, `orm-models`, …); don't reach for those APIs from here.

## Same Open, a quicsql:// DSN

`litesql.Open` opens locally or remotely by the DSN's shape — a path opens a file, a `quicsql://` URL opens a remote server. Blank-import the driver once so the scheme is registered.

```go
import (
    _ "quicsql.net/client/sqldriver"        // registers the quicsql:// scheme (once)
    litesql "liteorm.org/dialect/sqlite"
)

// Local:  db, _ := litesql.Open("app.db")
db, _ := litesql.Open("quicsql://host:7777/app?transport=h2&token=SECRET")   // remote
defer db.Close()
```

`db` is an ordinary `*liteorm.DB`. Everything LiteORM does — `orm.AutoMigrate`, `orm.NewRepo[T]`, `query.Select[T]`, `search.For[T]().Vector/FullText/Hybrid`, `changeset.Capture/Apply`, `lob` large objects, `liteorm.Transaction`, the `ErrUniqueViolation` sentinels — now runs as SQL on the server. The DSN is the same one the `using-quicsql` skill describes.

## When the DSN can't carry the credential (mTLS / keyring)

Build a `*client.Client` and wrap the driver connector:

```go
import (
    "quicsql.net/client"
    "quicsql.net/client/sqldriver"
    litesql "liteorm.org/dialect/sqlite"
)

cl := client.H2TLS("host:7777", false, client.WithRootCA(pool), client.WithClientCert(cert))
db := litesql.WrapDB(sql.OpenDB(sqldriver.OpenConnectorClient(cl, "app")))
defer db.Close()
```

## What works remotely (and what doesn't)

Reachable over the wire: ORM CRUD, the query builder, transactions (session-pinned), vector/FTS/hybrid search (run as SQL against vec0/fts5 on the server), SESSION changesets, and whole-object large objects. Not a network story: in-process-only handles (client-registered Go functions, native vec/fts handles, streaming/incremental blob cursors) — for those you'd open a local gosqlite database directly. Auth and transports are exactly as in the `auth-and-tls` and `using-quicsql` skills; the server needs the extension bundle imported (it is, in every standard deployment) for search to work.
