---
name: using-quicsql
description: Use when connecting to a quicSQL server from Go — choosing between the client library and the database/sql driver, picking a transport (h1/h2/h3/unix), and running queries, batches, or transactions against a remote SQLite database. The starting point for any task using quicSQL.
---

# Using quicSQL

quicSQL serves SQLite databases over the network. You address a database **by name** (`app`, `catalog`, …); the backend and storage are the server's concern. Two ways to connect from Go: the **client library** (full surface) or the **`database/sql` driver** (standard `*sql.DB`). Install: `go get quicsql.net`.

## The database/sql driver (standard, DSN-based)

```go
import _ "quicsql.net/client/sqldriver" // registers the "quicsql" driver

db, _ := sql.Open("quicsql", "quicsql://host:7777/app?transport=h2&token=SECRET")
db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n)
```

Blank-importing the driver also teaches gosqlite's built-in `"sqlite"` driver to dispatch the same DSN, so `sql.Open("sqlite", "quicsql://…")` works too.

DSN: one scheme, transport as a parameter. Canonical port is **7775** (h1), sequencing up per transport.

```
quicsql://host:7775/db?transport=h1              # cleartext HTTP/1.1 (default)
quicsql://host:7776/db?transport=h2c             # cleartext HTTP/2
quicsql://host:7777/db?transport=h2&insecure=1   # HTTP/2 over TLS (insecure=1 = dev cert)
quicsql://host:7777/db?transport=h3&insecure=1   # HTTP/3 over QUIC (shares the h2 port)
quicsql:///db?transport=unix&socket=/run/quicsql/sql.sock
```

Credentials a URL can carry: `?token=<bearer>` **or** `?user=<u>&password=<p>`. **mTLS and the ed25519 keyring cannot live in a DSN** — build a client (below) and hand it to `sqldriver.OpenConnectorClient(cl, "app")`, then `sql.OpenDB(...)`.

## The client library (full surface)

One constructor per transport; the SQL surface is identical across them.

```go
import "quicsql.net/client"

cl := client.H2TLS("host:7777", false,             // false = verify the server cert
    client.WithRootCA(pool), client.WithBearer(token))
defer cl.Close()

res, _ := cl.Query(ctx, "app", "SELECT id, name FROM users WHERE age > ?", 40)
for _, row := range res.Rows { /* row[0], row[1] … */ }
cl.Exec(ctx, "app", "INSERT INTO users(name) VALUES(?)", "Ada")
```

Constructors: `H1(addr)`, `H2C(addr)`, `H2TLS(addr, insecure)`, `H3(addr, insecure)`, `Unix(path)` — each takes auth `Option`s (see the `auth-and-tls` skill). Cleartext transports carry credentials in the clear; use TLS off the loopback.

## Which path?

- **Standard app / ORM / existing `database/sql` code** → the driver. LiteORM rides it — see the `liteorm-over-quicsql` skill.
- **mTLS or keyring auth, or the native extras** (streamed blobs, changesets, whole-DB export, per-statement `Batch`) → the client library.

## Beyond one statement

- **Many statements, one round trip** → `cl.Batch(ctx, db, []client.Statement{{SQL: …, Args: …}, …})`. See the `transactions-and-hrana` skill.
- **Interactive transaction** (`BEGIN … COMMIT`, savepoints) → the driver's `db.BeginTx`, or `cl.OpenStream(db)`. Same skill.

Depth: the [Hrana guide](../../docs/hrana.md) and the driver's package doc.
