# Getting started

quicSQL is one static binary. This page takes you from nothing to a running
server your language can query, in about a minute.

## Install

<!-- tabs:start -->

#### Docker

```sh
docker run -p 7775:7775 -v quicsql-data:/data \
  -v ./quicsql.yaml:/etc/quicsql/quicsql.yaml \
  ghcr.io/quicsql/quicsql:latest
```

#### Binary

Download the archive for your platform from the
[releases page](https://github.com/quicsql/quicsql/releases) — one static
executable, no dependencies to install. Linux, macOS, and Windows, amd64 and
arm64.

#### go install

```sh
go install quicsql.net/cmd/quicsql@latest
```

Pure Go, no CGo — it also cross-compiles with plain `GOOS=… GOARCH=… go build`.

<!-- tabs:end -->

## 1. Run the daemon

One YAML file describes the whole server: listeners (one per transport),
databases (one per line), and — when you want them — secrets, TLS, principals,
and grants.

```yaml
# quicsql.yaml
server:
  data_dir: ./data
secrets:
  - {name: keys, type: file, dir: ./data/keys}     # "keys:<name>" reads ./data/keys/<name>
tls:
  dev: {mode: self_signed, hosts: [localhost, 127.0.0.1]}   # use mode: files in production
listeners:
  - {name: h1,   transport: h1,   address: 127.0.0.1:7775}
  - {name: h2,   transport: h2,   address: 127.0.0.1:7777, tls: dev}
  - {name: h3,   transport: h3,   address: 127.0.0.1:7777, tls: dev, advertise: true}   # HTTP/3 over QUIC — shares the h2 port (UDP vs TCP)
  - {name: unix, transport: unix, address: ./data/quicsql.sock, socket_mode: "0600"}
databases:
  - {name: users,  backend: file, path: users.db, mode: rwc, pragmas_preset: recommended}
  - name: orders                                   # encrypted + compressed at rest
    backend: vault
    path: orders.vault
    vault: {compression: default, cipher: adiantum, key: keys:orders}
```

```sh
quicsql --config quicsql.yaml
```

> [!WARNING]
> With no principals or grants configured, the server runs in **open mode** —
> every caller is read-write. That's the right default for a loopback dev
> server; bind to `127.0.0.1` and nothing else. To lock it down, add a
> principal, a grant, and a listener `auth:` list — see
> [Auth & authorization](auth-and-authz.md).

Every listener serves the same endpoints: `POST /<db>/query` (native JSON),
`/<db>/v2|v3/pipeline` and `/<db>/v3/cursor` (Hrana), `/<db>/export`,
`/<db>/changeset/*`, `/<db>/blob/*`, plus the server-scoped `/_health`,
`/_metrics`, `/_admin/*`, and `/_auth/challenge`. The canonical port is
**7775** (h1); the sequence continues h2c 7776 and h2 7777 — and **h3 shares
7777** (QUIC/UDP alongside h2's TLS/TCP, the way HTTPS shares :443; the h3
listener's `advertise: true` emits `Alt-Svc` so clients auto-upgrade).

## 2. Talk to it — from your language

<!-- tabs:start -->

#### curl

The native JSON endpoint takes `{sql, args}` — or a `statements` batch, which
runs as one explicit transaction, all-or-nothing:

```sh
curl -s http://127.0.0.1:7775/users/query \
  -d '{"sql":"CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT)"}'

curl -s http://127.0.0.1:7775/users/query \
  -d '{"statements":[
        {"sql":"INSERT INTO users(name) VALUES (?)","args":["ada"]},
        {"sql":"SELECT * FROM users"}
      ]}'
```

Integers stay exact on the wire; blobs are boxed as `{"base64": …}`. Full
shapes in the [HTTP API reference](clients/http-api.md).

#### TypeScript

The official libSQL SDK connects by URL alone — keep the **trailing slash**
(quicSQL namespaces databases by path):

```ts
import { createClient } from "@libsql/client";

const db = createClient({ url: "http://127.0.0.1:7775/users/" });

await db.execute({ sql: "INSERT INTO users(name) VALUES (?)", args: ["ada"] });
const rs = await db.execute("SELECT * FROM users");
```

Transactions, batches, Drizzle, and Prisma: the
[JavaScript guide](clients/javascript.md).

#### Python

The official `libsql` binding (`pip install libsql`) speaks quicSQL's wire
protocol out of the box:

```python
import libsql

conn = libsql.connect("http://127.0.0.1:7775/users")
conn.execute("INSERT INTO users(name) VALUES (?)", ("ada",))
conn.commit()
print(conn.execute("SELECT * FROM users").fetchall())
```

SQLAlchemy and the zero-dependency path: the [Python guide](clients/python.md).

#### PHP

The libSQL extension (PHP 8.1–8.5) connects by URL — and plain curl works on
any PHP:

```php
$db = new LibSQL("libsql:dbname=http://127.0.0.1:7775/users");
$db->execute('INSERT INTO users(name) VALUES (?)', ['ada']);
$rows = $db->query('SELECT * FROM users')->fetchArray(LibSQL::LIBSQL_ASSOC);
```

Install steps and the curl path: the [PHP guide](clients/php.md).

#### Go

The [`client`](https://pkg.go.dev/quicsql.net/client) package speaks every
transport; the `database/sql` driver opens a remote database like a local one:

```go
import (
    "database/sql"

    _ "quicsql.net/client/sqldriver"
)

//   sql.Open("sqlite", "file:app.db")   → a local SQLite file
db, _ := sql.Open("sqlite", "quicsql://127.0.0.1:7775/users?transport=h1")

var n int
db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n)
```

The full surface — every transport, every auth method, LiteORM:
the [Go guide](clients/go.md).

<!-- tabs:end -->

These are dev-mode snippets (open mode, no token). Once you add principals,
every SDK passes its token via `authToken` / `auth_token`, which quicSQL
receives as standard bearer auth — see [Clients & languages](clients/README.md).

## 3. Embed it (Go)

`serverd.Run` assembles the whole pipeline in-process — for tests, custom SQL
functions, or shipping a bundled server inside your own binary:

```go
import "quicsql.net/serverd"

inst, _ := serverd.Run(cfg, log)   // cfg is a *config.Config; returns an *Instance
defer inst.Shutdown(ctx)
```

## Where next

- **[Clients & languages](clients/README.md)** — your language's path in, with
  CI-tested examples: JavaScript/TypeScript, Python, PHP, Go, and more.
- **[Databases & backends](databases.md)** — every open mode gosqlite has,
  over the wire: files, in-memory, mvcc snapshots, and vault containers in every
  shape, plus pragmas, pool tuning, and secrets.
- **[Auth & authorization](auth-and-authz.md)** — six authentication methods,
  the `none < read-only < read-write < admin` capability model, and why
  read-only cannot be talked around.
- **[The Hrana pipeline](hrana.md)** — transactions, batches, batons, and
  production limits.
- **[Runnable examples](https://github.com/quicsql/quicsql/tree/main/examples/clients)** —
  every language above, asserting its results against a real server in CI.
