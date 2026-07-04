# quicSQL examples

## `demo` — runnable example + cross-protocol benchmark

A single self-contained program: it starts an in-process quicSQL server with three databases across every transport, runs real-life operations against each, demonstrates a libSQL Hrana interactive transaction, and benchmarks request throughput (requests/sec and requests/min) on each protocol.

```
just demo                      # from the server/ directory
# or:
go run ./examples/demo         # default: 2s benchmark, 16 workers
go run ./examples/demo -dur 5s -workers 64
go run ./examples/demo -v      # verbose server logs
```

No setup is required — it uses a temporary data directory (removed on exit), picks free loopback ports, and mints a self-signed dev certificate for the TLS transports.

What it exercises:

- **users** — a plain file database (WAL): create / insert / query / update.
- **orders** — a `vfs/vault` database (encrypted + compressed at rest): a seeded catalog and per-user order totals via a JOIN + aggregate.
- **cache** — a shared in-memory database: a value written over the Unix socket is read back over HTTP/1.1, proving cross-session visibility.
- an **interactive transaction** over the Hrana pipeline (`BEGIN … COMMIT` on one pinned connection).
- a **benchmark** firing concurrent `SELECT 1` requests over HTTP/1.1, cleartext h2c, HTTP/2 (TLS), HTTP/3 (QUIC), and a Unix socket, reporting per-protocol req/s, req/min, and p50/p99 latency.

## `auth` — authentication + authorization matrix

Every authentication method and every authorization level, with success **and** denial paths, printed as a matrix (and exits non-zero if any expectation fails, so it doubles as a smoke test):

```
just auth-demo                 # credential methods over cleartext HTTP/1.1
just auth-demo-tls             # …over a server-authenticated TLS h2 listener
# or:
go run ./examples/auth
go run ./examples/auth -tls
```

It configures one principal per method — no-auth (anonymous), Unix peer-credentials, bearer token, HTTP-basic password, mTLS client certificate, and the ed25519 challenge/response — and a `data` database granting each principal a different level (`read-write`, `read-only`, `admin`) plus a `public` database with a `*` (wildcard) `read-only` grant. It then shows, for example, a read-only principal's write rejected with 403, a wrong credential rejected with 401, an untrusted client cert refused at the TLS handshake, an anonymous caller denied a database with no grant, and the admin-only control plane (`/_admin`) accepting the admin and rejecting a non-admin.

By default the secret-bearing methods (bearer / password / keyring) run over cleartext HTTP/1.1 so the demo needs no certificate setup on a first run; those methods send a credential on every request, so in a real deployment you would put them behind TLS. `-tls` demonstrates exactly that: the same matrix, but the credential listener becomes a server-authenticated TLS h2 endpoint (its own `self_signed` profile with no client-CA, so it presents a cert without demanding one). mTLS keeps its own client-CA listener and peer-credentials keeps the Unix socket regardless.

## `charged-server` + `remote-tour` — a real two-process deployment, over the network

`demo` and `auth` run the server in-process. This pair runs the **deployed shape**: a standalone server process and a separate client process talking over TLS with mTLS — exactly what a real deployment does, HTTP/3 included.

- **`charged-server`** is a fully-charged, deployable server: an encrypted + compressed `vfs/vault` database, a plain file DB and a shared in-memory DB; the standard extension bundle plus a custom server-registered SQL function; every auth method; TLS h2 + HTTP/3 as the primary secure transports (with cleartext h1/h2c and a Unix socket as dev extras); the control plane; rate/concurrency limits; a slow-query log; and a vault-backed meta store. It binds a real interface and mints its TLS leaf for the SANs you pass, so it can run on a host and be reached from elsewhere. It ships a `Dockerfile` and a matching `charged.yaml` for the standalone `quicsql` binary.
- **`remote-tour`** is a pure remote client — only `quicsql.net/client` and the `database/sql` driver, no ORM — that walks every network-reachable feature and self-verifies (non-zero exit on any miss): native CRUD with parameterized args, a Hrana interactive transaction (commit + rollback), the custom SQL function and bundled extensions (REGEXP, sha256, `generate_series`, rtree, FTS5), SESSION changesets, streamed large objects, the `database/sql` driver under both names, decrypting a vault export, the auth matrix, the h2/h3 transport matrix, the control plane, and `/_metrics`.

```
just showcase                  # self-contained: builds + starts the server, runs the tour, stops the server
# or, as two processes (e.g. on two machines):
go run ./examples/charged-server -hosts your.host,203.0.113.10   # on the server host
go run ./examples/remote-tour   -addr your.host:7777             # from anywhere
```

Both sides derive the SAME fixed dev credentials (CA, mTLS client cert, keyring key, bearer token) from the shared `internal/showcase` package, so nothing is copied between them at runtime — DEV ONLY; replace it for a real deployment. (The LiteORM-over-quicSQL tour — models, typed vector/full-text/hybrid search, sessions — is a cross-module demo and lives with LiteORM.)

## Connecting from Go — the `client` package, the `quicsql` database/sql driver, and LiteORM

`gosqlite.org` itself is a driver for **local** SQLite; it is not a network client. To reach the server from Go:

- **`quicsql.net/client`** — a thin client for the native-JSON API, one constructor per transport (`H1`, `H2C`, `H2TLS`, `H3`, `Unix`) with auth/TLS options (`WithBearer`, `WithBasicAuth`, `WithClientCert`, `WithEd25519`, `WithRootCA` to verify a private/dev CA) — plus `WithMaxResponse`, which raises the 1 GiB client-side ceiling on a buffered blob/export/result body. This is what both demos use.
- **`quicsql.net/client/sqldriver`** — registers a `database/sql` driver named `quicsql`, so ordinary `database/sql` code connects to a remote database exactly like a local one:

  ```go
  import _ "quicsql.net/client/sqldriver"

  db, _ := sql.Open("quicsql", "quicsql://db.example.com:7777/users?transport=h2&token=<bearer>")
  var n int
  db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n)
  ```

  One scheme (`quicsql`), transport as a parameter: `?transport=h1|h2c|h2|h3|unix` (default `h1`). Credentials go in query params (`?token=` or `?user=&password=`); `?insecure=1` skips cert verification for the dev cert; a unix DSN is `quicsql:///<db>?transport=unix&socket=/path`. A DSN carrying a credential is refused over a channel that would expose it (`h1`/`h2c`, or `insecure=1`) — send it over verified TLS or a unix socket, or add `allow_insecure_auth=1` to opt in on a trusted dev link. **Transactions are supported** — `BeginTx` pins a libSQL Hrana session so `BEGIN … COMMIT` and SAVEPOINT nesting run on one server connection; autocommit statements use the faster stateless endpoint. Importing the driver also teaches gosqlite's built-in `sqlite` driver to open the same DSN, so `sql.Open("sqlite", "quicsql://…")` works too.

- **LiteORM** (`liteorm.org/dialect/sqlite`) — the full ORM and query builder run against a remote server: `sqlite.Open(dsn)` opens a local path or, for a `quicsql://` DSN, a remote server (or `WrapDB(*sql.DB)` to adapt a client you built yourself, e.g. for mTLS/keyring). Migrations, CRUD, the query builder, transactions, and SQLite constraint-error classification all work unchanged; over the wire, vector/full-text/hybrid search runs as SQL against the server's vec0/fts5 sidecars, changesets drive the SESSION extension server-side, and large objects transfer whole (streaming/partial blob I/O needs a local handle). The runnable LiteORM-over-quicSQL tour lives in the LiteORM repo's examples.

## `quicsql.demo.yaml` — standalone config

The equivalent config for running the real `quicsql` binary (`quicsql --config quicsql.demo.yaml`); see the comments at the top of the file for the one-time key setup and example `curl` calls. The Go `client` package (`quicsql.net/client`) is the thin Go client the demo uses; point it at any of the listeners.
