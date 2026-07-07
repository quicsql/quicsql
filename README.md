<div align="center">

<img src="https://github.com/quicsql/.github/raw/main/profile/quicsql.svg" alt="quicSQL" width="128" />

# quicSQL

[**Docs**](docs/) &nbsp;·&nbsp; [**Get started**](#quick-start) &nbsp;·&nbsp; [**API reference**](https://pkg.go.dev/quicsql.net) &nbsp;·&nbsp; [**Config**](docs/databases.md)

[![Go Reference](https://pkg.go.dev/badge/quicsql.net.svg)](https://pkg.go.dev/quicsql.net)

</div>

**Network SQLite for every language.** quicSQL takes a local SQLite database — a plain file, an in-memory database, or an encrypted-and-compressed [`vfs/vault`](https://pkg.go.dev/gosqlite.org/vfs/vault) container — and turns it into a networked, authenticated, multi-tenant service. It owns each database as **one long-lived open handle** and fans many network clients into it (the single-owner discipline that makes a vault file safely shareable), speaks **two protocols over one handler** — a dead-simple native JSON API and the libSQL **Hrana** pipeline — across the **whole transport matrix** (HTTP/1.1, cleartext h2c, HTTP/2 over TLS, **HTTP/3 over QUIC**, and Unix sockets), with authentication, per-database authorization, a control plane, and observability built in. Because it speaks the libSQL wire protocol, the **official libSQL SDKs — TypeScript, Python, PHP, Ruby, Rust, Swift, Elixir — connect by URL alone** ([`docs/clients/`](docs/clients/)); anything else can use the plain JSON API. It's built on [gosqlite](https://gosqlite.org) and is **pure Go — no CGo, one static binary**.

```go
// The SAME "sqlite" driver name opens a local file or a remote database —
// only the DSN scheme changes. Importing the driver registers "sqlite" too.
import _ "quicsql.net/client/sqldriver"

//   sql.Open("sqlite", "file:app.db")   → a local SQLite file
db, _ := sql.Open("sqlite", "quicsql://127.0.0.1:7775/users?transport=h1") // → SQLite via a quicSQL server
db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n)
```

Or reach it with nothing but `curl` — the native JSON endpoint is that thin:

```sh
curl -s http://127.0.0.1:7775/users/query -d '{"sql":"SELECT * FROM users WHERE id = ?","args":[7]}'
```

Existing **libSQL / Turso clients work as-is**: quicSQL serves the Hrana `v2`/`v3` pipeline and cursor (`/<db>/v3/pipeline`, `/<db>/v3/cursor`), including baton-pinned interactive transactions — the official SDKs for TypeScript, Python, PHP, Ruby, Rust, and more point at a quicSQL host by URL alone, verified in CI by [`examples/clients/`](examples/clients/).

## Why quicSQL

- **🔐 It networks the databases nothing else can — including encrypted vaults.** gosqlite gives you a live, file-backed **encrypted + compressed** SQLite container ([`vfs/vault`](https://pkg.go.dev/gosqlite.org/vfs/vault)): multi-recipient keyslots, tamper-evident storage, crash-safe key rotation. But such a container is only safe under a **single owner** — you can't just hand the file to N machines. quicSQL *is* that owner: it opens the vault once and multiplexes every client through it, so an encrypted database becomes a shared network service without ever weakening what's written to disk. No other SQLite server does this in pure Go.

- **📦 Batteries included — auth, authz, control plane, observability.** Not "SQLite behind an HTTP handler you have to secure yourself." quicSQL ships a real access model: seven authentication methods (no-auth, Unix peer credentials, bearer token, HTTP-basic password, **mTLS**, an **ed25519 challenge/response** that reuses the same key that unlocks a vault, and **short-lived session tokens** minted from any of them), a principal → capability authorization layer with per-database grants and **read-only enforced in the engine** (not by parsing SQL), a `/_admin` control plane (create / detach / list databases, plus vault maintenance — compact, reclaim, trim, snapshot), a meta store with an audit log, a Prometheus-text `/_metrics` endpoint, a slow-query log, per-principal rate limits, per-database concurrency caps, and statement / transaction timeouts that interrupt a runaway query.

- **🌐 Every transport, one handler — up to HTTP/3.** The identical `http.Handler` serves HTTP/1.1, cleartext h2c, HTTP/2 over TLS, **HTTP/3 over QUIC**, and Unix domain sockets. Put credential methods behind TLS, keep an admin socket local with peer-credential auth, and let mobile/edge clients ride QUIC — same server, same semantics.

- **🧩 Pure Go, CGo-free, one binary.** Because it's built on gosqlite (SQLite transpiled to Go), quicSQL cross-compiles with plain `GOOS=… go build`, ships as a static distroless/alpine binary with no `apk add`, and passes `go test -race` cleanly. No C toolchain in your build or your container.

- **🔌 Two protocols, both first-class.** The **native JSON** API (`POST /<db>/query`) is trivial to call from any language, `curl`, or a shell script — one request, `{sql, args}` or a `statements` batch. The **Hrana** pipeline gives you baton-pinned interactive transactions, batches with step conditions, and compatibility with the existing libSQL client ecosystem. Pick per use case; the server speaks both at once.

## Documentation

- **[`docs/`](docs/)** — the human guides: [getting started](docs/getting-started.md), [clients & languages](docs/clients/) (the official [`@quicsql/client`](docs/clients/javascript.md) JS/TS SDK, plus Python, PHP, Go, and the [HTTP API reference](docs/clients/http-api.md)), [databases & open modes](docs/databases.md), [auth & authorization](docs/auth-and-authz.md), [the Hrana pipeline](docs/hrana.md), [the change feed](docs/change-feed.md), [administration & backup/restore](docs/administration.md), and [mTLS in production](docs/mtls-production.md).
- **[pkg.go.dev/quicsql.net](https://pkg.go.dev/quicsql.net)** — the Go API reference (the client, the driver, and the embeddable `serverd`).
- **[`AGENTS.md`](AGENTS.md)** — architecture, invariants, and conventions for anyone (human or AI agent) working *in* the codebase; `doc.go` on every package for pkg.go.dev.
- **[`examples/`](examples/)** — runnable, self-contained programs (see [Examples](#examples)).

## What you get

- **[Every open mode gosqlite has, over the wire](docs/databases.md)** — plain files (with a `recommended` WAL pragma preset), read-only, private and shared in-memory, `vfs/mvcc` (snapshot isolation) and `vfs/memdb`, and `vfs/vault` in every shape: plain, compressed, encrypted, multi-recipient, and authenticated-writer. The server owns pragmas and pool tuning; clients can't reconfigure the connection.
- **[Authentication, seven ways](docs/auth-and-authz.md)** — none (anonymous), Unix peer credentials (uid → principal), bearer token (hashed, constant-time compared), HTTP-basic password (bcrypt), mTLS client certificate (by subject CN or SPKI), a stateless ed25519 challenge/response whose signature is **bound to the request** so a captured signature can't be replayed onto another, and **short-lived session tokens** (`POST /_auth/session` exchanges any credential for a TTL-bounded, revocable token — the right shape for browsers). A present-but-invalid credential is a `401`, never a silent downgrade to anonymous.
- **[Authorization in depth](docs/auth-and-authz.md)** — a `none < read-only < read-write < admin` capability model with per-database and wildcard (`*`) grants. Read-only isn't a suggestion: a read-only principal runs on a borrowed connection put in `PRAGMA query_only` **plus** a write-denying authorizer, so DML, DDL, header writes, and `VACUUM` are all refused at the engine.
- **[The Hrana pipeline](docs/hrana.md)** — `execute` / `batch` / interactive transactions over baton-pinned sessions (one server-side connection per baton), `store_sql`, and batch step conditions — the libSQL wire protocol, served natively.
- **A native JSON API** — `POST /<db>/query` with `{sql, args}` or a `statements` batch (one explicit transaction, all-or-nothing), integers exact on the wire, blobs boxed as `{"base64": …}`, results bounded by row/byte caps so a huge `SELECT` can't OOM the server.
- **A control plane at `/_admin`** — runtime create / detach / list databases (persisted to a meta store and reconciled on restart), vault maintenance (offline compact, online reclaim (`compact_online`), trim, encrypted snapshot), introspection (info / databases / sessions / kill), and an audit log — every route gated by a named server-admin (open mode never applies to the control plane).
- **Changesets & blobs over the wire** — apply / invert / concat SQLite session changesets, and stream large objects into a `blobstore` (`create` / `write` / `read` / `size` / `delete`) with bounded memory.
- **A Go client + `database/sql` driver** — [`client`](https://pkg.go.dev/quicsql.net/client) speaks every transport (`H1` / `H2C` / `H2TLS` / `H3` / `Unix`) with `Query` / `Exec` / `Batch` / `OpenStream` / changeset / blob / export; [`client/sqldriver`](https://pkg.go.dev/quicsql.net/client/sqldriver) registers a `database/sql` driver so ordinary Go code reaches a remote database by DSN alone. It dispatches under gosqlite's `"sqlite"` name (change `file:app.db` to `quicsql://host/app` and your existing code points at a server — no driver swap), and under an explicit `"quicsql"` name too.
- **Safety rails** — `/_metrics` (Prometheus text), a params-redacted slow-query log, per-principal rate limiting, per-database concurrency admission caps, and statement / transaction timeouts that interrupt a runaway or disconnected query.
- **Browser-ready** — an opt-in `cors:` block (preflights answered before auth, `Authorization` and the keyring headers pre-approved) so web apps call the JSON or Hrana endpoints directly; pair it with session tokens so a page never holds a long-lived secret.
- **Self-service device enrollment** — public apps that can't ship a credential generate an ed25519 key on-device and register its public half at `POST /_auth/enroll` (possession-proved, quota'd, optionally gated by enrollment tokens); the server assigns the principal name and a templated grant set, optionally provisions a private database per key, and `/_admin/principals` manages the fleet. (Full user accounts and sign-in — one person behind many devices and factors — are a separate product built on this engine.)
- **[A committed-change feed](docs/change-feed.md)** — `GET /<db>/changes` streams `{seq, table, op, rowid}` over Server-Sent Events, published only at COMMIT (rollbacks are never seen), with resume-by-sequence and per-database subscriber caps. The realtime primitive no other SQLite server ships.

## Declarative models over the network: LiteORM

Want an ORM on top? [**LiteORM**](https://liteorm.org) — the declarative, CGo-free SQLite data layer built on gosqlite — runs over quicSQL **unchanged**. Its `sqlite.Open` selects local or remote by DSN shape, so the same models, migrations, and queries that hit a local file hit a quicSQL server the moment you point them at a `quicsql://` URL:

```go
import (
	"liteorm.org/dialect/sqlite"
	"liteorm.org/orm"
	_ "quicsql.net/client/sqldriver" // registers the quicsql:// scheme
)

// A local file in dev, a quicSQL server in prod — only the DSN changes:
db, _ := sqlite.Open("quicsql://db.example.com:7777/app?transport=h2&token=…")
defer db.Close()
orm.AutoMigrate[User](ctx, db) // runs the DDL on the server
```

- **Same models, local or remote.** Declare once; the full ORM and query builder — statements, SAVEPOINT-nested transactions, schema introspection, additive `AutoMigrate` — execute as SQL on the server, and SQLite constraint violations come back as typed liteorm errors.
- **Native search, executed server-side.** LiteORM's typed **vector, full-text, and hybrid (RRF) search** (`search.For[T](db).Vector` / `.FullText` / `.Hybrid`) run as SQL against the server's `vec0` / `fts5` sidecars — declarative model tags, ranked results, no hand-written KNN. (The server needs `vec0` registered; `fts5` is built in.)
- **Changesets & large objects over the wire.** SQLite session changesets (capture / apply / invert / concat) drive the SESSION extension server-side; large objects transfer whole.
- **mTLS / keyring auth.** For credentials a DSN can't carry, build a `*client.Client`, hand it to `sqldriver.OpenConnectorClient`, and `sqlite.WrapDB` the resulting `*sql.DB`.

LiteORM is a separate module (`liteorm.org`), so quicSQL's own dependencies stay lean.

## How it compares

The "SQLite over a network" landscape is small, and each entry makes a different bet. Where quicSQL sits:

| Capability | quicSQL | libSQL `sqld` | rqlite | ws4sql |
|---|---|---|---|---|
| Works with the existing **libSQL SDKs** (TS, Python, PHP, Ruby, Rust, …) | ✓ | ✓ | ✗ | ✗ |
| Pure Go, CGo-free, static binary | ✓ | ✗ (Rust) | ✗ (CGo driver) | ✗ (CGo driver) |
| libSQL **Hrana** protocol | ✓ | ✓ | ✗ | ✗ |
| Simple JSON-over-HTTP API | ✓ | ✓ | ✓ | ✓ |
| **HTTP/3 (QUIC)** transport | ✓ | ✗ | ✗ | ✗ |
| Unix socket + **peer-credential** auth | ✓ | ✗ | ✗ | ✗ |
| Built-in auth (mTLS, bearer, ed25519, password) | ✓ | partial (token) | ✓ (basic/mTLS) | partial |
| Per-database capability authz, read-only enforced in-engine | ✓ | ✗ | ✗ | partial |
| **Encrypted + compressed** database, served **live** in place | ✓ (`vfs/vault`) | encryption only | ✗ | ✗ |
| Multi-recipient / tamper-evident storage | ✓ | ✗ | ✗ | ✗ |
| Runtime control plane (create / detach / maintenance) + audit | ✓ | partial | ✗ | ✗ |
| Declarative ORM with native vector / FTS / hybrid search over the wire (via LiteORM) | ✓ | ✗ | ✗ | ✗ |
| Distributed replication / Raft consensus | ✗ | ✓ (Turso) | ✓ | ✗ |

**Better here:** it's the only pure-Go option that speaks Hrana *and* a plain JSON API, serves the full transport matrix up to HTTP/3, bakes in a real auth + per-database authorization model with read-only enforced at the engine, and — uniquely — serves an **encrypted, compressed, multi-recipient vault container live and in place**, safe because the server enforces single-ownership. And because it's built on gosqlite, [LiteORM](https://liteorm.org) runs over it: a declarative ORM with **native vector / full-text / hybrid search over the wire**, which no other SQLite server offers. One static binary carries all of it.

**The trade-off is deliberate:** quicSQL is a **single-owner multiplexer, not a replicated cluster.** If you need Raft consensus and multi-node failover, rqlite and Turso are built for that; quicSQL is built to make *one* powerful SQLite database — especially an encrypted vault — safely and richly network-accessible. (Nothing stops you from running it behind your own replication or failover; it just doesn't ship consensus in the box.)

## Quick start

**1. Run the daemon** with a YAML config — one listener per transport, a few databases, auth optional:

```yaml
# quicsql.yaml
server:
  data_dir: ./data
secrets:
  - {name: keys, type: file, dir: ./data/keys}     # a "keys:<name>" reference reads ./data/keys/<name>
tls:
  dev: {mode: self_signed, hosts: [localhost, 127.0.0.1]}   # use mode: files in production
listeners:
  - {name: h1,   transport: h1,   address: 127.0.0.1:7775}
  - {name: h2,   transport: h2,   address: 127.0.0.1:7777, tls: dev}
  - {name: h3,   transport: h3,   address: 127.0.0.1:7777, tls: dev}   # HTTP/3 over QUIC — shares the h2 port (UDP vs TCP)
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

With no principals or grants, the server is in **open mode** (every caller is read-write — bind to loopback). Add a principal, a grant, and a listener `auth:` list to lock it down; see **[auth & authz](docs/auth-and-authz.md)**.

**2. Talk to it** — from Go, over any transport:

```go
import "quicsql.net/client"

c := client.H1("127.0.0.1:7775")                       // or H2TLS / H3 / Unix, with client.WithBearer(…) etc.
defer c.Close()

res, _ := c.Query(ctx, "users", "SELECT name FROM users WHERE id = ?", 7)

// An interactive transaction over the Hrana pipeline (one pinned connection,
// driven by SQL — BEGIN/COMMIT are statements; args are passed as an []any):
tx := c.OpenStream("bank")
defer tx.Close(ctx)
tx.Exec(ctx, "BEGIN", nil)
tx.Exec(ctx, "UPDATE accounts SET balance = balance - ? WHERE id = ?", []any{100, 1})
tx.Exec(ctx, "UPDATE accounts SET balance = balance + ? WHERE id = ?", []any{100, 2})
tx.Exec(ctx, "COMMIT", nil)
```

...or through `database/sql` (`import _ "quicsql.net/client/sqldriver"`), or with `curl`, or with any libSQL SDK pointed at the Hrana endpoint.

**3. Embed it** — `serverd.Run` assembles the whole pipeline in-process (custom SQL functions, tests, a bundled server):

```go
import "quicsql.net/serverd"

inst, _ := serverd.Run(cfg, log)   // cfg is a *config.Config; returns an *Instance
defer inst.Shutdown(ctx)
```

## Transports & protocols

One `http.Handler` is served on every wire; pick per listener.

| Transport | Config `transport:` | Typical use |
|---|---|---|
| HTTP/1.1 | `h1` | the simplest client, `curl`, loopback |
| Cleartext HTTP/2 | `h2c` | in-cluster, multiplexed, no TLS |
| HTTP/2 over TLS | `h2` | the deployed shape for credentialed clients |
| HTTP/3 over QUIC | `h3` | mobile / edge / lossy networks |
| Unix domain socket | `unix` | local admin, peer-credential auth |

Endpoints on each: `POST /<db>/query` (native JSON), `/<db>/v3/pipeline` (Hrana), `/<db>/export`, `/<db>/changeset/*`, `/<db>/blob/*`, plus server-scoped `/_health`, `/_metrics`, `/_admin/*`, and `/_auth/*` (challenge, session, enroll). The **canonical port is 7775** (h1); the sequence continues h2c 7776, h2 7777, and **h3 shares 7777** (QUIC/UDP alongside h2's TLS/TCP, the way HTTPS shares :443 — set the h3 listener's `advertise: true` to emit `Alt-Svc` so clients auto-upgrade).

## Packages

| Import path | What it gives you |
|---|---|
| `quicsql.net/serverd` | `serverd.Run(cfg, log) → *Instance` — assemble the whole server in-process; `Shutdown(ctx)` |
| `quicsql.net/config` | the YAML config surface — `Load(path)` + `Validate()` (one source of truth for the vocabulary) |
| `quicsql.net/client` | the Go client: `H1` / `H2C` / `H2TLS` / `H3` / `Unix` + `Query` / `Exec` / `Batch` / `OpenStream` / changeset / blob / export |
| `quicsql.net/client/sqldriver` | a `database/sql` driver for the `quicsql://` DSN, under both the `"sqlite"` and `"quicsql"` names — a remote database opened like a local one |
| `quicsql.net/backend` | maps a configured database to a concrete open (file / memory / vault / mvcc / memdb) |
| `quicsql.net/auth` · `quicsql.net/authz` | authenticate a request → principal; principal → per-database capability |
| `quicsql.net/registry` | the single-owner handle registry — one open `*sqlite.DB` per database, ref-counted |
| `quicsql.net/httpapi` | the transport-neutral HTTP surface (native + Hrana + export/changeset/blob) |
| `quicsql.net/admin` | the `/_admin` control plane (create / detach / list, vault maintenance, introspection) |
| `cmd/quicsql` | the standalone daemon (`quicsql --config quicsql.yaml`) |

## Examples

Runnable, smoke-tested programs under [`examples/`](examples/):

- **[`demo`](examples/demo/)** — one program that starts an in-process server with three databases (a WAL file, an encrypted+compressed vault, a shared in-memory database) across **every transport**, runs real operations against each, drives a Hrana interactive transaction, and **benchmarks throughput per protocol** (req/s, p50/p99). Zero setup: `go run ./examples/demo`.
- **[`auth`](examples/auth/)** — the full authentication + authorization matrix, every method and every level, with success **and** denial paths, exiting non-zero if any expectation fails (so it doubles as a smoke test). `go run ./examples/auth` (cleartext) or `-tls`.

`just demo`, `just auth-demo`, `just auth-demo-tls`, and `just showcase` run them; see the [examples README](examples/README.md).

## Development

`just` recipes drive everything: `just` (build + test + lint), `just test`, `just test-race`, `just lint`, `just demo`, `just ci`. The underlying commands are vanilla `go build ./...` / `go test ./...`. Architecture, the fragile invariants (single-owner handles, baton binding, read-only-in-depth, open-mode rules), and conventions live in **[`AGENTS.md`](AGENTS.md)**.

quicSQL is co-developed with **[gosqlite](https://gosqlite.org)**: during development its `go.mod` resolves `gosqlite.org` (and `vfs/vault`, `vfs/crypto`, `crypto/keyring`, `blobstore`) from the sibling checkout via `replace` directives; a real release pins published versions.

## Supported Go

The two most recent Go releases (the pin lives in `go.mod`). `gopls modernize` is enforced in CI, so modern idioms are expected.

## Acknowledgements

- **[gosqlite](https://gosqlite.org)** — the CGo-free SQLite engine quicSQL is built on; the `vfs/vault` container, `crypto/keyring`, and `blobstore` that make encrypted, multi-recipient, networked databases possible.
- **[libSQL / Turso](https://turso.tech)** — the Hrana wire protocol quicSQL implements, so the existing libSQL client ecosystem works unchanged.
