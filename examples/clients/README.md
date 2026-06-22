# quicSQL from every language

Self-contained, runnable examples of talking to one quicSQL server from many
languages — each over one of the two protocols every quicSQL database serves:

- the **native JSON API** (`POST /<db>/query`) — plain HTTP, zero dependencies,
  works from anything that can send a request;
- the **libSQL Hrana protocol** (`/<db>/v2|v3/pipeline`, `/<db>/v3/cursor`) —
  what the existing libSQL/Turso SDK ecosystem speaks, so official client
  libraries connect to quicSQL **by URL alone**.

Every example asserts its results and exits non-zero on mismatch, so the suite
doubles as a cross-SDK integration test.

## Run everything

```sh
./smoke.sh            # or from the repo root:  just clients-smoke
```

`smoke.sh` starts a scratch server (port 7785, config in `server.yaml`: one
database `app`, one principal authenticating with the bearer token
`dev-token`), then runs each example whose toolchain is available — Node and
Python natively, PHP via Docker — and prints a PASS/FAIL/SKIP summary.

## Run one example

Start the server, in this directory:

```sh
mkdir -p data && go run ../../cmd/quicsql --config server.yaml
```

Then (each example honors `QUICSQL_URL`, default `http://127.0.0.1:7775`, and
`QUICSQL_TOKEN`, default `dev-token`):

| Example | Stack | Shows |
|---|---|---|
| [`node-libsql/`](node-libsql/) | TypeScript, `@libsql/client` | CRUD, batch, interactive transaction over Hrana |
| [`node-drizzle/`](node-drizzle/) | TypeScript, Drizzle ORM | typed schema, queries, and transactions — no adapter |
| [`node-fetch/`](node-fetch/) | plain JS, zero deps | the native JSON API with `fetch` (Node/Bun/Deno) |
| [`python-libsql/`](python-libsql/) | `libsql` (official binding) | DB-API-style CRUD + transaction over Hrana |
| [`python-sqlalchemy/`](python-sqlalchemy/) | SQLAlchemy + `sqlalchemy-libsql` | ORM models and sessions over the wire |
| [`python-stdlib/`](python-stdlib/) | stdlib `urllib`, zero deps | the native JSON API |
| [`php-libsql/`](php-libsql/) | `turso-client-php` extension | CRUD + transaction over Hrana (Dockerfile included) |
| [`php-curl/`](php-curl/) | any PHP 8.x, `ext-curl` | the native JSON API |

## The gotchas these examples encode

- **`@libsql/client` URLs need a trailing slash** (`http://host:7775/app/`) —
  quicSQL namespaces databases by path, and the client's URL resolution drops a
  path with no trailing slash.
- **Prebuilt-binary coverage:** the Python `libsql` wheel and the PHP extension
  ship for linux-x86_64 and macOS, but not linux-aarch64 — on ARM hosts the
  Docker examples run under `--platform linux/amd64` emulation.
- **Native JSON batches report SQL errors in-band:** a failing statement returns
  HTTP 200 with `{"error": …, "failed_index": n}` — check for `error`, not just
  the HTTP status.
- The Go client and `database/sql` driver live in the main module — see
  [`examples/demo`](../demo/) and the [package docs](https://pkg.go.dev/quicsql.net/client).
