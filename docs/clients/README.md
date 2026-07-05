# Using quicSQL from your language

quicSQL is a network SQLite server for **every language**, not just Go. Each
database it serves speaks two protocols at once, and between them nearly any
stack has a first-class path in:

- **The native JSON API** — `POST /<db>/query` with `{"sql", "args"}`, or a
  `{"statements": [...]}` batch that runs as one all-or-nothing transaction.
  Zero dependencies: if your language can send an HTTP request, it can query
  quicSQL. The full reference is in [the HTTP API guide](http-api.md).
- **The libSQL Hrana protocol** — `POST /<db>/v2/pipeline`, `/<db>/v3/pipeline`,
  and `/<db>/v3/cursor`. This is the wire protocol of the libSQL / Turso client
  ecosystem, served natively — so the **official libSQL SDKs connect to quicSQL
  by URL alone**, including interactive transactions.

JavaScript/TypeScript additionally has an official quicSQL SDK,
[`@quicsql/client`](javascript.md) — zero-dependency, browser-first, and the
only client that exposes quicSQL's session tokens, keyring auth, and live change
feeds.

## Which SDK, per language

| Language | Recommended path | Guide |
|---|---|---|
| JavaScript / TypeScript | `@quicsql/client` (also `@libsql/client`, Drizzle, Prisma) | [JavaScript & TypeScript](javascript.md) |
| Python | `libsql` binding (also SQLAlchemy) | [Python](python.md) |
| PHP 8 | `turso-client-php` extension, or plain curl | [PHP](php.md) |
| Go | the quicSQL client & `database/sql` driver (also LiteORM) | [Go](go.md) |
| Rust, Ruby, Swift, Elixir | official/community libSQL bindings | [More languages](more-languages.md) |
| Java, C#, anything else | the native JSON API | [More languages](more-languages.md), [HTTP API](http-api.md) |

## The three facts every client needs

**1. The database is in the URL.** quicSQL hosts many databases per server and
resolves the target three ways, in this order:

- **Path prefix** — `http://host:7775/app/query`, `…/app/v3/pipeline`. This is
  the default; for libSQL SDKs the base URL is simply `http://host:7775/app`.
- **Host routing** — with `host_suffix` configured, `app.db.example.com`
  addresses the database `app`. Useful for the few SDKs that mangle URL paths.
- **Server default** — a configured `default_db` answers requests that name no
  database at all.

**2. Auth tokens map 1:1.** Every libSQL SDK has an `authToken` / `auth_token`
option; it is sent as `Authorization: Bearer <token>` — exactly quicSQL's
[bearer method](../auth-and-authz.md). One quicSQL principal serves every
language. (mTLS and the other methods work wherever the language's HTTP stack
can present them; the Go client supports all six.)

**3. Plain `http://` works.** SDK URLs accept `http://host:7775/db` directly —
use it on loopback and inside trusted networks, and TLS (`https://`) for
anything real. SDKs built on system TLS stacks validate certificates normally,
so production setups should use real certificates per the
[mTLS guide](../mtls-production.md); self-signed dev certs generally require
extra trust configuration in each SDK.

## Gotchas worth knowing up front

- **`@libsql/client` (JS) needs a trailing slash** on the URL —
  `http://host:7775/app/` — or its URL resolution silently drops the database
  path. `@quicsql/client` makes the trailing slash optional. Details in the
  [JavaScript guide](javascript.md).
- **Deprecated Python packages don't work**: `libsql-client` and
  `libsql-experimental` predate Hrana or are archived; use the current
  [`libsql`](python.md) package.
- **Prebuilt-binary coverage varies** for the Rust-based SDKs (Python wheel,
  PHP extension): linux-x86_64 and macOS are covered, linux-aarch64 is not —
  on ARM, run those under amd64 emulation or use the JSON API.
- **Batch error reporting differs by protocol**: the native JSON API returns
  HTTP 200 with an `{"error", "failed_index"}` envelope for a failed batch
  statement; Hrana reports per-step results. Check accordingly.

## Runnable examples

Every guide's code is lifted from
[`examples/clients/`](https://github.com/quicsql/quicsql/tree/main/examples/clients)
— self-contained programs that assert their results and run in CI against a
real server, so the snippets you read here are tested, not aspirational.
