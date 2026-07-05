# JavaScript & TypeScript

quicSQL serves the Hrana protocol that the official libSQL SDK speaks, so
`@libsql/client` — and everything built on it, including **Drizzle** and
**Prisma** — connects to a quicSQL database by URL alone. Node, Bun, and Deno
all work; so does the zero-dependency `fetch` path.

## `@libsql/client`

```sh
npm install @libsql/client
```

```ts
import { createClient } from "@libsql/client";

const db = createClient({
  url: "http://127.0.0.1:7775/app/", // trailing slash — see below
  authToken: "your-token",           // sent as Authorization: Bearer
});

await db.execute({
  sql: "INSERT INTO users(name, balance) VALUES (?, ?)",
  args: ["ada", 100],
});

const rs = await db.execute("SELECT name, balance FROM users ORDER BY name");
for (const row of rs.rows) console.log(row.name, row.balance);
```

> **The one gotcha: keep the trailing slash.** quicSQL namespaces databases by
> path (`/app`), and `@libsql/client` resolves its endpoint with WHATWG URL
> rules: `http://host:7775/app` becomes `http://host:7775/v2/pipeline` (the
> database vanishes), while `http://host:7775/app/` correctly becomes
> `http://host:7775/app/v2/pipeline`.

Batches run in one round trip as one transaction; interactive transactions get
a baton-pinned session — one server-side connection for their whole life:

```ts
await db.batch(
  [
    { sql: "INSERT INTO users(name, balance) VALUES (?, ?)", args: ["bob", 100] },
    { sql: "INSERT INTO users(name, balance) VALUES (?, ?)", args: ["carol", 100] },
  ],
  "write",
);

const tx = await db.transaction("write");
try {
  await tx.execute({ sql: "UPDATE users SET balance = balance - ? WHERE name = ?", args: [30, "ada"] });
  await tx.execute({ sql: "UPDATE users SET balance = balance + ? WHERE name = ?", args: [30, "bob"] });
  await tx.commit();
} catch (e) {
  await tx.rollback();
  throw e;
}
```

Notes:

- `lastInsertRowid` comes back as a `BigInt`.
- `libsql://` URLs mean HTTPS in this SDK; use explicit `http://` / `https://`
  with quicSQL and don't add query parameters (the SDK rejects unknown ones).
- **Bun**: `bun add @libsql/client` — supported by the SDK. **Deno**:
  `deno add npm:@libsql/client` or import `@libsql/client/web`.

## Drizzle ORM

Drizzle's libSQL driver wraps `@libsql/client`, so a typed schema, queries, and
transactions run over the wire with no adapter:

```ts
import { createClient } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { sqliteTable, integer, text } from "drizzle-orm/sqlite-core";

const users = sqliteTable("users", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  name: text("name").notNull(),
  balance: integer("balance").notNull(),
});

const client = createClient({ url: "http://127.0.0.1:7775/app/", authToken: "your-token" });
const db = drizzle(client);

await db.insert(users).values({ name: "ada", balance: 100 });
const all = await db.select().from(users).orderBy(users.name);
```

`drizzle-kit` migrations emit plain SQL, which quicSQL executes like any other
statement.

## Prisma

Prisma's [`@prisma/adapter-libsql`](https://www.npmjs.com/package/@prisma/adapter-libsql)
wraps a `createClient` instance too — configure it with the same URL (trailing
slash included) and token, and Prisma Client talks to quicSQL.

## Zero dependencies: `fetch` + the native JSON API

For scripts, edge runtimes, or when you don't want an SDK at all:

```js
const res = await fetch("http://127.0.0.1:7775/app/query", {
  method: "POST",
  headers: {
    authorization: "Bearer your-token",
    "content-type": "application/json",
  },
  body: JSON.stringify({ sql: "SELECT name, balance FROM users WHERE id = ?", args: [7] }),
});
const { columns, rows } = await res.json();
```

Full request/response shapes — including `statements` batches and how errors
come back — are in the [HTTP API reference](http-api.md).

## Browsers

Two server-side settings make quicSQL callable from a web page; both are off by default:

```yaml
cors:
  enabled: true
  origins: ["https://app.example.com"]   # or ["*"]
auth:
  session: { enabled: true, idle_ttl: 15m, max_ttl: 8h }   # max_ttl ⇒ renewable sliding sessions
listeners:
  - { name: h2, transport: h2, address: 0.0.0.0:7777, tls: main, auth: [password, session] }
```

`cors:` answers the browser's preflight (without it, every cross-origin call fails before it starts — see [auth & authz](../auth-and-authz.md)). Session tokens keep a long-lived secret out of the page: sign in once, hold only a short-lived revocable token.

```js
// Sign in once: exchange a real credential for a short-lived token.
const res = await fetch("https://db.example.com:7777/_auth/session", {
  method: "POST",
  headers: { authorization: "Basic " + btoa("analyst:hunter2") },
});
const { token, expires_at } = await res.json(); // token starts with "qs_"; keep it in memory, not localStorage

// Then use it with @libsql/client/web, the fetch API, or anything else:
import { createClient } from "@libsql/client/web";
const db = createClient({ url: "https://db.example.com:7777/app/", authToken: token });

// Log out (revoke the token server-side):
await fetch("https://db.example.com:7777/_auth/session", {
  method: "DELETE",
  headers: { authorization: `Bearer ${token}` },
});
```

When the token expires (401), re-mint and retry — a token deliberately cannot renew itself.

With the server's [`changefeed:`](../change-feed.md) enabled, `@quicsql/client` also streams committed changes live — `db.subscribe({tables, onChange})` — with automatic reconnect and resume. Notes for local development: pages on HTTPS may call `http://localhost`/`127.0.0.1` (browsers treat loopback as secure), but a LAN address needs real TLS, and current Chrome/Firefox show a local-network permission prompt when a public site calls a private address.

## Runnable versions

[`examples/clients/node-libsql`](https://github.com/quicsql/quicsql/tree/main/examples/clients/node-libsql),
[`node-drizzle`](https://github.com/quicsql/quicsql/tree/main/examples/clients/node-drizzle), and
[`node-fetch`](https://github.com/quicsql/quicsql/tree/main/examples/clients/node-fetch)
run these exact flows against a real server in CI.
