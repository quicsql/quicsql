# JavaScript & TypeScript

quicSQL has a first-class client: **[`@quicsql/client`](https://github.com/quicsql/quicsql-js)** — one small zero-dependency ESM module built on `fetch`. It runs in browsers, Node ≥ 20.19, Bun, Deno, and edge runtimes, speaks both quicSQL protocols (the **Hrana v3 pipeline** and the **native JSON API**), and presents every quicSQL auth method a JS runtime can: bearer tokens, HTTP-basic passwords, **short-lived session tokens**, and the **ed25519 keyring** challenge/response via WebCrypto.

It is also **structurally compatible with `@libsql/client`**, so Drizzle, Prisma, and the rest of the libSQL ecosystem work against quicSQL too — [see below](#also-works-libsqlclient-drizzle-prisma). Reach for `@quicsql/client` when you want the quicSQL-only surface (session tokens, keyring auth, the native tier, live change feeds, `quicsql://` URLs) or simply the smallest dependency; reach for `@libsql/client` when you're already invested in it or an ORM pins it.

## `@quicsql/client`

```sh
npm install @quicsql/client
```

```ts
import { createClient, sql } from "@quicsql/client";

const db = createClient({
  url: "https://db.example.com:7777/app",   // trailing slash optional — no gotchas
  auth: { token: "your-token" },            // {token} · {username,password} · {ed25519} · {signer}
});

await db.execute({ sql: "INSERT INTO users(name, balance) VALUES (?, ?)", args: ["ada", 100] });

// The sql`` tag binds parameters safely — no string concatenation:
const rs = await db.execute(sql`SELECT id, name FROM users WHERE name = ${"ada"}`);
console.log(rs.rows[0].name);   // rows index by position AND by column name
```

Rows are both an array and a record: `row[0]` and `row.name` return the same cell. `lastInsertRowid` comes back as a `bigint`. Integers decode per the `intMode` option — `"number"` (default) throws past 2⁵³−1, `"bigint"` is exact, `"string"` is raw.

## Batches & interactive transactions

```ts
// One round trip, one all-or-nothing transaction:
await db.batch([
  { sql: "INSERT INTO users(name, balance) VALUES (?, ?)", args: ["bob", 100] },
  { sql: "INSERT INTO users(name, balance) VALUES (?, ?)", args: ["carol", 100] },
], "write");

// Baton-pinned interactive transaction — one server-side connection for its whole life:
const tx = await db.transaction("write");
try {
  await tx.execute({ sql: "UPDATE users SET balance = balance - ? WHERE name = ?", args: [30, "ada"] });
  await tx.execute({ sql: "UPDATE users SET balance = balance + ? WHERE name = ?", args: [30, "bob"] });
  await tx.commit();
} finally {
  await tx.close();   // rolls back if still open — safe to call unconditionally
}
```

`executeMultiple(sql)` runs a semicolon-separated script, and `migrate(stmts)` runs a batch outside a transaction — the two entry points ORMs use.

## Browsers: session tokens, no durable secret

A public web page must never ship a long-lived credential. Two server-side settings (both off by default) let a browser hold only a **short-lived, revocable** token:

```yaml
cors:
  enabled: true
  origins: ["https://app.example.com"]          # explicit origins; "*" is refused unless auth is configured
auth:
  session: { enabled: true, idle_ttl: 15m, max_ttl: 8h }   # max_ttl ⇒ renewable sliding sessions
listeners:
  - { name: h2, transport: h2, address: 0.0.0.0:7777, tls: main, auth: [password, session] }
```

`cors:` answers the browser's preflight — without it every cross-origin call fails before it starts (see [auth & authz](../auth-and-authz.md#browsers-and-cors)). A `*` origin is **rejected at startup unless authentication is configured**, so you cannot accidentally expose an open database to every website; name your origins explicitly.

Sign in once with a real credential, then let the SDK mint and hold the token:

```ts
const db = createClient({
  url: "https://db.example.com:7777/app",
  auth: { username: "analyst", password },
  // Re-persist the token whenever the server slides it forward, so a reload keeps the session:
  onSessionRenewed: ({ token }) => sessionStorage.setItem("qs", token),
});

const { token, expiresAt } = await db.mintSession();   // db now authenticates with the qs_… token
// … on logout:
await db.revokeSession();
```

When the token expires you get an `HttpError` with `status === 401` — re-mint and retry (a token deliberately cannot mint its own successor). For a **renewable** session (`max_ttl` set) the SDK adopts the server's transparent `X-Quicsql-Session` refresh automatically and fires `onSessionRenewed`; `renewSession()` forces an early extension if you need one. See the [session-token guide](../auth-and-authz.md#session-tokens-short-lived-revocable-credentials) for the full model.

> **Why an SDK and not a `fetch` wrapper?** In a browser, `fetch` must be called with `this === window` — a naïvely method-bound or object-wrapped fetch throws *"'fetch' called on an object that does not implement interface Window."* `@quicsql/client` binds fetch to `globalThis` internally so it works everywhere; that binding pitfall is the main reason to prefer it over hand-rolled requests in the browser.

**Local development:** a page on HTTPS may call `http://localhost` / `127.0.0.1` (browsers treat loopback as secure), but a LAN address needs real TLS, and current Chrome/Firefox show a local-network permission prompt when a public site calls a private address.

## Live change feed

With the server's [`changefeed:`](../change-feed.md) enabled, `subscribe()` streams committed row changes — automatic reconnect, resume-from-sequence, and `reset` handling behind one call:

```ts
const stop = db.subscribe({
  tables: ["orders"],                       // optional server-side filter
  onChange: (e) => refetchOrder(e.rowid),   // e = { seq, table, op: "insert"|"update"|"delete", rowid }
  onReset: () => refetchEverything(),        // your horizon left the buffer, or the server restarted
});
// … later:
stop();
```

Events carry `{seq, table, op, rowid}` — never column values — so the feed can never leak a column a subscriber shouldn't see; you re-read by rowid. It streams over `fetch` (not `EventSource`), so **every auth mode works** — a bare `EventSource` cannot send an `Authorization` header.

## Keyring auth & device enrollment

The ed25519 key that unlocks a quicSQL vault can also be the **network principal**, and in a browser it can live as a **non-extractable** `CryptoKey` — unstealable even by XSS. Every request is individually signed and bound to its method, path, and query; there is no bearer secret to leak.

```ts
const db = createClient({
  url: "https://db.example.com:7777/app",
  auth: { ed25519: { publicKey: "ssh-ed25519 AAAA… me@laptop", privateKey } },
  // privateKey: CryptoKey | 32-byte seed | PKCS#8 DER/PEM | JWK
});
```

Pass `auth: { signer }` — any `{ publicKey, sign(message) }` pair — to bring your own crypto (e.g. `@noble/curves` on runtimes without WebCrypto Ed25519); `sshPublicKeyLine(rawBytes)` builds the canonical `ssh-ed25519 …` line from 32 raw public-key bytes.

For **public apps with no backend and no shipped credential at all**, generate the key on-device and self-register it:

```ts
const { principal } = await db.enroll();   // calls /_auth/enroll when the server has enrollment on
```

The server assigns the principal a name and a templated grant set; enrollment is idempotent per key, so a reinstalled app keeps its identity. See [device enrollment](../auth-and-authz.md#device-enrollment-self-service-principals-for-public-apps) for the server side.

## The native tier

When one autocommit statement per request is all you need, skip the pipeline entirely — `query()` is a single `POST /<db>/query`:

```ts
const { columns, rows } = await db.query("SELECT * FROM users WHERE id = ?", [7]);
```

## Configuration & errors

| Option | Default | Notes |
| --- | --- | --- |
| `url` | — | `http(s)://host[:port]/db` or `quicsql://host[:port]/db?transport=h1\|h2c\|h2\|h3&token=…` |
| `auth` | none | `{token}` · `{username, password}` · `{ed25519: {publicKey, privateKey}}` · `{signer}` |
| `intMode` | `"number"` | `"number"` throws beyond 2⁵³−1; `"bigint"` is exact; `"string"` is raw |
| `fetch` | global | custom fetch for proxies/instrumentation/tests |
| `onSessionRenewed` | — | fires when a renewable session slides forward — re-persist the token |

Errors are typed: `HttpError` (with `.status`), `ResponseError` (per-statement, with the server's SQL `.code`), and `ClientError` (client-side, with `.code`).

## Also works: `@libsql/client`, Drizzle, Prisma

quicSQL serves the Hrana protocol the official libSQL SDK speaks, so `@libsql/client` — and Drizzle and Prisma on top of it — connect by URL alone:

```ts
import { createClient } from "@libsql/client";

const db = createClient({
  url: "http://127.0.0.1:7775/app/", // trailing slash — see below
  authToken: "your-token",           // sent as Authorization: Bearer
});
await db.execute("SELECT name, balance FROM users ORDER BY name");
```

> **The one gotcha (libSQL only): keep the trailing slash.** quicSQL namespaces
> databases by path (`/app`), and `@libsql/client` resolves its endpoint with
> WHATWG URL rules: `http://host:7775/app` becomes `http://host:7775/v2/pipeline`
> (the database vanishes), while `http://host:7775/app/` correctly becomes
> `http://host:7775/app/v2/pipeline`. `@quicsql/client` makes the trailing slash
> optional, so this gotcha does not apply to it.

Notes for `@libsql/client`: `lastInsertRowid` comes back as a `BigInt`; `libsql://` URLs mean HTTPS in this SDK (use explicit `http://` / `https://` with quicSQL and don't add query parameters — it rejects unknown ones); **Bun** `bun add @libsql/client`, **Deno** `deno add npm:@libsql/client` or import `@libsql/client/web`.

**Drizzle** wraps a `createClient` instance directly — `@quicsql/client` too, since it satisfies the same `Client` interface:

```ts
import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@quicsql/client";   // or "@libsql/client"

const db = drizzle(createClient({ url: "http://127.0.0.1:7775/app", auth: { token } }) as any);
```

`drizzle-kit` migrations emit plain SQL, which quicSQL executes like any other statement. **Prisma**'s [`@prisma/adapter-libsql`](https://www.npmjs.com/package/@prisma/adapter-libsql) wraps a `@libsql/client` instance the same way — configure it with the URL (trailing slash included) and token.

## Zero dependencies without an SDK

`@quicsql/client` is *itself* zero-dependency, so it is the recommended lightweight path. But if you want no client at all — a one-off script, an exotic runtime — the native JSON API is one `fetch`:

```js
const res = await fetch("http://127.0.0.1:7775/app/query", {
  method: "POST",
  headers: { authorization: "Bearer your-token", "content-type": "application/json" },
  body: JSON.stringify({ sql: "SELECT name, balance FROM users WHERE id = ?", args: [7] }),
});
const { columns, rows } = await res.json();
```

Full request/response shapes — `statements` batches, error envelopes — are in the [HTTP API reference](http-api.md). In a browser, mind the `fetch`/`window` binding pitfall noted above.

## Runnable versions

[`examples/clients/node-libsql`](https://github.com/quicsql/quicsql/tree/main/examples/clients/node-libsql),
[`node-drizzle`](https://github.com/quicsql/quicsql/tree/main/examples/clients/node-drizzle), and
[`node-fetch`](https://github.com/quicsql/quicsql/tree/main/examples/clients/node-fetch)
run the libSQL and raw-`fetch` flows against a real server in CI. For `@quicsql/client`, the SDK repo's own test suite spawns a real quicSQL server, and the [demo apps](https://github.com/quicsql/quicsql-demos) are full browser SPAs built on it (session tokens, keyring auth, and live change feeds end to end).
