---
name: javascript-and-browser-clients
description: Use when building a JavaScript/TypeScript or browser app on quicSQL — the @quicsql/client SDK (queries, batches, transactions), authenticating a public browser app without shipping a secret (session tokens, ed25519 keyring, device enrollment), subscribing to the live change feed, and the CORS server config browsers need.
---

# JavaScript, TypeScript & browser clients

quicSQL's official client is **[`@quicsql/client`](https://github.com/quicsql/quicsql-js)** — one zero-dependency ESM module on `fetch`, for browsers, Node ≥ 20.19, Bun, Deno, and edge runtimes. It speaks the Hrana v3 pipeline and the native JSON API, and presents every auth method a JS runtime can. It is also `@libsql/client`-compatible, so Drizzle/Prisma work too. Install: `npm install @quicsql/client`.

```ts
import { createClient, sql } from "@quicsql/client";

const db = createClient({
  url: "https://db.example.com:7777/app",  // trailing slash optional
  auth: { token: "your-token" },           // {token} · {username,password} · {ed25519} · {signer}
});

await db.execute({ sql: "INSERT INTO users(name) VALUES (?)", args: ["ada"] });
const rs = await db.execute(sql`SELECT id, name FROM users WHERE name = ${"ada"}`);
rs.rows[0].name;   // rows index by position AND column name; lastInsertRowid is a bigint
```

`batch(stmts, "write")` runs N statements as one transaction in a round trip; `transaction("write")` opens a baton-pinned interactive transaction (`tx.execute` … `tx.commit()`, `tx.close()` in `finally` rolls back if still open). `query(sql, args)` is the single-shot native tier. Depth: the [JS guide](../../docs/clients/javascript.md), and `transactions-and-hrana` for the transaction model.

## Browser auth: never ship a durable secret

A public page must not embed a long-lived credential. Two moves:

1. **Server-side:** enable `cors:` (preflight) and `auth.session` (see the `auth-and-tls` skill). A `cors.origins` of `"*"` is **refused at startup unless auth is configured** — name the page origins explicitly.
2. **Client-side:** sign in once, then hold only a short-lived, revocable token:

```ts
const db = createClient({
  url, auth: { username: "analyst", password },
  onSessionRenewed: ({ token }) => sessionStorage.setItem("qs", token),  // persist slides across reloads
});
await db.mintSession();   // db now uses the st_… token; expires_at (+ max_expires_at if renewable) returned
// … logout:
await db.revokeSession();
```

Expiry surfaces as `HttpError` with `status === 401` — re-mint and retry (a token can't mint its own successor). For a renewable session (`max_ttl` set) the SDK adopts the server's transparent `X-Session-Token` refresh and fires `onSessionRenewed`; `renewSession()` forces an early extension.

## Keyring auth & enrollment (no backend at all)

For a public app with **zero shipped credentials**: generate an ed25519 key on-device (in a browser, a **non-extractable** WebCrypto `CryptoKey` — unstealable by XSS) and self-register it. Every request is signed and request-bound; there is no bearer secret.

```ts
const db = createClient({ url, auth: { ed25519: { publicKey: "ssh-ed25519 AAAA… me", privateKey } } });
const { principal } = await db.enroll();                 // policy: open
const { principal } = await db.enroll({ token: "ec_…" }); // policy: token — redeem a single-use invite code
```

`enroll()` is idempotent per key. Pass `enroll({ token })` under `policy: token` — the browser's only path for a **single-use enrollment code** (`ec_…`, minted by an admin at `POST /_admin/enroll/codes`). Bring your own crypto with `auth: { signer }` (`{ publicKey, sign(msg) }`); `sshPublicKeyLine(rawBytes)` builds the `ssh-ed25519 …` line. `db.backup()` downloads the database as a `Uint8Array`. Server side: the `auth-and-tls` skill and the [auth guide](../../docs/auth-and-authz.md#device-enrollment-self-service-principals-for-public-apps). Note: admin ops — minting codes, vault key lifecycle, provisioning management — are **Go-client / HTTP only**; `@quicsql/client` covers the data + self-service-auth plane.

Full user accounts and sign-in — one identity across many devices and factors — are a separate product built on this engine, not part of quicSQL core; this SDK covers the core data plane plus device-key enrollment and session tokens above.

## Live change feed

With the server's `changefeed:` enabled, subscribe to committed row changes — auto-reconnect, resume, and reset behind one call:

```ts
const stop = db.subscribe({
  tables: ["orders"],
  onChange: (e) => refetchOrder(e.rowid),   // e = { seq, table, op, rowid } — never column values
  onReset: () => refetchEverything(),        // horizon left the buffer / server restarted
});
```

It streams over `fetch` (not `EventSource`), so **every auth mode works** — a bare `EventSource` can't send `Authorization`. Full guide: `docs/change-feed.md`.

## Gotchas

- **Why the SDK, not a `fetch` wrapper:** in a browser `fetch` must be called with `this === window`; a method-bound or object-wrapped fetch throws *"'fetch' called on an object that does not implement interface Window."* `@quicsql/client` binds fetch to `globalThis` internally. If you hand-roll requests, replicate that.
- **Keep session tokens out of `localStorage`** where practical — memory or `sessionStorage` limits XSS exposure; keyring keys should be non-extractable.
- **ORMs:** `createClient(...)` satisfies `@libsql/client`'s `Client` interface, so `drizzle(createClient({url, auth}) as any)` works; Prisma's `@prisma/adapter-libsql` wraps a `@libsql/client` instance. `@libsql/client` itself also connects to quicSQL — but needs a **trailing slash** on the URL; `@quicsql/client` doesn't.
- **`intMode`** defaults to `"number"` (throws past 2⁵³−1); use `"bigint"` for exact int64.

Working browser apps built on all of this — session tokens, keyring auth, live feeds — are the [demo SPAs](https://github.com/quicsql/quicsql-demos).
