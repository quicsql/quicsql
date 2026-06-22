// Drizzle ORM on quicSQL — no adapter needed. Drizzle's libSQL driver wraps
// @libsql/client, and quicSQL speaks the Hrana protocol that client uses, so a
// typed schema, inserts, selects, and transactions all run over the wire as-is.
//
//   npm install && npm start        (env: QUICSQL_URL, QUICSQL_TOKEN)
//
// Same gotcha as @libsql/client directly: keep the trailing slash on the URL.

import { createClient } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { sql, eq } from "drizzle-orm";
import { sqliteTable, integer, text } from "drizzle-orm/sqlite-core";

const users = sqliteTable("users_drizzle", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  name: text("name").notNull(),
  balance: integer("balance").notNull(),
});

const base = (process.env.QUICSQL_URL ?? "http://127.0.0.1:7775").replace(/\/+$/, "");
const client = createClient({
  url: `${base}/app/`, // trailing slash — quicSQL namespaces databases by path
  authToken: process.env.QUICSQL_TOKEN ?? "dev-token",
});
const db = drizzle(client);

function assert(cond: boolean, msg: string): asserts cond {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    process.exit(1);
  }
}

// Examples keep DDL inline; real projects would use drizzle-kit migrations
// (they emit plain SQL, which quicSQL executes like any other statement).
await db.run(sql`CREATE TABLE IF NOT EXISTS users_drizzle
  (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, balance INTEGER NOT NULL)`);
await db.delete(users);

await db.insert(users).values([
  { name: "ada", balance: 100 },
  { name: "bob", balance: 100 },
]);

// A typed transaction — Drizzle opens a Hrana session under the hood.
await db.transaction(async (tx) => {
  await tx.update(users).set({ balance: sql`${users.balance} - 30` }).where(eq(users.name, "ada"));
  await tx.update(users).set({ balance: sql`${users.balance} + 30` }).where(eq(users.name, "bob"));
});

const rows = await db.select().from(users).orderBy(users.name);
const got = rows.map((r) => `${r.name}=${r.balance}`).join(",");
assert(got === "ada=70,bob=130", `typed select after transaction, got ${got}`);

client.close();
console.log("OK node-drizzle");
