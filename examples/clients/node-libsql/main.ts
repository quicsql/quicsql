// quicSQL from TypeScript via the official libSQL SDK (@libsql/client).
// quicSQL serves the Hrana pipeline the SDK speaks, so it connects by URL alone.
//
//   npm install && npm start        (env: QUICSQL_URL, QUICSQL_TOKEN)
//
// Runs directly under Node 24+ (native type stripping); works on Bun too.
//
// THE ONE GOTCHA: the URL must end with a trailing slash. quicSQL namespaces
// databases by path (/app), and @libsql/client resolves its endpoint with the
// WHATWG URL rules — "http://host:7775/app" would drop the /app segment,
// "http://host:7775/app/" keeps it.

import { createClient } from "@libsql/client";

const base = (process.env.QUICSQL_URL ?? "http://127.0.0.1:7775").replace(/\/+$/, "");
const db = createClient({
  url: `${base}/app/`, // trailing slash — see note above
  authToken: process.env.QUICSQL_TOKEN ?? "dev-token",
});

function assert(cond: boolean, msg: string): asserts cond {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    process.exit(1);
  }
}

await db.execute(
  "CREATE TABLE IF NOT EXISTS users_node (id INTEGER PRIMARY KEY, name TEXT NOT NULL, balance INTEGER NOT NULL)",
);
await db.execute("DELETE FROM users_node");

// Positional args; the result carries lastInsertRowid as a BigInt.
const ins = await db.execute({
  sql: "INSERT INTO users_node(name, balance) VALUES (?, ?)",
  args: ["ada", 100],
});
assert(ins.lastInsertRowid !== undefined && Number(ins.lastInsertRowid) > 0, "insert returns lastInsertRowid");

// A batch: statements run in order in one round trip, as one transaction.
await db.batch(
  [
    { sql: "INSERT INTO users_node(name, balance) VALUES (?, ?)", args: ["bob", 100] },
    { sql: "INSERT INTO users_node(name, balance) VALUES (?, ?)", args: ["carol", 100] },
  ],
  "write",
);

// An interactive transaction — a baton-pinned Hrana session on the server:
// both updates run on one connection and commit atomically.
const tx = await db.transaction("write");
try {
  await tx.execute({ sql: "UPDATE users_node SET balance = balance - ? WHERE name = ?", args: [30, "ada"] });
  await tx.execute({ sql: "UPDATE users_node SET balance = balance + ? WHERE name = ?", args: [30, "bob"] });
  await tx.commit();
} catch (e) {
  await tx.rollback();
  throw e;
}

const rs = await db.execute("SELECT name, balance FROM users_node ORDER BY name");
const got = rs.rows.map((r) => `${r.name}=${r.balance}`).join(",");
assert(got === "ada=70,bob=130,carol=100", `transaction applied atomically, got ${got}`);

db.close();
console.log("OK node-libsql");
