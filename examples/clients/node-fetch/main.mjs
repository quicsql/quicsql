// quicSQL from plain JavaScript — zero dependencies, just fetch and the native
// JSON API. Runs on Node 18+, Bun, and Deno unchanged.
//
//   node main.mjs        (env: QUICSQL_URL, QUICSQL_TOKEN)
//
// The native API is one endpoint per database: POST /<db>/query with either
// {"sql", "args"} or a {"statements":[...]} batch that runs as a single
// all-or-nothing transaction. Note: a failing batch statement returns HTTP 200
// with an {"error", "failed_index"} envelope — check for "error", not just
// response.ok.

const BASE = (process.env.QUICSQL_URL ?? "http://127.0.0.1:7775").replace(/\/+$/, "");
const TOKEN = process.env.QUICSQL_TOKEN ?? "dev-token";

async function query(body) {
  const res = await fetch(`${BASE}/app/query`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const out = await res.json();
  if (!res.ok || out.error) {
    throw new Error(`query failed (${res.status}): ${out.error?.message ?? "unknown"}`);
  }
  return out;
}

function assert(cond, msg) {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    process.exit(1);
  }
}

// A clean slate for this example's own table.
await query({ sql: "CREATE TABLE IF NOT EXISTS users_fetch (id INTEGER PRIMARY KEY, name TEXT NOT NULL, balance INTEGER NOT NULL)" });
await query({ sql: "DELETE FROM users_fetch" });

// Single statement with positional args; integers stay exact on the wire.
const ins = await query({ sql: "INSERT INTO users_fetch(name, balance) VALUES (?, ?)", args: ["ada", 100] });
assert(ins.last_insert_id > 0, "insert returns last_insert_id");

// A statements batch: one explicit transaction, all-or-nothing.
await query({
  statements: [
    { sql: "INSERT INTO users_fetch(name, balance) VALUES (?, ?)", args: ["bob", 100] },
    { sql: "UPDATE users_fetch SET balance = balance - ? WHERE name = ?", args: [30, "ada"] },
    { sql: "UPDATE users_fetch SET balance = balance + ? WHERE name = ?", args: [30, "bob"] },
  ],
});

const rs = await query({ sql: "SELECT name, balance FROM users_fetch ORDER BY name" });
assert(JSON.stringify(rs.columns) === '["name","balance"]', "columns come back named");
assert(JSON.stringify(rs.rows) === '[["ada",70],["bob",130]]', `rows transferred exactly, got ${JSON.stringify(rs.rows)}`);

console.log("OK node-fetch");
