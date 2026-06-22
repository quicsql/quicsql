#!/usr/bin/env python3
"""quicSQL from Python with nothing but the standard library.

    python3 main.py        (env: QUICSQL_URL, QUICSQL_TOKEN)

The native JSON API is one endpoint per database: POST /<db>/query with either
{"sql", "args"} or a {"statements": [...]} batch that runs as one all-or-nothing
transaction. A failing batch statement returns HTTP 200 with an
{"error", "failed_index"} envelope — check for "error", not just the status.
"""

import json
import os
import sys
import urllib.request

BASE = os.environ.get("QUICSQL_URL", "http://127.0.0.1:7775").rstrip("/")
TOKEN = os.environ.get("QUICSQL_TOKEN", "dev-token")


def query(body: dict) -> dict:
    req = urllib.request.Request(
        f"{BASE}/app/query",
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req) as res:
        out = json.load(res)
    if "error" in out:
        raise RuntimeError(f"query failed: {out['error']['message']}")
    return out


def check(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


query({"sql": "CREATE TABLE IF NOT EXISTS users_py (id INTEGER PRIMARY KEY, name TEXT NOT NULL, balance INTEGER NOT NULL)"})
query({"sql": "DELETE FROM users_py"})

ins = query({"sql": "INSERT INTO users_py(name, balance) VALUES (?, ?)", "args": ["ada", 100]})
check(ins["last_insert_id"] > 0, "insert returns last_insert_id")

# A statements batch: one explicit transaction, all-or-nothing.
query({
    "statements": [
        {"sql": "INSERT INTO users_py(name, balance) VALUES (?, ?)", "args": ["bob", 100]},
        {"sql": "UPDATE users_py SET balance = balance - ? WHERE name = ?", "args": [30, "ada"]},
        {"sql": "UPDATE users_py SET balance = balance + ? WHERE name = ?", "args": [30, "bob"]},
    ]
})

rs = query({"sql": "SELECT name, balance FROM users_py ORDER BY name"})
check(rs["columns"] == ["name", "balance"], "columns come back named")
check(rs["rows"] == [["ada", 70], ["bob", 130]], f"rows transferred exactly, got {rs['rows']}")

print("OK python-stdlib")
