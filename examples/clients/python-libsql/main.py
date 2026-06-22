#!/usr/bin/env python3
"""quicSQL from Python via the official libSQL binding (`pip install libsql`).

    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    .venv/bin/python main.py        (env: QUICSQL_URL, QUICSQL_TOKEN)

quicSQL serves the Hrana pipeline the binding speaks, so it connects by URL
alone — http:// URLs are accepted directly, and the database is the URL path.
The API is DB-API-flavored: execute/executemany, commit/rollback, cursors.
"""

import os
import sys

import libsql

BASE = os.environ.get("QUICSQL_URL", "http://127.0.0.1:7775").rstrip("/")
TOKEN = os.environ.get("QUICSQL_TOKEN", "dev-token")

conn = libsql.connect(f"{BASE}/app", auth_token=TOKEN)


def check(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


conn.execute("CREATE TABLE IF NOT EXISTS users_pylibsql (id INTEGER PRIMARY KEY, name TEXT NOT NULL, balance INTEGER NOT NULL)")
conn.execute("DELETE FROM users_pylibsql")
conn.commit()

cur = conn.execute("INSERT INTO users_pylibsql(name, balance) VALUES (?, ?)", ("ada", 100))
check(cur.lastrowid and cur.lastrowid > 0, "insert returns lastrowid")

conn.executemany(
    "INSERT INTO users_pylibsql(name, balance) VALUES (?, ?)",
    [("bob", 100), ("carol", 100)],
)
conn.commit()

# A transaction: both updates land atomically, then commit.
conn.execute("UPDATE users_pylibsql SET balance = balance - ? WHERE name = ?", (30, "ada"))
conn.execute("UPDATE users_pylibsql SET balance = balance + ? WHERE name = ?", (30, "bob"))
conn.commit()

rows = conn.execute("SELECT name, balance FROM users_pylibsql ORDER BY name").fetchall()
got = ",".join(f"{name}={balance}" for name, balance in rows)
check(got == "ada=70,bob=130,carol=100", f"rows after transaction, got {got}")

print("OK python-libsql")
