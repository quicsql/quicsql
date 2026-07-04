# Python

The official `libsql` binding speaks the Hrana protocol quicSQL serves, so it
connects by URL alone — and SQLAlchemy rides on top through the official
dialect. For zero dependencies, the stdlib and the native JSON API do fine.

> **Package names matter.** Install **`libsql`** — the current official
> binding. The older `libsql-client` and `libsql-experimental` packages are
> deprecated, and `libsql-client`'s HTTP mode speaks a pre-Hrana protocol that
> will **not** work against quicSQL (or current sqld).

## `libsql`

```sh
pip install libsql
```

> The `http://` URL below sends the token in the clear — fine on a trusted loopback
> for local development, but in production point the client at an `https://` (TLS)
> endpoint so the bearer token isn't exposed on the wire.

```python
import libsql

conn = libsql.connect("http://127.0.0.1:7775/app", auth_token="your-token")

conn.execute("INSERT INTO users(name, balance) VALUES (?, ?)", ("ada", 100))
conn.executemany(
    "INSERT INTO users(name, balance) VALUES (?, ?)",
    [("bob", 100), ("carol", 100)],
)
conn.commit()

# A transaction: both updates land atomically on commit.
conn.execute("UPDATE users SET balance = balance - ? WHERE name = ?", (30, "ada"))
conn.execute("UPDATE users SET balance = balance + ? WHERE name = ?", (30, "bob"))
conn.commit()

for name, balance in conn.execute("SELECT name, balance FROM users ORDER BY name").fetchall():
    print(name, balance)
```

The API is DB-API-flavored: `execute` returns a cursor (`fetchone` /
`fetchall`, `lastrowid`), writes participate in an implicit transaction until
`commit()` / `rollback()`. `http://` URLs are accepted directly; the database
is the URL path.

**Wheels:** PyPI ships prebuilt wheels for CPython 3.8–3.14 on linux-x86_64 and
3.8–3.13 on macOS — but none for linux-aarch64. On ARM Linux (or an Apple
Silicon Docker container), install with `--only-binary=:all:` to fail fast and
fall back to an amd64 image or the stdlib path below.

## SQLAlchemy

```sh
pip install sqlalchemy sqlalchemy-libsql
```

```python
from sqlalchemy import create_engine, text

# Plain HTTP by default; add ?secure=true for HTTPS.
engine = create_engine(
    "sqlite+libsql://127.0.0.1:7775/app",
    connect_args={"auth_token": "your-token"},
)

with engine.begin() as conn:
    conn.execute(text("INSERT INTO users(name, balance) VALUES (:n, :b)"), {"n": "ada", "b": 100})
```

Full ORM models, sessions, and transactions work — the dialect is SQLite's,
executed over the wire.

## Zero dependencies: stdlib + the native JSON API

```python
import json, urllib.request

def query(body):
    req = urllib.request.Request(
        "http://127.0.0.1:7775/app/query",
        data=json.dumps(body).encode(),
        headers={"Authorization": "Bearer your-token", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as res:
        out = json.load(res)
    if "error" in out:
        raise RuntimeError(out["error"]["message"])
    return out

rs = query({"sql": "SELECT name, balance FROM users WHERE id = ?", "args": [7]})
print(rs["columns"], rs["rows"])
```

Request/response shapes, batches, and error handling are specified in the
[HTTP API reference](http-api.md).

## Runnable versions

[`examples/clients/python-libsql`](https://github.com/quicsql/quicsql/tree/main/examples/clients/python-libsql),
[`python-sqlalchemy`](https://github.com/quicsql/quicsql/tree/main/examples/clients/python-sqlalchemy), and
[`python-stdlib`](https://github.com/quicsql/quicsql/tree/main/examples/clients/python-stdlib)
run these exact flows against a real server in CI.
