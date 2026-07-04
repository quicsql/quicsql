# Go

Go gets the richest client surface: the native quicSQL client covers every
transport (HTTP/1.1, h2c, HTTP/2, HTTP/3, Unix sockets) and every auth method
(bearer, password, mTLS, keyring), the `database/sql` driver makes a remote
database open like a local file, and LiteORM runs on top unchanged. The
community `libsql-client-go` works too, if you're arriving from that ecosystem.

## The quicSQL client

```go
import "quicsql.net/client"

c := client.H1("127.0.0.1:7775", client.WithBearer(token)) // or H2C / H2TLS / H3 / Unix
defer c.Close()

res, err := c.Query(ctx, "app", "SELECT name, balance FROM users WHERE id = ?", 7)

// An interactive transaction: one pinned server-side connection.
st := c.OpenStream("app")
defer st.Close(ctx)
st.Exec(ctx, "BEGIN", nil)
st.Exec(ctx, "UPDATE users SET balance = balance - ? WHERE name = ?", []any{30, "ada"})
st.Exec(ctx, "UPDATE users SET balance = balance + ? WHERE name = ?", []any{30, "bob"})
st.Exec(ctx, "COMMIT", nil)
```

`Batch` runs N statements in one round trip; changesets, blob streaming, and
full-database export are one call each — see
[pkg.go.dev/quicsql.net/client](https://pkg.go.dev/quicsql.net/client).

Those whole-response reads — a blob, an inverted or concatenated changeset, an
export, a query result — are buffered under a client-side ceiling,
`DefaultMaxResponse` (1 GiB), that bounds what a hostile or buggy server can make
the client allocate. A body over the cap fails with `server response exceeds the
N-byte client cap`; `client.WithMaxResponse(n)` raises it for genuinely large
blobs or exports, and `WithMaxResponse(0)` removes it entirely.

## `database/sql`

The driver registers under gosqlite's `sqlite` name **and** as `quicsql`, so a
remote database opens like a local one — only the DSN changes:

```go
import (
    "database/sql"

    _ "quicsql.net/client/sqldriver"
)

//   sql.Open("sqlite", "file:app.db")   → a local SQLite file
db, _ := sql.Open("sqlite", "quicsql://db.example.com:7777/app?transport=h2&token="+tok)

tx, _ := db.BeginTx(ctx, nil) // transparently opens a Hrana session
```

The driver refuses to send a credential over a channel that would expose it —
the plaintext transports (`h1`, `h2c`) or `h2`/`h3` with `insecure=1` (unverified
TLS) — so a token rides verified TLS (above) or a unix socket. On a trusted
local/dev link with the self-signed dev cert, add `allow_insecure_auth=1` to opt
in knowingly.

Credentials ride query params (`?token=` or `?user=&password=`), never URL
userinfo: a `quicsql://user:pw@host/db` DSN is rejected outright, since it would
send no credential yet slip past that transport guard. A unix socket has no host,
so its DSN carries the path instead —
`quicsql:///app?transport=unix&socket=/run/quicsql/sql.sock`. Statements bind
positionally: use `?` placeholders with ordered args; a named parameter is
rejected rather than silently mis-bound. And when the server caps a result set at
its row or byte limit, the delivered rows are a prefix of the real result and
`rows.Err()` returns `sqldriver.ErrTruncated` (not `io.EOF`), so
`errors.Is(rows.Err(), sqldriver.ErrTruncated)` keeps a partial answer from
passing for a complete one.

For credentials a DSN can't carry (mTLS, keyring), build a `*client.Client`
and hand it to `sqldriver.OpenConnectorClient` — see the
[auth guide](../auth-and-authz.md) and [mTLS guide](../mtls-production.md).

## LiteORM

[LiteORM](https://liteorm.org) — the declarative, CGo-free SQLite data layer —
selects local or remote by DSN shape, so the same models, migrations, and
typed vector / full-text / hybrid search hit a quicSQL server the moment you
point them at a `quicsql://` URL:

```go
import (
    "liteorm.org/dialect/sqlite"
    "liteorm.org/orm"
    _ "quicsql.net/client/sqldriver"
)

db, _ := sqlite.Open("quicsql://db.example.com:7777/app?transport=h2&token=" + tok)
defer db.Close()
orm.AutoMigrate[User](ctx, db)
```

## `libsql-client-go`

The community libSQL Go client speaks Hrana v2 over HTTP and preserves URL
paths, so it points at quicSQL directly — useful when porting code written for
sqld/Turso:

```go
import "github.com/tursodatabase/libsql-client-go/libsql"

db, _ := sql.Open("libsql", "http://127.0.0.1:7775/app?authToken="+tok)
```

For new Go code, prefer the native client/driver — it covers all transports
and auth methods, with exact integer/blob round-trips.
