# More languages

quicSQL speaks the libSQL Hrana protocol on the wire, so any libSQL SDK that
does **Hrana over plain HTTP** connects by URL alone — and every language with
an HTTP client can use the [native JSON API](http-api.md) with no SDK at all.
The snippets below follow each SDK's documented usage; the wire behavior they
rely on is the same one our CI-tested
[Python](python.md)/[PHP](php.md)/[JavaScript](javascript.md) examples exercise.

## Rust

The `libsql` crate's remote mode is Hrana over HTTP:

```toml
libsql = { version = "0.10", default-features = false, features = ["remote"] }
```

```rust
let db = libsql::Builder::new_remote(
    "http://127.0.0.1:7775/app".to_string(),
    "your-token".to_string(),
).build().await?;
let conn = db.connect()?;

conn.execute("INSERT INTO users(name, balance) VALUES (?1, ?2)", libsql::params!["ada", 100]).await?;
let mut rows = conn.query("SELECT name, balance FROM users", ()).await?;
while let Some(row) = rows.next().await? {
    println!("{}: {}", row.get::<String>(0)?, row.get::<i64>(1)?);
}
```

## Ruby

The official gem (technical preview) wraps the same core:

```sh
gem install turso_libsql
```

```ruby
require 'libsql'

db = Libsql::Database.new(url: 'http://127.0.0.1:7775/app', auth_token: 'your-token')
db.connect do |conn|
  conn.execute 'INSERT INTO users(name, balance) VALUES (?, ?)', ['ada', 100]
  rows = conn.query 'SELECT name, balance FROM users'
  rows.each { |r| puts r }
end
```

## Elixir

[`ecto_libsql`](https://hex.pm/packages/ecto_libsql) is a full Ecto adapter
with a remote-only mode:

```elixir
config :my_app, MyApp.Repo,
  adapter: EctoLibSql,
  database: "remote.db",
  uri: "http://127.0.0.1:7775/app",
  auth_token: "your-token"
```

## Swift

[`libsql-swift`](https://github.com/tursodatabase/libsql-swift) (technical
preview) has a remote-only initializer:

```swift
let db = try Database(url: "http://127.0.0.1:7775/app", authToken: "your-token")
let conn = try db.connect()
try conn.execute("INSERT INTO users(name, balance) VALUES (?, ?)", ["ada", 100])
```

## Java / Kotlin (JVM)

There is currently **no viable Hrana SDK for the JVM** (the official libSQL
artifact is Android-only). The native JSON API with `java.net.http` is the
honest, dependency-free path:

```java
var body = """
    {"sql": "SELECT name, balance FROM users WHERE id = ?", "args": [7]}""";
var req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:7775/app/query"))
    .header("Authorization", "Bearer your-token")
    .header("Content-Type", "application/json")
    .POST(HttpRequest.BodyPublishers.ofString(body))
    .build();
var res = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
// {"columns":["name","balance"],"rows":[["ada",70]],...}
```

## C# / .NET

The libSQL .NET bindings are pre-1.0; `HttpClient` against the JSON API is the
dependable route today:

```csharp
using var http = new HttpClient();
http.DefaultRequestHeaders.Authorization = new("Bearer", "your-token");
var res = await http.PostAsJsonAsync(
    "http://127.0.0.1:7775/app/query",
    new { sql = "SELECT name, balance FROM users WHERE id = ?", args = new object[] { 7 } });
var doc = await res.Content.ReadFromJsonAsync<JsonDocument>();
```

(If you do try an SDK: `Libsql.Client` routes through the same Rust core that
works against quicSQL; the pure-HTTP `LibSql.Http.Client` drops URL paths — use
[host routing or a default database](README.md) with it.)

## Anything else

If it can send an HTTP POST, it can query quicSQL — one endpoint, two JSON
shapes. Start from the [HTTP API reference](http-api.md), or crib the
[curl examples](../hrana.md) for raw Hrana.
