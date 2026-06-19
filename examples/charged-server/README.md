# charged-server

A deployable, **fully-charged** quicSQL server — meant to run on a host and be reached over the network. It is a first-class in-module example of quicSQL (`quicsql.net`): purely a server, with no client or LiteORM dependency. Run it from the module root with `go run ./examples/charged-server` or `just charged`.

## What's charged

- **Encryption + compression at rest** — the `catalog` database is a `vfs/vault` container: Adiantum-encrypted and zstd-compressed (`best`). Plus a plain file DB `app` and a shared in-memory `cache`. (See the [databases guide](../../docs/databases.md).)
- **Server-composed engine** — the standard extension bundle (`regexp`, `fts5`, `vec0`, `spellfix1`, `rtree`, …) **and a custom SQL function** (`showcase_greet`) registered via `sqlite.RegisterAutoHook` before `serverd.Run`. This is how server-side functions/extensions/VFS reach remote clients: the server runs them; clients call them via SQL.
- **Encryption in transit** — **h2/TLS (7777)** and **HTTP/3 over QUIC (7778)** as the primary secure transports, with cleartext h1 (7775) / h2c (7776) and a Unix socket as dev extras. It mints its TLS leaf from a fixed dev CA for the SANs you pass with `-hosts`. (See the [mTLS guide](../../docs/mtls-production.md).)
- **Every auth method + authz level** — bearer, HTTP-password, **mTLS**, and the **ed25519 keyring** challenge/response; per-database grants at `none`/`read-only`/`read-write`/`admin`. (See the [auth guide](../../docs/auth-and-authz.md).)
- **Control plane** (`/_admin`, admin-only), rate + concurrency **limits**, a **slow-query log**, and a **vault-backed meta store**.

## Run it

From the quicSQL module root, on the server host:

```
go run ./examples/charged-server -hosts your.host.name,203.0.113.10    # bind 0.0.0.0; TLS cert covers these SANs
just charged -hosts your.host.name,203.0.113.10                        # same, via the recipe
```

Then point a client at it from anywhere — e.g. the `quicsql-remote-tour` in the gosqlite repo: `go run . -addr your.host.name:7777`.

### Containers

The `Dockerfile` builds the **released** `quicsql.net` (published gosqlite). During local co-development the module's `go.mod` replaces gosqlite with the sibling checkout, which a container build from this repo alone cannot see — so for a local container build use the self-contained variant in the gosqlite repo (`examples/quicsql-charged-server`), which builds from a context that includes gosqlite. Either way, `go run` works locally via the replace.

### HTTP/3 (QUIC) through Docker

h2 is TCP (7777); **h3 is QUIC over UDP (7778)**. Two things trip it up in containers, and both look the same on the client — `timeout: no recent network activity` (quic-go's idle timeout, i.e. UDP never made the round trip) while h2 keeps working:

- **Forget the `/udp` suffix.** `-p 7778:7778` publishes *TCP* 7778; QUIC packets are silently dropped. It must be `-p 7778:7778/udp`.
- **Docker Desktop on macOS/Windows.** Its userspace UDP proxy does not reliably forward QUIC even with `/udp`, so h3 can still time out. This is a Docker Desktop limitation, not a server bug — the same binary serves h3 fine when run natively (`go run`) or in Docker on **Linux** with host or bridge networking.

## Credentials

All dev credentials are **fixed** (see `creds.go`): the TLS PKI is committed ECDSA material (universally interoperable), and the ed25519 keyring identity is derived from a seed — so a client derives identical material with nothing copied at runtime. **Replace every value in `creds.go` for a real deployment.** The bearer token, mTLS client cert (CN=`tourist`), password (`analyst`), and keyring key are all dev-only.

`-hosts` **must** include the hostname/IP that clients dial, or TLS verification fails from another machine. `peercred` + the Unix socket are same-machine only (there is no Unix socket over a network), so they are not part of the network story.

`charged.yaml` is a reference config mirroring what `main.go` composes — the shape you would hand the standalone `quicsql` daemon (`cmd/quicsql`), which cannot register the custom `showcase_greet` function or derive the dev PKI, so it expects real key/cert files.
