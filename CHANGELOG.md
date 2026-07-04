# Changelog

All notable changes to quicSQL are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/) — with the pre-1.0 caveat that a minor
(0.x.0) bump may carry breaking changes, which are always called out under
**Upgrade notes**.

## [0.6.0] - 2026-07-04

A wire-protocol unification plus a security-hardening pass.

### ⚠️ Upgrade notes (breaking / behavior changes)

- **Keyring auth is not wire-compatible across the upgrade.** The ed25519
  challenge/response now signs the request's method, path, **and raw query
  string** (previously method + path only). A v0.5.x client talking to a v0.6.0
  server — or the reverse — will **fail keyring authentication**, even for
  requests with no query string, because the signed byte string differs.
  **Upgrade the client and server together.** Bearer, HTTP-basic, and mTLS are
  unaffected.
- **Raw `quicsql.net/client` result cells changed Go type.** `Result.Rows` cells
  are now `int64`/`float64` instead of `json.Number` (both the native and Hrana
  paths decode through one shared codec now). **`database/sql` / the `quicsql`
  driver are UNAFFECTED** — the driver already normalized both to `int64`/`float64`.
  Only code that type-asserts `json.Number` on a raw `*client.Client` result needs
  to change.
- **`obs.Registry.WriteOpenMetrics` was renamed to `WritePrometheus`** (and the
  `obs.Exposer` interface method with it). Recompile if you import `quicsql.net/obs`
  and call the method or implement `Exposer`. The `/_metrics` HTTP output is
  unchanged (`text/plain; version=0.0.4`).
- **A DSN with URL userinfo is now rejected.** `quicsql://user:pw@host/db` returns
  a clear error (it previously sent *no* credential, silently). Put credentials in
  query params: `?token=` or `?user=&password=`.
- **Native wire: an integral REAL now serializes as `100.0`, not `100`.** Parses to
  the same numeric value; it fixes an int-vs-float drift between the autocommit and
  transaction paths. Only non-Go clients inspecting the raw JSON number could notice.

### Added
- **`auth.sql_policy.allow_attach`** — a **development-only** switch that permits
  `ATTACH`/`DETACH`, and even then only for a **server-admin** on a **pinned Hrana
  session** (never the autocommit path); the attachment is torn down on session close.
  Off by default (the sandbox stays unconditional); logs a startup warning when on.
  `load_extension` remains non-configurable (RCE class); the two dead `sql_policy`
  fields (`allow_load_extension`, `enabled_extensions`) were removed.
- **TLS `qip` mode** — auto-fetch a browser-trusted [qip.sh](https://qip.sh) wildcard
  certificate for a private-network or localhost server, with no CA setup
  (`tls.<profile>.mode: qip`, with `subdomain`/`refresh`). Gives a valid padlock, but
  the qip.sh private key is public, so it is NOT server authentication — the server
  warns when a qip listener binds a non-loopback address. Use `files` for anything an
  untrusted party can reach.
- **`logging.format`** (`json` | `text`) is now wired — `json` emits structured logs
  for a log pipeline (previously parsed but ignored).
- **`limits.max_export_bytes`** — the full-database `/export` cap is now configurable
  (previously a fixed 1 GiB); unset keeps the 1 GiB default.
- `internal/wire` — a single source of truth for the on-the-wire value
  representation (`Value`/`Kind`), the Go↔value normalizer, both JSON codecs
  (native + Hrana), and the SQLite result-code table, shared by the server and the
  client so the two protocols cannot drift.
- `config.ValidateDatabase` — one per-database validator shared by config seeds,
  the `/_admin` create route, and the startup reconcile, so all three agree (a
  typo'd `mode` can no longer be silently coerced to read-write-create).
- `meta.AuditEntries(limit)` + `meta.AuditEntry` — read the admin audit log
  newest-first (nil-safe for stateless deployments).
- `client/sqldriver.ErrTruncated` — the truncation sentinel is now **exported**, so
  a capped result set can be classified with `errors.Is` on `rows.Err()` instead of
  string-matching.
- `docs/administration.md` — an operator / control-plane guide.

### Changed
- Result cells now decode through the shared `wire` codec on both paths (see Upgrade
  notes for the raw-client type change).
- `obs.WriteOpenMetrics` → `WritePrometheus` (see Upgrade notes).
- `engine.Value` / `engine.Kind` are now transparent type aliases of `wire.Value` /
  `wire.Kind` (identical fields — no consumer break).
- The daemon defaults the transaction idle/lifetime timeouts in one place
  (`MaxTxLifetime` = 5m), instead of relying on `session.NewStore`'s internal fallback.
- `session.Store.Open` gained a trailing `allowAttach bool` parameter (internal
  server seam for the dev-only ATTACH switch; the server is the only caller —
  recompile if you drive `quicsql.net/session` directly).

### Fixed
- **Read-only pool poisoning:** `SetConnMode` now tightens `query_only=ON` before
  swapping in the write-denying authorizer (and reverses the order on restore), so a
  mid-transition failure can't return a connection to the pool carrying the
  authorizer without `query_only` — which had spuriously denied a later
  write-capable borrower with `SQLITE_AUTH`.
- **Metrics gauge race:** `quicsql_databases` is now sampled under the registry
  mutex instead of an unlocked `len()` that raced control-plane create/detach.
- **Unbounded metric series:** requests are metered only for databases the registry
  knows, so a caller can no longer mint phantom, never-reclaimable per-database series.
- Changeset-invert and the Hrana cursor now return **413** (not 400) for an
  over-cap body.
- `/export` fails closed (500) if the size probe errors, instead of proceeding to an
  unbounded in-RAM serialize.
- Blob uploads use a per-chunk idle deadline, so a large-but-progressing upload is
  no longer severed at a fixed wall-clock deadline.
- The `H1` client owns its transport, so `Close()` releases its idle connections;
  a `WithMaxResponse` set near `MaxInt64` no longer overflows.

### Security
- Keyring signing input binds the raw query string (see Upgrade notes) — a captured
  ed25519 signature can no longer be replayed onto a different operation target
  (`?id=`, `?store=`) within the challenge TTL.
- DSN userinfo is rejected (see Upgrade notes).
- The server logs a startup **warning** when a bearer/password/keyring listener runs
  over a cleartext transport (h1/h2c); keyring is flagged specially (its signature is
  exposed and replayable over cleartext). The raw client warns when built with a
  credential over a cleartext or unverified-TLS transport. Advisory, not enforced.
- Denied **and failed** control-plane attempts are audited (`.denied` / `.failed`),
  not only successes — across create, detach, kill, and the maintenance ops.
- Secret file references are contained with `config.WithinDir`, rejecting an absolute
  path outside the source dir that the previous `filepath.Join` silently remapped
  under it.

### Removed
- The exported name `obs.*.WriteOpenMetrics` (renamed — see Upgrade notes). The
  internal `httpapi/codec.go` was deleted (folded into `internal/wire`).

## [0.5.3] - 2026-07-04
- Credential-safety hardening and documentation coverage: the `database/sql` driver
  refuses to send a credential over a cleartext/insecure transport (with an
  `allow_insecure_auth=1` override), DSN-parse errors redact secrets, and the client
  caps server-supplied response bodies (`WithMaxResponse`, default 1 GiB).
  (Aggregates v0.5.1–v0.5.3.)

## [0.5.0] - 2026-07-03
- CI & automated release workflows; a security-audit hardening pass across the
  data/control planes; dependency pinning (gosqlite v0.13.0, no replace directives);
  LICENSE. First public, release-ready cut.

## [0.4.0] - 2026-06-18
- Migration of package names and module paths to `quicsql.net` — stable public
  import paths for downstream consumers.

## [0.3.0] - 2026-06-11
- Admin control plane: runtime database lifecycle (create/detach) and vault
  maintenance (compact / reclaim / snapshot) under an admin-gated `/_admin` surface.

## [0.2.0] - 2026-06-08
- Authentication & authorization: bearer tokens, mTLS, and the ed25519
  challenge/response, over a fail-closed per-database grant policy.

## [0.1.0] - 2026-06-05
- First runnable multi-transport server (h1/h2c/h2/h3/unix) over the CGo-free
  gosqlite engine, with interactive Hrana sessions.

[0.6.0]: https://github.com/quicsql/quicsql/compare/v0.5.3...v0.6.0
[0.5.3]: https://github.com/quicsql/quicsql/compare/v0.5.0...v0.5.3
[0.5.0]: https://github.com/quicsql/quicsql/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/quicsql/quicsql/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/quicsql/quicsql/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/quicsql/quicsql/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/quicsql/quicsql/releases/tag/v0.1.0
