# Changelog

All notable changes to quicSQL are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/). quicSQL is **alpha**: a 0.x.0 bump may
carry breaking changes without further ceremony.

## [Unreleased]

The client-facing wave: browser and device clients become first-class (CORS,
session tokens, self-service enrollment, a change feed), operations grow real
backup/restore and vault key lifecycle, and the server becomes an embeddable
core that product binaries extend with compiled-in feature modules.

### Added

- **Feature modules (plugin architecture).** Optional server modules compile into
  a *product* binary — the Caddy/CoreDNS model — while the core `quicsql` binary
  stays lean: `serverd.RegisterFeature` (a `Feature` is set up against a `Host`
  after the core is built, torn down at shutdown), `config.RegisterSection` (a
  feature owns its own config key), and `meta.RegisterMigration` + `meta.Store.DB`
  (a feature keeps its own tables in the meta store, vault-safe on the shared
  handle). The new `cli` package exports the daemon entrypoint, so a product
  binary is a blank import of its features plus `cli.Main` — `cmd/quicsql` is now
  a thin shim over it.
- **Session tokens** (`auth.session`) — exchange any real credential at
  `POST /_auth/session` for a short-lived, HMAC-signed `st_` bearer token
  (renew with `PUT`, revoke with `DELETE`); optionally sliding (`idle_ttl` /
  `max_ttl`) with transparent renewal via the `X-Session-Token` response header.
  A token cannot mint its successor, and a restart invalidates all outstanding
  tokens. Optional **cookie transport**: the token can also travel as a
  `__Host-`-prefixed HttpOnly cookie, which auto-enables the CSRF defenses
  (SameSite=Strict, Secure, and a Sec-Fetch-Site check on state-changing requests).
- **Assurance levels (step-up authorization).** A session token carries how it
  was authenticated (factor tier, auth time, credential id); an operator-tunable
  `AssurancePolicy` gates sensitive action classes (credential management,
  destructive ops) on factor strength and step-up recency, with secure defaults.
- **Device enrollment** (`auth.enroll`) — a public client generates an ed25519
  keypair and self-registers its public key at `POST /_auth/enroll` (possession
  proven by signing a challenge, like keyring auth). Principals get
  server-assigned names (`u_<key-hash>`) and exactly the configured grants
  template. Gate with static tokens or **single-use enrollment codes**; quotas
  (`max_principals`, per-IP rate) bound abuse; stale enrollees are GC'd after
  `idle_ttl`; and `provision:` optionally gives each enrollee their **own
  database** (database-per-user, with a `max_bytes` size cap and revoke policy).
  Managed at `/_admin/principals` (list, delete — key and grants revoked together).
- **CORS** (`cors:` block) — serve browser apps cross-origin: preflights are
  answered before authentication, approvals stamped on real responses. Validation
  refuses the `*` origin on a server with no auth configured.
- **Change feed** — `GET /<db>/changes` streams committed changes over SSE
  (table, operation, rowid — never column values; nothing is published for a
  rolled-back write). Per-database replay ring for reconnect-and-resume, a
  subscriber cap, and control-plane create/detach keep the feed in step.
- **Online backup and in-place restore** — `GET /<db>/backup` streams a
  standalone SQLite file via the online-backup API (bounded memory, no size cap,
  writers not blocked), complementing the in-RAM `/export`. `POST
  /_admin/restore?database=<db>` swaps a validated image into a file database
  atomically (magic + open + integrity check first, 409 if busy). Go client:
  `BackupTo` + `AdminRestore` — a clone in two calls.
- **Vault key lifecycle** — maintenance ops to list key **members**, **rewrap**
  (rotate the wrapping of the data key), and **rekey** (rotate the data key
  itself) a live vault, plus **`snapshot_encrypted`** (an encrypted-at-rest
  snapshot artifact, unlike the decrypted logical image).
- **Vault space ops** — `compact_logical` (online rewrite down to the logical
  footprint, O(live data) after big deletes), `reclaimable` (read-only probe of
  what it would free), and `checkpoint` (WAL checkpoint on any WAL database,
  `passive|full|restart|truncate`).
- **Changeset apply controls** — an `on_conflict` policy and a table filter on
  `POST /<db>/changeset/apply`.
- **`kms` secret source** — resolves `kms:<name>` references by exec'ing an
  operator-provided command that wraps the real KMS (previously reserved and
  unimplemented).
- **Docs & skills** — a JavaScript/browser clients guide and skill, the change-feed
  guide, and refreshed auth/administration/operations docs covering all of the above.

### Changed

- **White-label wire surface.** Everything on the wire is brand-neutral and
  defined once in `internal/wire`: header names (`X-Session-Token`,
  `X-Keyring-Key/Challenge/Signature`), the `st_` session-token prefix, a generic
  `WWW-Authenticate` realm, the `__Host-session` cookie, and **unprefixed metric
  names** (`databases`, `active_sessions` — previously `quicsql_*`).
- **Lazy warming.** `registry.Warm(ctx, names)` now eagerly opens only the
  config-declared seeds; meta-store databases (runtime-created and per-user
  provisioned) open lazily on first request, so startup is no longer O(total
  provisioned databases). (Signature change from `Warm(ctx)`; the server passes
  seed names.)
- `internal/httpjson` is exported as `httpjson` so feature modules can use it;
  admin create/detach share one provisioning path.

### Fixed

- Enrollment-lifecycle contradictions and assorted security/perf hardening from
  the post-feature audit wave, including audit coverage for every control-plane
  denial and failure path.

## [0.6.0] - 2026-07-04

A wire-protocol unification plus a security-hardening pass.

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
- Result cells decode through the shared `wire` codec on both paths: raw
  `*client.Client` cells are now `int64`/`float64` instead of `json.Number`
  (`database/sql` / the driver already normalized, so they are unaffected), and
  an integral REAL serializes as `100.0` on the native wire (was `100`).
- `obs.WriteOpenMetrics` → `WritePrometheus` (the `/_metrics` output itself is
  unchanged: `text/plain; version=0.0.4`).
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
- **Metrics gauge race:** `databases` is now sampled under the registry
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
- Keyring signing input binds the raw query string — a captured ed25519 signature
  can no longer be replayed onto a different operation target (`?id=`, `?store=`)
  within the challenge TTL. The signed bytes changed, so upgrade a keyring client
  and server together.
- A DSN with URL userinfo (`quicsql://user:pw@host/db`) is rejected with a clear
  error (it previously sent *no* credential, silently); use `?token=` or
  `?user=&password=`.
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
- The exported name `obs.*.WriteOpenMetrics` (renamed to `WritePrometheus`). The
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

[Unreleased]: https://github.com/quicsql/quicsql/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/quicsql/quicsql/compare/v0.5.3...v0.6.0
[0.5.3]: https://github.com/quicsql/quicsql/compare/v0.5.0...v0.5.3
[0.5.0]: https://github.com/quicsql/quicsql/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/quicsql/quicsql/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/quicsql/quicsql/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/quicsql/quicsql/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/quicsql/quicsql/releases/tag/v0.1.0
