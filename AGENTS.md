# AGENTS.md

Onboarding for AI agents and humans **developing** this repository. Read it top-to-bottom to be useful within ~5 minutes. (Agents *using* quicSQL as a dependency — connecting, deploying, securing — want [`skills/`](skills/) instead; humans want [`docs/`](docs/) and the package docs on pkg.go.dev.)

This file is canonical; `CLAUDE.md` is a pointer to it.

---

## What this is

`quicsql.net` is a **CGo-free SQLite network server**: it owns local databases (plain files, in-memory, and encrypted/compressed `vfs/vault` containers) and fans many network clients into **one long-lived open handle per database** — the single-owner discipline that makes a vault file safely shareable. Clients speak two protocols over one HTTP handler: a thin **native-JSON** endpoint (`POST /<db>/query`) and the libSQL **Hrana** pipeline (`/<db>/v3/pipeline`, baton-pinned sessions for interactive transactions), across the full transport matrix — HTTP/1.1, cleartext h2c, h2 over TLS, HTTP/3 over QUIC, and Unix sockets.

It is built on **gosqlite** (`gosqlite.org`, the CGo-free SQLite engine) and co-developed alongside it: the `go.mod` replaces resolve gosqlite from the sibling checkout (see [Co-developing with gosqlite](#co-developing-with-gosqlite)). Supported Go: the two most recent releases (the pin lives in `go.mod`; don't name versions in prose). `just lint` runs `gopls modernize`, so modern syntax is expected.

## Architecture in one paragraph

Every request flows through a fixed pipeline: a **listener** (one per wire) hands the request to the **auth middleware**, which authenticates it into an `authz.Principal` and attaches it to the context; the **httpapi handler** then enforces the per-database capability via `authz.Policy` (read needs ≥ read-only, write ≥ read-write, admin ops need admin), routes to the native or Hrana path, and asks the **registry** for the database's single shared handle. The registry opens each database once through a **backend** (`backend.For` → file / memory / vault / mvcc / memdb) and reference-counts it. Autocommit statements run on the shared pool; a **Hrana session** pins one connection for a baton's life (interactive transactions, SESSION capture), and a read-only principal's pinned connection is put in `query_only` with a write-denying authorizer so it *cannot* write. The whole thing is composed by `serverd.Run(cfg, log)`, which returns an `*Instance` you `Shutdown(ctx)`.

---

## Repository layout

Each package documents its contract in a `doc.go`; the root package (`quicsql`) is the umbrella doc.

```
serverd/        serverd.Run(cfg, log) → *Instance; wires the whole pipeline + Shutdown
config/         Config structs + Load(path) + Validate() (the YAML surface, one source of truth)
backend/        backend.For(db) → Backend: file.go / memory.go / vault.go / vfs.go (mvcc, memdb); pragmas, slow log
registry/       one shared *sqlite.DB handle per database, ref-counted; Get(ctx, db)
engine/         Queryer/TxBeginner adapters + IsReadOnly SQL classification
httpapi/        the HTTP handler: native.go (/query), hrana.go (/v3/pipeline), hrana_cursor.go (/v3/cursor), export/changeset/blob, routing, limits gate
transport/      serve.go / tls.go — start the handler on h1 / h2c / h2-TLS / h3-QUIC / unix; buildTLS (mTLS)
auth/           auth.go (authenticate → Principal), methods, challenge.go (ed25519 challenge/response), peercred_*, session.go (st_ session tokens), cookie.go
authz/          Level (none<ro<rw<admin) + Policy (per-db grants); transport-neutral
session/        Store of baton-pinned sessions; read-only pinning; the reaper; SESSION capture handle
enroll/         self-service dynamic principals (auth.enroll): /_auth/enroll register + one-time codes + idle GC
provision/      materializes/tears down a per-principal database from a template (shared by enroll and the control plane)
feed/           the change-feed broker: connection hook → per-table ring → SSE at /<db>/changes
admin/          /_admin control plane: create/detach/list, sessions/kill, vault maintenance (admin-gated)
meta/           the runtime database registry + enrolled principals + enroll codes + audit log (vault-backed by default)
secret/         "source:name" resolver (env / file / kms) for keys, tokens, identities
limits/         per-principal rate limit + per-db concurrency cap + statement/tx timeouts
obs/            /_metrics (Prometheus text), slow-query log
client/         the Go client (H1/H2C/H2TLS/H3/Unix, Query/Exec/Batch/OpenStream, changeset/blob/export)
client/sqldriver/  the database/sql driver ("quicsql", quicsql:// DSN) + OpenConnectorClient for mTLS/keyring
extensions/     the curated, network-safe extension bundle (regexp, fts5, vec0, spellfix1, rtree, …)
cmd/quicsql/    the standalone daemon (`quicsql --config quicsql.yaml`)
internal/       httpjson/ (response envelope), raceskip/ (checkptr skip; local — can't import gosqlite's)
examples/       in-module runnable examples: demo (transports + bench), auth (auth matrix), charged-server (deployable)
docs/           human guides: getting-started, auth-and-authz (static principals, session tokens, device enrollment), mtls-production, hrana, databases, change-feed, administration, clients/ (incl. the @quicsql/client JS SDK, http-api)
```

---

## Fragile invariants you must not break

1. **Single owner per database.** The registry holds exactly one open handle per database and fans all clients into it (in-process advisory locks only, no cross-process sharing). This is the reason the daemon exists — a vault container is only safely shareable under a single owner. Don't add a code path that opens a second handle to the same file.
2. **A Hrana baton is bound to (database, principal).** `session.Resume` validates both before consuming the baton, so a wrong-principal request can't ride or invalidate the owner's session (`ErrPrincipalMismatch` → 403; bad/expired baton → 400). Don't loosen the binding.
3. **Read-only is enforced in depth, not by trusting SQL.** A read-only principal runs on a borrowed connection put in `query_only` + a write-denying authorizer (native path in `httpapi/native.go`; the whole stream for a Hrana session in `session.Open(readOnly)`). Never gate writes by parsing the statement.
4. **Auth "hard vs soft".** A present-but-invalid credential is a `401` — never silently downgraded to anonymous (`auth.hardMethods` = mtls→keyring→session→bearer→password, first present decides; session precedes bearer because both read `Authorization: Bearer` — the `st_` prefix routes a token to exactly one). `peercred` is the only soft method (unmapped uid falls through); `none` is the terminal anonymous fallback. Keep this ordering and the "present ⇒ decisive" rule.
5. **Open mode is fail-open only when nothing is configured.** `authz.NewPolicy(open)` is open (every principal read-write everywhere) **only** when there are zero principals AND zero grants (`serverd.buildPolicy`). The moment one appears, it's grants-decide-default-none. Don't widen this.
6. **SESSION handle is taken atomically.** `session.TakeCapture` hands the capture off exactly once so teardown can't double-free the native SESSION handle. Preserve the atomic take on close/shutdown.
7. **A vtab ctor must run on the executing connection.** `vtab` trampolines resolve the connection from the db handle SQLite passed in (`connForDB`), not a connection captured at registration — otherwise `declare_vtab` targets the wrong handle and returns `SQLITE_MISUSE`. This lives in gosqlite, but the server's per-connection extension registration is what exercises it.
8. **Canonical port 7775.** h1 is 7775; sequence up for multi-transport (h2c 7776, h2/TLS 7777). **h3/QUIC shares 7777** — QUIC is UDP, a separate namespace from h2's TCP, so they co-locate on one port the way HTTPS does on :443 (h3's `advertise: true` makes the TCP transports emit `Alt-Svc` so clients upgrade). Never invent 78xx placeholders.

---

## Conventions

- **Lint = `just lint`** (fmt-check + vet + staticcheck + golangci + modernize). Every CI lint step has a matching justfile dependency. Run it (and `just test`) before reporting done.
- **`interface{}` is `any`.** Always. Modern syntax is expected (generics, `iter.Seq`, `strings.SplitSeq`, range-over-int, `atomic.Int32`).
- **Comments: WHY not WHAT.** A well-named identifier says what; comments explain the non-obvious choice, the invariant preserved, or the protocol contract honored.
- **Secrets never logged.** Tokens, keys, passwords, and bound parameters (unless `logging.expand_params`) are redacted.
- **Markdown:** never hard-wrap prose (single long lines per paragraph). No version numbers in prose. No "Recent additions" / "Unreleased" holding sections.
- **Config vocabulary is single-sourced** in `config/load.go` (`KnownBackends`, `ListenerAuthMethods`, `grantLevels`, vault vocab); backend/auth/authz switch over the same sets. Add a new value in both places.

---

## Common tasks

| Task | Command |
|---|---|
| Build / test / lint | `just build` · `just test` · `just lint` |
| One named test | `just test-one TestBatch` |
| Race detector | `just test-race` |
| Format check / apply | `just fmt-check` / `just fmt` |
| Run the daemon | `just run --config quicsql.yaml` |
| Self-contained demos | `just demo` (transports + bench) · `just auth-demo` / `auth-demo-tls` · `just charged` |
| Two-module showcase / studio (reach the gosqlite-repo examples) | `just showcase` · `just studio` |
| Cross-build / release binaries | `just cross-build` / `just dist` |
| Full CI locally | `just ci` |
| List recipes | `just --list` |

`just` is convenience over vanilla `go test ./...`, not a build dependency.

---

## When asked to add a new feature

First: **which layer owns this?**

- **A transport** → `transport/` (mirror an existing case in `serve.go`; TLS shape in `tls.go`).
- **An auth method** → `auth/` (compile it in `auth.go`, try it in the right priority slot) + add its name to `config.ListenerAuthMethods` / `KnownAuthMethods` in `config/load.go`.
- **A database backend** → `backend/` (a new `Backend` impl + dispatch in `backend.For`) + `config.KnownBackends` + validation in `config/load.go`.
- **A wire endpoint** → `httpapi/` (route in `handler.go`; native vs Hrana as appropriate; enforce the level via `authorize`).
- **A control-plane op** → `admin/` (gate with `adminFilter` / `canAdminDB`).
- **A client method** → `client/` (and expose it through the driver in `client/sqldriver/` if it belongs on a `database/sql` conn).

Always:

1. Add tests in the package's `*_test.go` (prefer integration over the wire — see `client/*_test.go`, `httpapi/*_test.go`). Native C paths (Serialize, SESSION, blobstore) trip `-race` checkptr; skip them with `internal/raceskip`.
2. **Update every doc the change touches, in the same change** — doc drift is the #1 failure mode:
   - `doc.go` for the package whose API moved.
   - `docs/<guide>.md` — the human guide (getting-started / auth-and-authz / mtls-production / hrana / databases / change-feed / administration / clients/).
   - **`skills/<name>/SKILL.md`** — the agent-usage recipe. Skills ship to consumers and go stale silently; treat updating them as part of the feature. Add a new skill folder when a feature is a distinct task an agent would do.
   - `README` if the change affects the landing overview.
3. Don't quote test counts in user-facing docs — describe behavior, not numbers.

---

## When asked to bump dependencies

- **gosqlite** is the co-dev sibling. During development it resolves via the `replace … => ../../sqlite` directives; a real release pins published versions. Don't bump it in isolation from a change that needs it — build against the sibling checkout and let the consumer examples confirm.
- **`quic-go`** (h3), **`go.yaml.in/yaml`** (config), **`golang.org/x/crypto`** (bcrypt / ssh / adiantum) — `go get` directly, then `just test` + `just cross-build`.

---

## Where to look for what

| Question | File |
|---|---|
| Request → principal (all auth methods) | `auth/auth.go::authenticate` + `try*` |
| ed25519 challenge/response nonce | `auth/challenge.go` (stateless HMAC + TTL) |
| Per-database capability enforcement | `authz/authz.go::Policy.Level` + `httpapi/{handler,native,hrana}.go` |
| Open-mode decision | `serverd/serverd.go::buildPolicy` |
| Hrana pipeline / baton sessions | `httpapi/hrana.go::handlePipeline` + `session/session.go` |
| Hrana streamed cursor (NDJSON batch) | `httpapi/hrana_cursor.go::handleCursor` |
| Native single-statement endpoint | `httpapi/native.go` |
| Backend dispatch | `backend/backend.go::For` |
| Vault (encryption + compression) options | `backend/vault.go::newVault` (raw-key / recipient / authenticated-writer) |
| Config schema + validation | `config/config.go` + `config/load.go::Validate` |
| Pragmas / pool per database | `backend/backend.go::pragmas` |
| Secret resolution ("source:name") | `secret/secret.go` |
| The database/sql driver + DSN | `client/sqldriver/driver.go` (`OpenConnector` / `OpenConnectorClient`) |
| Client transports + auth options | `client/client.go` (H1/H2C/H2TLS/H3/Unix, With*) |
| Batch + interactive streams | `client/hrana.go` (`Batch`, `OpenStream`) |
| Control plane (create/detach/maintenance) | `admin/admin.go` |
| Metrics / slow log | `obs/` |
| Limits (rate, concurrency, timeouts) | `limits/` |
| mTLS handshake (require vs verify-if-given) | `transport/tls.go::buildTLS` |

---

## Things that look broken but aren't

- **A read-only request borrows a dedicated connection** (`httpapi/native.go`) — that's the *enforcement* (`query_only` + authorizer), not waste; it's restored before the conn returns to the pool.
- **A batonless Hrana pipeline opens a session** even for a one-shot batch — `Batch` appends a trailing `close` so the session opens, runs, and tears down within the one POST (no leak).
- **The keyring client fetches `/_auth/challenge`** — but caches and reuses it within its window, so a burst pays it roughly once, not per request.
- **`../../sqlite` replaces** resolve correctly whether Go follows the `.quicsql` symlink or the real path — both sit two levels under the shared parent.
- **The daemon (`cmd/quicsql`) can't register custom SQL functions** — those need a custom `main()` calling `serverd.Run` (see `examples/charged-server`); a config file alone can't express Go code.

---

## Co-developing with gosqlite

quicSQL's `go.mod` pins **published** `gosqlite.org*` versions — no committed `replace` directives — so it builds and releases like any normal module and `go get quicsql.net` just works. quicSQL lives at the `.quicsql` symlink inside the gosqlite repo (→ its own checkout), the same arrangement as `.liteorm`. To work on quicSQL and gosqlite **together** (build against the sibling `../../sqlite` working tree instead of the published versions), run **`just codev`** — it writes a gitignored `go.work` overlay (`use . ../../sqlite …`); `just codev off` removes it. Keep the overlay local: never commit `go.work`, and don't add `replace` directives to `go.mod` (`release.yml` hard-gates on that). CI has no overlay, so it builds against the pinned published gosqlite — the released config. `just showcase` / `just studio` reach the sibling example modules via `../../sqlite/examples/…`.

## Last words

When in doubt, find an existing parallel — another transport case, another auth method, another backend — and mirror its shape. The pipeline is deliberately uniform.
