# Configuring and using databases in quicSQL

One quicSQL server hosts **many databases**, each an entry under `databases:` in the config. Every entry maps a logical **name** — what clients address over the wire — to a **backend** that decides how the bytes are actually stored: a plain file, an in-memory database, or an encrypted-and-compressed `vault` container. This guide walks every backend with copy-pasteable config, then goes deep on the vault (encryption + compression at rest), pragmas and pool tuning, and how secrets are supplied.

The single most important idea: **the backend is a server-side decision that clients never see.** A client connects to a database by name — `POST /catalog/query`, or `quicsql://host/catalog` — and gets plain SQL results. Whether `catalog` is a plain file or an Adiantum-encrypted, zstd-compressed vault is invisible to it. You can change a database's storage without touching a line of client code.

## Every database shares these fields

```yaml
databases:
  - name: app                 # logical name clients address (unique; no path separators)
    backend: file             # file | memory | memory-shared | mvcc | memdb | vault
    path: app.db              # for file/vault: relative to server.data_dir, or absolute
    mode: rwc                 # rw | ro | rwc (default rwc = read, write, create-if-missing)
    pragmas_preset: recommended   # "" (bare SQLite) | recommended (WAL + busy_timeout + foreign_keys)
    pragmas: { cache_size: -20000 }   # optional overrides on top of the preset
    pool: { max_open: 8, tx_lock: immediate, busy_timeout: 5s }
    grants:                   # per-database authorization (see the auth guide)
      - { principal: analyst, level: read-only }
```

`name`, `backend`, and (for on-disk backends) `path` are the essentials; everything else has a sensible default. `mode`, `pragmas*`, and `pool` are explained in [Tuning any database](#tuning-any-database-pragmas--pool). `grants` are covered in the [auth & authz guide](auth-and-authz.md); the vault-only `vault:` block is [below](#the-vault-backend-encryption--compression).

## The backends at a glance

| Backend | Persists? | Shared across connections? | Use it for |
| --- | --- | --- | --- |
| `file` | yes (on disk) | yes (one file) | the default — ordinary durable databases |
| `memory` | no | no (one connection) | a scratch database private to a single connection |
| `memory-shared` | no | yes (shared cache) | a fast ephemeral database many clients share |
| `mvcc` | no | yes | in-memory with MVCC concurrency (readers don't block a writer) |
| `memdb` | no | yes | in-memory via the memdb VFS |
| `vault` | yes (on disk) | yes (single-owner) | **encryption and/or compression at rest** |

All the in-memory backends are **ephemeral**: their contents vanish when the handle closes or the server restarts. Only `file` and `vault` survive a restart.

## file — the default

A plain SQLite database file. This is what you get if you omit `backend` entirely. Put `pragmas_preset: recommended` on anything doing real work — it turns on WAL, a busy timeout, and foreign keys:

```yaml
databases:
  - name: app
    backend: file
    path: app.db            # → <data_dir>/app.db (or an absolute path)
    mode: rwc
    pragmas_preset: recommended
```

`mode: ro` opens it read-only (no writes reach the file regardless of grants); `rw` requires it to already exist; `rwc` (the default) creates it if missing.

## The in-memory family

Four backends keep the database in RAM. They differ in who can see it and how concurrency works:

```yaml
databases:
  - name: scratch
    backend: memory          # private to ONE connection; not shared across the pool
  - name: cache
    backend: memory-shared   # shared cache: every pooled connection sees the same rows
  - name: work
    backend: mvcc            # in-memory + MVCC — readers proceed while a writer commits
  - name: temp
    backend: memdb           # in-memory via the memdb VFS
```

Reach for `memory-shared` when you want a fast, throwaway database that several clients read and write together (a cache, a staging area). Plain `memory` is genuinely single-connection — useful mainly for isolated scratch work. `mvcc` is the pick when many readers must not block an occasional writer. Note that the in-memory VFS backends have no journal file, so a `journal_mode` you set is ignored (there is nothing on disk to journal).

## The vault backend — encryption + compression

A `vault` is a single-file container from `vfs/vault` that transparently **compresses and/or encrypts** a SQLite database at rest. The server is its sole owner (this daemon exists precisely so one process holds the container and fans clients into it), and clients talk to it exactly like any other database — the crypto happens entirely server-side, on the way to and from disk.

A vault has two independent knobs, `compression` and `cipher`, plus a `key` (or key set). Enable either, both, or neither:

```yaml
databases:
  - name: catalog
    backend: vault
    path: catalog.vault
    mode: rwc
    vault:
      compression: best      # none | fastest | fast | default | better | best
      cipher: adiantum       # adiantum (default) | aes-xts
      key: keys:catalog       # a secret reference (raw-key mode) — see below
```

### Compression tiers

The tier names *are* the algorithm/effort. Pick by your read/write mix and how compressible the data is:

| Tier | Algorithm | Character |
| --- | --- | --- |
| `none` | — | no compression |
| `fastest` / `fast` | LZ4 / LZ4-HC | cheap CPU, modest ratio — good for hot, write-heavy data |
| `default` / `better` / `best` | zstd (rising effort) | better ratio for more CPU — `best` for cold or archival data |

### Ciphers

`adiantum` (the default) is a fast, length-preserving cipher that needs no special CPU support — the portable choice, and what the examples use. `aes-xts` uses hardware AES; pick it when your servers have AES-NI and you prefer AES. The only config difference is the key length (below).

### Raw-key mode (the simplest encryption)

One symmetric key opens and writes the container. Generate a raw key of the cipher's length and store it where a [secret source](#supplying-secrets) can read it:

```sh
mkdir -p ./secrets
openssl rand -out ./secrets/catalog 32     # 32 bytes for adiantum (use 64 for aes-xts)
chmod 600 ./secrets/catalog
```

```yaml
secrets:
  - { name: keys, type: file, dir: ./secrets }   # keys:<name> → ./secrets/<name>

databases:
  - name: catalog
    backend: vault
    path: catalog.vault
    vault:
      compression: best
      cipher: adiantum
      key: keys:catalog                          # the raw key generated above
```

That is the whole recipe for an encrypted, compressed database. On first open the container is created with that key; on later opens the same key unlocks it. Lose the key and the data is unrecoverable — back it up in your secret manager.

### Recipient mode (public-key, multi-holder)

Instead of one shared secret, a vault can be locked to one or more **recipients** (public keys) and opened by whoever holds a matching **identity** (private key) — the age/SSH model. This is the right choice when several people or services should each open the container with their own key, and you never want a single shared secret to exist.

Generate an ed25519 keypair (the `.pub` is the recipient, the private file is the identity):

```sh
ssh-keygen -t ed25519 -f ./secrets/catalog_a -N '' -C catalog_a   # → catalog_a (identity) + catalog_a.pub (recipient)
```

A **new** container is provisioned from a `create:` block that lists the recipients who may unwrap it; an **existing** container is opened with an `identities` list:

```yaml
secrets:
  - { name: keys, type: file, dir: ./secrets }

databases:
  - name: catalog
    backend: vault
    path: catalog.vault
    vault:
      compression: best
      cipher: adiantum
      identities: [ keys:catalog_a ]        # used to OPEN an existing container (private key)
      create:                               # used only when the file does NOT yet exist
        recipients: [ keys:catalog_a.pub ]  # who may unwrap the new container (public keys)
```

To add a second holder, generate their keypair, add their `.pub` to `create.recipients` (at provisioning time), and give them their identity to list in `identities`. Raw-key mode and recipient mode are mutually exclusive — set `key` **or** `identities`, never both.

### Authenticated writes and membership signing (advanced)

For high-assurance deployments the vault can also **authenticate** its contents and cryptographically control who may change keyslot membership. These are optional and layer on top of either mode:

- `authenticate: true` — the container authenticates its pages (tamper-evidence), not just encrypts them.
- `create.masters` / `create.sign_with` — the trust anchors that sign keyslot membership, and the master key that signs the initial membership; open-time `masters:` lists the anchors to trust.
- `create.writers` + `write_as` — authenticated-writer mode: only holders of a writer identity may commit, and `write_as` is the identity the server signs commits with. Omit `write_as` on open to mount the container **read-only at rest**.
- `anchor: { type: file, path: … }` — a rollback-resistance anchor (an external monotonic counter) so a stale snapshot can't be silently swapped back.

```yaml
vault:
  cipher: adiantum
  authenticate: true
  identities: [ keys:catalog_a ]   # unwrap the container on open (private key)
  write_as: keys:writer            # this server signs commits as the writer
  masters: [ keys:master.pub ]     # trust this master as the membership signer (open)
  create:
    recipients: [ keys:catalog_a.pub ]
    masters:  [ keys:master.pub ]  # ed25519 public key
    sign_with: keys:master         # ed25519 private key that signs initial membership
    writers:  [ keys:writer.pub ]  # only these identities may write
```

Masters and writers are ed25519 SSH keys (a `.pub` line is the public half, the private file the signer). Start with raw-key or plain recipient mode; add authentication and writer control only when your threat model calls for it.

### Container geometry (create-time only)

When a vault is first provisioned you can set its on-disk geometry — larger blocks compress better for big, cold databases; smaller pages suit random-write workloads. These are honored **only** at creation and ignored on later opens:

```yaml
vault:
  key: keys:catalog
  create: { page_size: 8192, block_size: 65536, dir_segment_pages: 64 }
```

The defaults are fine for most databases — reach for these only when tuning a known workload.

### Maintenance

A vault reclaims space through the control plane (`/_admin`, admin only): offline **compact** (rewrite densely), online **reclaim** and **trim** (return freed blocks to the OS on the live handle), and **snapshot**. See the control-plane docs; grant a principal `admin` on the database (or make it a server-admin) to run these.

## Tuning any database — pragmas & pool

Two surfaces tune any backend, and both are **server-owned**: a client cannot change a connection's configuration over the wire.

`pragmas_preset: recommended` seeds the production baseline (WAL journal, a busy timeout, foreign keys on). The free-form `pragmas:` map then overrides individual settings on top of it:

```yaml
databases:
  - name: app
    backend: file
    path: app.db
    pragmas_preset: recommended
    pragmas:
      synchronous: NORMAL     # WAL + NORMAL is the usual durable-yet-fast combination
      cache_size: -20000      # ~20 MB page cache (negative = KiB)
      foreign_keys: true
    pool:
      max_open: 8             # max concurrent connections in the pool
      tx_lock: immediate      # BEGIN IMMEDIATE — take the write lock up front for write tx
      busy_timeout: 5s        # authoritative busy timeout (wins over a pragmas busy_timeout)
```

Recognized pragma keys include `journal_mode`, `synchronous`, `auto_vacuum`, `temp_store`, `foreign_keys`, `cache_size`, and `busy_timeout`; anything else is passed through as a raw pragma. `pool.busy_timeout` is the typed, authoritative timeout — prefer it over a `busy_timeout` in the pragmas map.

## Supplying secrets

Any key field on a vault (`key`, `identities`, `masters`, `write_as`, `create.recipients`, …) is a **`source:name` reference**, resolved at startup from a declared secret source — so raw key material never lives inline in the config:

```yaml
secrets:
  - { name: keys, type: file, dir: ./secrets }   # keys:<name> reads ./secrets/<name>
  - { name: env,  type: env }                     # env:<VAR> reads environment variable <VAR>
```

- `type: file` — `name` is a filename inside the source's `dir` (reads escaping the dir via `..` are rejected).
- `type: env` — `name` is an environment variable.

How the referenced bytes are interpreted depends on the field: a `key` is the **raw cipher key** (32 bytes for adiantum, 64 for aes-xts); an `identity` is an **OpenSSH private key** (or a passphrase); a `recipient` is an **authorized_keys public line** (or a passphrase); `masters`/`writers`/`sign_with`/`write_as` are **ed25519 SSH keys** (public line or private key). A broken reference fails at startup, not on first request. (The server's own encrypted meta store uses the same references — see the config for `meta_store.key`.)

## Using them — the client sees only the name

Because the backend is server-side, client code is identical no matter how a database is stored. The same call works against a plain file and an encrypted, compressed vault:

```go
c := client.H2TLS("db.example.com:7777", false, client.WithRootCA(pool), client.WithBearer(tok))

c.Query(ctx, "app",     "SELECT count(*) FROM users")   // a plain file database
c.Query(ctx, "catalog", "SELECT count(*) FROM parts")   // an Adiantum-encrypted, zstd-compressed vault
```

The vault's decryption and decompression happen on the server as it reads pages from disk; what crosses the wire is ordinary result data (protect *that* with TLS — see the [mTLS guide](mtls-production.md)). The `database/sql` driver and LiteORM are equally oblivious: they address a database by name and never know or care about its backend.

## A complete multi-backend server

Here is one server hosting three databases with three different storage strategies — an encrypted+compressed catalog, a durable file app database, and a shared in-memory cache — all reachable by name over the same listener:

```yaml
secrets:
  - { name: keys, type: file, dir: /etc/quicsql/secrets }

server:
  data_dir: /var/lib/quicsql

auth:                                # grants reference these principals — see the auth guide
  principals:
    - { name: analyst, methods: [ { bearer: { token_hash: "<sha256-of-token>" } } ] }
    - { name: app,     methods: [ { bearer: { token_hash: "<sha256-of-token>" } } ] }

databases:
  - name: catalog                    # encrypted + compressed at rest
    backend: vault
    path: catalog.vault
    mode: rwc
    vault: { compression: best, cipher: adiantum, key: keys:catalog }
    grants: [ { principal: analyst, level: read-only } ]

  - name: app                        # durable plain file, production pragmas
    backend: file
    path: app.db
    mode: rwc
    pragmas_preset: recommended
    pool: { max_open: 8, tx_lock: immediate, busy_timeout: 5s }
    grants: [ { principal: app, level: read-write } ]

  - name: cache                      # fast, ephemeral, shared
    backend: memory-shared
    grants: [ { principal: "*", level: read-only } ]
```

## Quick reference

**Backends:** `file` (default, durable) · `memory` (private, ephemeral) · `memory-shared` (shared, ephemeral) · `mvcc` / `memdb` (in-memory VFS, ephemeral) · `vault` (durable, encrypted and/or compressed).

**Vault modes:** raw-key (`key:`) **or** recipient (`identities:` + `create.recipients:`) — never both. Add `authenticate`, `masters`/`writers`/`sign_with`/`write_as`, and `anchor` for authenticated / writer-controlled / rollback-resistant containers.

**Compression:** `none` · `fastest`/`fast` (LZ4) · `default`/`better`/`best` (zstd). **Ciphers:** `adiantum` (32-byte key) · `aes-xts` (64-byte key).

**Modes:** `rwc` (default, create if missing) · `rw` (must exist) · `ro` (read-only at rest).

**Tuning:** `pragmas_preset: recommended` + a `pragmas:` override map + `pool` (`max_open`, `tx_lock`, `busy_timeout`) — all server-owned.

**Secrets:** declare `secrets:` sources (`file` with a `dir`, or `env`); reference material as `source:name`. A `key` is raw bytes; identities/recipients/masters are SSH keys.

## Related guides

- [Authentication & authorization](auth-and-authz.md) — the `grants` on each database, and who may read/write/administer it.
- [Configuring mTLS in production](mtls-production.md) — protecting the data in transit that a vault protects at rest.
- [Using Hrana in production](hrana.md) — transactions and batches against any of these databases.
