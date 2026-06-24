---
name: databases-and-backends
description: Use when choosing or configuring a database on a quicSQL server — picking a backend (file, in-memory, or an encrypted-and-compressed vault container), setting encryption/compression, tuning pragmas and the connection pool, or supplying key material via secret sources.
---

# Databases and backends

Each `databases:` entry maps a **name** (what clients address) to a **backend** (how it's stored). The backend is a server-side decision clients never see: the same query works against a plain file or an encrypted, compressed vault. Full narrative: the [databases guide](../../docs/databases.md).

## Pick a backend

| Backend | Persists? | Use for |
|---|---|---|
| `file` (default) | yes | ordinary durable databases |
| `memory` | no | scratch, private to one connection |
| `memory-shared` | no | fast ephemeral database shared across connections |
| `mvcc` / `memdb` | no | in-memory with MVCC / plain in-memory VFS |
| `vault` | yes | **encryption and/or compression at rest** |

Common fields: `path` (file/vault, relative to `data_dir` or absolute), `mode` (`rwc` default / `rw` / `ro`), `pragmas_preset: recommended` (WAL + busy_timeout + foreign_keys), a `pragmas:` override map, and `pool` (`max_open`, `tx_lock`, `busy_timeout`). All are server-owned — a client can't change connection config over the wire.

## Vault: encryption + compression

A vault is a single-file container that compresses and/or encrypts a database at rest. Two independent knobs plus a key:

```yaml
secrets:
  - { name: keys, type: file, dir: /etc/quicsql/secrets }   # keys:<name> → that file
databases:
  - name: catalog
    backend: vault
    path: catalog.vault
    vault:
      compression: best      # none | fastest | fast | default | better | best  (LZ4 → zstd)
      cipher: adiantum       # adiantum (default, 32-byte key) | aes-xts (64-byte key)
      key: keys:catalog      # RAW-KEY mode — one symmetric key opens and writes
```

Generate the raw key: `openssl rand -out /etc/quicsql/secrets/catalog 32` (adiantum) — the file's bytes *are* the key.

**Recipient mode** (public-key, multi-holder) instead of a shared secret: provision with `create.recipients` (public keys) and open with `identities` (private keys). Raw-key and recipient modes are mutually exclusive.

```yaml
    vault:
      compression: best
      identities: [ keys:catalog_a ]          # OPEN with this private key
      create:
        recipients: [ keys:catalog_a.pub ]    # who may unwrap the NEW container
```

(`ssh-keygen -t ed25519 -f catalog_a` → `catalog_a` = identity, `catalog_a.pub` = recipient.) For authenticated writes, membership signing (`masters`/`sign_with`/`writers`/`write_as`), a rollback anchor, and create-time geometry, see the [databases guide](../../docs/databases.md).

## Secrets

Any key field is a `source:name` reference resolved at startup from a `secrets:` source — `type: file` (a filename in `dir`) or `type: env` (an env var). A `key` is raw bytes; identities/recipients are SSH keys. Plaintext never lives in the config.

## Grants

Every database takes `grants:` (who may read/write/administer it) — that's authorization, in the `auth-and-tls` skill.
