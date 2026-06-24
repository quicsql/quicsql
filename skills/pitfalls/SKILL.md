---
name: pitfalls
description: Use when debugging surprising behaviour with quicSQL, or as a pre-ship checklist — h3/QUIC through Docker, the keyring per-request cost, open-mode exposure, read-only enforcement, Hrana session leaks, credentials a DSN can't carry, and the canonical port.
---

# quicSQL pitfalls

Surprises that are actually deliberate, and the ones that bite before shipping.

## Connectivity

- **h3/QUIC times out while h2 works.** h2 is TCP (7777); **h3 is QUIC over UDP on the same port (7777)**. `timeout: no recent network activity` means UDP isn't completing the round trip. Two causes: a container `-p 7777:7777` publishes *TCP* only — you need both `-p 7777:7777 -p 7777:7777/udp`; and **Docker Desktop on macOS/Windows** doesn't reliably forward QUIC even with `/udp`. The same binary serves h3 fine run natively or in Docker on Linux. It's an environment issue, not a server bug.
- **Cleartext carries credentials in the clear.** `h1`/`h2c` send a bearer token or password unencrypted. Use them only on loopback or a trusted socket; put anything networked behind TLS.
- **Canonical port is 7775** (h1), sequencing up (h2c 7776, h2 7777); **h3 shares 7777** (QUIC/UDP alongside h2's TCP, as HTTPS shares :443). Don't invent 78xx placeholders.

## Auth

- **A DSN can't carry mTLS or the keyring.** `quicsql://…?token=` and `?user=&password=` work; a client certificate and an ed25519 key do not. Build a `*client.Client` and use `sqldriver.OpenConnectorClient`.
- **Open mode is a foot-gun off localhost.** Configure *zero* principals and *zero* grants and every database is publicly read-write — the server logs a loud warning. Add one principal or grant and it flips to grants-decide-default-none. Never expose open mode to a network.
- **The keyring costs an extra round trip per request** (it fetches a challenge to sign). It's cached within a window so a burst pays it ~once, but for high-volume key-based auth prefer **mTLS** (zero per-request cost), or **batch** your statements so N share one authentication.
- **A verified client cert that maps to no principal is rejected** (401), and a present-but-wrong credential is never downgraded to anonymous. That's intentional.

## Sessions and writes

- **Always `Close` a Hrana stream** (`defer st.Close(ctx)`), or its pinned connection lingers until `tx_idle_timeout`. A climbing `quicsql_active_sessions` gauge means a missing close.
- **`Batch` is not atomic** — a failing statement doesn't roll back earlier ones. Wrap in `BEGIN`/`COMMIT` or use `OpenStream` for all-or-nothing.
- **Read-only really means read-only.** A read-only principal's connection runs `query_only` + a write-denying authorizer, so a write is refused by the engine even inside a `WITH` clause or a transaction — you can't talk past it from the client.
- **SQLite has one writer.** Keep write transactions short; do reads outside them. `max_write_sessions_per_db` caps concurrent writers rather than queueing them unboundedly.

## Config

- **The daemon can't register a custom SQL function** — that needs a custom `main()` calling `serverd.Run` (see `examples/charged-server`). A YAML config can't express Go code.
- **`pragmas_preset: recommended`** (WAL + busy_timeout + foreign_keys) is off by default — set it on anything doing real work.
- **Grants reference declared principals.** A grant to a principal you never defined fails validation at startup (a `*` wildcard is the exception).

## Pre-ship checklist

TLS on every networked listener · a real principal per client (not open mode) · least-privilege grants per database · `pragmas_preset: recommended` on durable DBs · vault key backed up in your secret manager · limits set (`per_principal_rps`, `tx_idle_timeout`, `statement_timeout`) · `expand_params` left off so params stay redacted · streams closed on every path.
