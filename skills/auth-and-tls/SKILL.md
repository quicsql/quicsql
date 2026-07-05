---
name: auth-and-tls
description: Use when securing a quicSQL server or presenting credentials from a client — configuring principals and auth methods (bearer, password, mTLS, ed25519 keyring, peercred, session tokens), per-database grants and levels, TLS profiles, mutual TLS, and CORS for browser apps. Covers both the server config and the client side.
---

# Auth and TLS

quicSQL separates three layers: **transport** (is the connection private — TLS), **authentication** (who are you — a principal), **authorization** (what may you do — a per-database level). Keep them distinct. Full narrative: the [auth guide](../../docs/auth-and-authz.md) and the [mTLS guide](../../docs/mtls-production.md).

## Authentication (server config)

A **principal** is a named identity that proves itself with one or more **methods**. Each listener declares which methods it accepts.

```yaml
auth:
  principals:
    - name: tourist
      methods:
        - bearer: { token_hash: "keys:tourist_token" }   # hex(sha256(token)) or a secret ref
        - mtls:   { subject_cn: tourist }                # or spki_sha256 to pin the key
    - name: analyst
      methods:
        - password: { user: analyst, password_hash: "keys:analyst_bcrypt" }   # bcrypt
    - name: signer
      methods:
        - keyring: { ed25519: "ssh-ed25519 AAAA… signer" }   # challenge/response
```

The server stores only hashes/public keys, never the raw secret. A **present-but-wrong credential is a 401** — never downgraded to anonymous. `peercred: { uid: 1000 }` works only on a Unix socket. `none` admits the anonymous principal.

The server **warns loudly at startup** (it does not refuse) when a cleartext listener (`h1`/`h2c`) accepts a secret-bearing method — `bearer`, `password`, `session`, or `keyring`; move that port to TLS or a Unix socket. `keyring` gets its own warning: a cleartext keyring signature is not just exposed but replayable within the challenge's lifetime (the challenge is not single-use), so cleartext voids its security model. `mtls`/`peercred`/`none` send no wire secret and are not flagged.

## Session tokens (short-lived credentials for browsers and jobs)

Enable server-wide, then list `session` on the listeners that should accept the minted tokens:

```yaml
auth:
  session: { enabled: true, idle_ttl: 15m }   # idle_ttl defaults to 15m; add max_ttl for renewable sliding sessions
listeners:
  - { name: h2, transport: h2, address: 0.0.0.0:7777, tls: main, auth: [password, session] }
```

`POST /_auth/session` with any **other** credential (password/bearer/keyring/mtls/peercred) returns `{token, expires_at, principal}`; use the `qs_…` token as `Authorization: Bearer` like any bearer token; `DELETE /_auth/session` (presenting the token) revokes it. A session token authenticates as the minting principal with the same grants, **cannot mint its successor**, and dies on server restart (per-process signing key, fail-closed). Anonymous cannot mint.

By default (`max_ttl` unset) a token dies at `idle_ttl` and is not renewable. Set `max_ttl` for a **sliding "extend on use"** session: an active session slides forward (transparently — the server returns an extended token in an `X-Quicsql-Session` header the SDK adopts — or explicitly via `PUT /_auth/session`), an idle one lapses at `idle_ttl`, and no renewal crosses `max_ttl` from the first mint (`max_ttl` ≥ `idle_ttl`). Opt-in: it trades some of the strict "dies at idle_ttl" bound for convenience.

## Device enrollment (self-service principals)

For public apps that can't ship a credential: the client generates an ed25519 keypair, proves possession by signing a challenge (same headers as keyring auth), and `POST /_auth/enroll` registers the public key as a new principal — server-assigned name `u_<key-hash>`, exactly the templated grants, never admin. Requires `control_plane.enabled` and explicit auth (refused on an open-mode server). Served on keyring-accepting listeners.

```yaml
auth:
  enroll:
    enabled: true
    policy: token                        # default; `open` for dev/demo
    tokens: ["keys:join_code_hash"]      # hex(sha256(code)) or secret refs
    max_principals: 1000                 # hard cap
    rate_per_ip: 0.1                     # ≈6/min per IP, burst 3
    grants: [{ db: appdb, level: read-write }]
```

Idempotent per key (`created: false` on re-enroll); denials are 401 (possession) / 403 (token) / 429 (rate or cap), all audited. Manage at `GET /_admin/principals` + `POST /_admin/principals/delete {"name"}` (server-admin only; delete revokes key + grants together). The grants template in YAML is the authorization truth — restart re-applies it to every enrollee.

## CORS (browser apps)

Off by default — without it a web page from another origin cannot call the server at all. Enable and allowlist the page origins (`"*"` allowed; exact match, no wildcards or paths):

```yaml
cors:
  enabled: true
  origins: ["https://app.example.com"]
```

Preflights (`OPTIONS`) are answered before auth (they carry no credential by design); actual requests still authenticate normally. `Authorization`, `Content-Type`, and the `X-Quicsql-*` keyring headers are pre-approved, so bearer/session/password/keyring all work from browsers; mTLS does not. Pair with session tokens so the page holds only a short-lived token.

## Authorization (per-database grants)

```yaml
databases:
  - name: app
    grants:
      - { principal: tourist, level: read-write }
      - { principal: analyst, level: read-only }
      - { principal: "*",     level: read-only }   # wildcard: everyone, incl. anonymous
```

Levels are ordered: `none < read-only < read-write < admin`. Effective level = **max(named grant, `*` grant)**. Unset = `none` (fails closed). Read-only is enforced by the engine (`query_only` + a write-denying authorizer), not by trusting SQL. **Open mode** (every principal read-write everywhere) applies only when you configure *zero* principals and *zero* grants — it logs a loud startup warning.

## TLS and mTLS

```yaml
tls:
  main:
    mode: files
    cert: /etc/quicsql/tls/server.crt
    key:  /etc/quicsql/tls/server.key
    client_ca: /etc/quicsql/tls/client-ca.crt   # enables mTLS: verifies client certs
    min_version: "1.3"
listeners:
  - { name: h2, transport: h2, address: 0.0.0.0:7777, tls: main, auth: [mtls, bearer] }
```

If `mtls` is a listener's **only** method, a valid client cert is mandatory (`RequireAndVerifyClientCert`); alongside other methods it's optional (`VerifyClientCertIfGiven`), so bearer clients still connect. A cert that verifies but maps to no principal is rejected. Certificate setup (two CAs, SANs, CN vs public-key pinning, rotation): the [mTLS guide](../../docs/mtls-production.md).

## Client side (presenting credentials)

```go
cl := client.H2TLS("host:7777", false, client.WithRootCA(pool),
    client.WithBearer(token))                    // or:
    // client.WithBasicAuth("analyst", pw)
    // client.WithClientCert(cert)               // mTLS
    // client.WithEd25519(pubLine, priv)         // keyring (challenge cached per window)
```

`false` = verify the server (never skip in production). A `database/sql` DSN can carry `?token=` or `?user=&password=`, but **not** mTLS/keyring — for those build a `*client.Client` and pass it to `sqldriver.OpenConnectorClient`. mTLS is the zero-per-request choice for key-based identity at volume.

The DSN driver guards credentials, with two **hard errors**: (1) a `?token=`/`?user=` DSN over cleartext (`transport=h1`/`h2c`) or unverified TLS (`h2`/`h3` with `insecure=1`) is **refused** — override with `allow_insecure_auth=1` for a trusted local/dev link (a `unix` socket is exempt); (2) URL userinfo (`quicsql://user:pw@host/db`) is **rejected** — credentials go in query params, never `user:pw@host`. The raw `client.H1/H2C/H2TLS/H3` constructors apply the same transport check but only **warn** (the caller chose transport + credential explicitly). An mTLS cert is public material, so it triggers neither guard.
