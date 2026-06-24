---
name: auth-and-tls
description: Use when securing a quicSQL server or presenting credentials from a client — configuring principals and auth methods (bearer, password, mTLS, ed25519 keyring, peercred), per-database grants and levels, TLS profiles, and mutual TLS. Covers both the server config and the client side.
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
