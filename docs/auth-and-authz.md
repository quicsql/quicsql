# Authentication & authorization in quicSQL

This guide explains, from the ground up, how quicSQL decides **who is talking to it** and **what they are allowed to do**. It is written for someone who has never read the code: by the end you should be able to look at a quicSQL config, know exactly what access each client has, and set up your own. Reference details for individual functions live in the Go package docs (`auth`, `authz`); this is the mental model and the worked examples that make those docs click.

## The one big idea: three independent layers

Every request that reaches a quicSQL database passes three checkpoints, and it helps enormously to keep them separate in your head. They answer three different questions and are configured in three different places.

| Layer | Question it answers | Configured by | Example |
| --- | --- | --- | --- |
| **Transport** | *Is the connection private?* | `listeners` + `tls` profiles | TLS, QUIC, a Unix socket |
| **Authentication** (authN) | *Who are you?* | `auth.principals` + each listener's `auth: [...]` | a bearer token, a client certificate |
| **Authorization** (authZ) | *What may you do to this database?* | `grants` on each database + `control_plane.admins` | read-only on `app`, admin on `catalog` |

They are independent. TLS encrypts bytes but never decides identity. Authentication turns a request into a named identity (a *principal*) but never decides access. Authorization maps that principal to a capability **per database**. A request must clear all three to touch data. Getting comfortable with quicSQL security is mostly a matter of not conflating these three.

The one method that spans two layers is **mutual TLS (mTLS)**: the client certificate both encrypts the channel (transport) and identifies the client (authentication). We will come back to that — it is a feature, not a contradiction.

## The life of a request

Here is what happens to a single request, start to finish:

```
                        ┌─────────────────────────────────────────────┐
   client request  ───▶ │  LISTENER (e.g. h2 on :7777, TLS)           │
                        │  accepts auth methods: [mtls, bearer, ...]   │
                        └───────────────────┬─────────────────────────┘
                                            │
                         ┌──────────────────▼───────────────────┐
                         │  AUTHENTICATION middleware            │
                         │  try each accepted method in order;   │
                         │  attach a Principal (or Anonymous)    │
                         └──────────────────┬───────────────────┘
                                            │  principal = "analyst"
                         ┌──────────────────▼───────────────────┐
                         │  HANDLER + AUTHORIZATION policy       │
                         │  level = policy.Level(principal, db)  │
                         │  read needs ≥ read-only,              │
                         │  write needs ≥ read-write,            │
                         │  admin ops need admin                 │
                         └──────────────────┬───────────────────┘
                                            │
                                allowed ────┴──── denied (401 / 403)
```

Two endpoints skip authentication entirely because they must be reachable before you have a credential: `GET /_health` (liveness) and `GET /_auth/challenge` (the nonce for the challenge/response method, and only on listeners that accept it). Everything else runs the full gauntlet.

## Layer 2: authentication — *who are you?*

### Principals and methods

A **principal** is a named identity — `analyst`, `tourist`, `ci-runner`. That is all it is: a name the rest of the system reasons about. A principal proves it is itself using one or more **methods**. You can give one principal several methods, and any one of them that matches logs the request in as that principal:

```yaml
auth:
  principals:
    - name: tourist
      methods:
        - bearer: { token_hash: "<sha256-of-the-token>" }
        - mtls:   { subject_cn: tourist }
```

Here `tourist` may present *either* a bearer token *or* a client certificate; both resolve to the same identity and therefore the same grants.

### The six methods

| Method | The client presents… | The server stores… | Good for |
| --- | --- | --- | --- |
| `none` | nothing | nothing | local dev; a deliberately public read replica (with a wildcard grant) |
| `peercred` | *(nothing — the OS vouches)* | a Unix `uid` → principal | same-machine processes over a Unix socket |
| `bearer` | `Authorization: Bearer <token>` | `hex(sha256(token))` | services, scripts, CI |
| `password` | HTTP Basic `user:password` | a bcrypt hash | humans, `psql`-style tooling |
| `mtls` | a client TLS certificate | the cert's subject CN, or a hash of its public key | strong service identity, zero shared secrets |
| `keyring` | an ed25519 signature over a server challenge | an `ssh-ed25519` public key | reusing the same key that unlocks a vault; SSH-style key rosters |

Two properties are worth internalizing:

**The server never stores your secret in the clear.** For `bearer` it stores only `sha256` of the token; for `password` only a bcrypt hash. You compute the hash once when you write the config (or point it at a secret source) and hand the *raw* token/password to the client. A leaked config does not leak usable credentials. `mtls` and `keyring` are even stronger: they store only public material (a certificate subject or a public key), and the private half never leaves the client.

**A wrong credential is rejected, never downgraded.** If a listener accepts `bearer` and a request arrives *with* a `Bearer` header that does not match, the request is denied — it does **not** silently fall back to anonymous. This is the "hard method" rule: presenting a credential is a claim, and a failed claim is a `401`. The methods are tried in priority order `mtls → keyring → bearer → password`; the first one whose credential is *present* decides the outcome. `peercred` is the one "soft" method — an unmapped Unix uid simply falls through — and `none` is the terminal fallback that yields the anonymous principal.

### Per-listener acceptance

Each listener independently declares which methods it will even consider, via its `auth: [...]` list. This is how you offer different security postures on different ports without running multiple servers:

```yaml
listeners:
  - { name: h2,  transport: h2,  address: 0.0.0.0:7777, tls: main, auth: [mtls, bearer, keyring, password] }
  - { name: h1,  transport: h1,  address: 127.0.0.1:7775,          auth: [bearer, none] }
  - { name: unix, transport: unix, address: ./quicsql.sock,        auth: [peercred, none] }
```

A method listed on a listener but not backed by any principal simply never matches. A listener with an empty (or absent) `auth` list admits the anonymous principal — the pre-auth "bind to localhost and trust the network" behavior.

### The keyring challenge/response, step by step

The `keyring` method deserves a closer look because it is the only interactive one, and it is elegantly stateless. It lets a client prove it holds an ed25519 private key **without ever sending it**, and without the server remembering anything between the two steps:

```
client                                             server
  │  GET /_auth/challenge                             │
  │ ─────────────────────────────────────────────▶   │  mint a challenge:
  │                                                   │  base64url( nonce ‖ expiry ‖ HMAC(nonce ‖ expiry) )
  │  { "challenge": "…" }                             │  (no server-side state saved)
  │ ◀─────────────────────────────────────────────   │
  │                                                   │
  │  sign the challenge with the ed25519 private key  │
  │  POST /app/query                                  │
  │    X-Quicsql-Key:       ssh-ed25519 AAAA…         │
  │    X-Quicsql-Challenge: <the challenge>           │
  │    X-Quicsql-Signature: <base64 signature>        │
  │ ─────────────────────────────────────────────▶   │  1. re-check the challenge's HMAC + expiry
  │                                                   │  2. look up the key → principal
  │                                                   │  3. verify the signature over the challenge
  │  result                                           │
  │ ◀─────────────────────────────────────────────   │
```

The challenge carries its own expiry and a keyed HMAC, so the server can validate it purely by recomputing the HMAC — it keeps no list of outstanding challenges. The HMAC key is random per process, so a challenge minted before a restart is refused after it (fail-closed). The short lifetime bounds how long a captured challenge+signature pair could be replayed. The client library does the whole dance for you before each request; you just supply the key.

### The anonymous principal

A request that authenticates via `none` (or an unmapped `peercred`) becomes **Anonymous** — a principal with an empty name. Anonymous is a real, first-class identity; it simply holds no *named* grants. It can still reach a database if that database has a wildcard grant (below) or if the server is in open mode. This is how you publish a deliberately public, read-only database without issuing anyone a credential.

## Layer 3: authorization — *what may you do?*

Authentication produced a principal. Authorization answers: given this principal and this database, what is allowed? The answer is one of four **levels**.

### The four levels

Levels are ordered, and each includes everything below it:

```
none  <  read-only  <  read-write  <  admin
 │         │            │             │
 │         │            │             └─ read + write + control-plane admin of THIS database
 │         │            └─ SELECT and data changes (INSERT/UPDATE/DELETE, DDL)
 │         └─ SELECT and other reads
 └─ no access at all (the safe default: an unset grant fails closed)
```

The zero value is `none`, which is deliberate: **if you never granted a principal access to a database, it has none.** Authorization fails closed.

### Grants: principal → level, per database

Access is expressed as **grants** attached to each database. A grant says "this principal has at least this level on this database":

```yaml
databases:
  - name: app
    backend: file
    path: app.db
    grants:
      - { principal: tourist, level: read-write }
      - { principal: analyst, level: read-only }
      - { principal: "*",     level: read-only }   # wildcard: everyone, including anonymous
```

The special principal `*` (**wildcard**) matches every principal, anonymous included. A named principal's **effective level is the maximum** of its own grant and the wildcard grant. So above: `tourist` gets read-write, `analyst` gets read-only, and *any other* authenticated identity — plus anonymous — gets read-only via the wildcard. Grants are per database, so the same principal can be admin on one database and have no access to another.

### Open mode: the localhost default

If you configure **no principals and no grants anywhere**, quicSQL starts in **open mode**: every principal (including anonymous) is read-write on every database. This preserves the friction-free "just run it on my laptop" experience. The server logs a loud warning at startup — *"no auth configured — every database is publicly read-write (open mode)"* — precisely because you never want this on a network. The moment you add a single principal or a single grant, open mode switches off and everything falls back to "grants decide, default none."

### Read-only is enforced by the engine, not by trust

A subtle but important point: quicSQL does **not** enforce read-only by parsing your SQL and hoping to catch every write. When a read-only principal runs a statement, the server borrows a dedicated connection, puts it in `query_only` mode and installs a write-denying authorizer inside SQLite itself for the life of that request, then restores it. A write attempt — even one smuggled inside a `WITH …` clause or a trigger — is refused *at the database engine*. The same holds for an interactive transaction: a read-only principal's session is pinned to a connection that is read-only for the whole stream. You cannot talk your way past it from the client.

### Admin and the control plane

`admin` is the top level, and it means two things depending on where it comes from:

- A **server-admin** is a principal named in `control_plane.admins`. Server-admins may run the control plane against *any* database: create and detach databases at runtime, list them, inspect stats and sessions, kill a session, and run vault maintenance (compact, reclaim, trim, snapshot). These operations live under `/_admin` (admin-only).
- A **per-database admin** is a principal holding an `admin`-level grant on a specific database. It may administer *that database only* — e.g. run vault maintenance on it — but cannot create or detach databases server-wide.

```yaml
control_plane:
  enabled: true
  admins: [tourist]        # tourist may create/detach/maintain ANY database
databases:
  - name: catalog
    grants:
      - { principal: analyst, level: admin }   # analyst may maintain `catalog`, nothing else
```

## How transport fits in

Transport and auth are separate layers, but they interact in ways worth stating plainly:

- **Cleartext transports (`h1`, `h2c`) carry credentials in the clear.** A bearer token or password sent over plain HTTP is visible to anyone on the path. Use them only on loopback or a trusted local socket. For anything crossing a network, put the listener behind a TLS profile (`h2`, `h3`).
- **mTLS is both transport and identity.** When a listener has a `client_ca` in its TLS profile and lists `mtls`, the client's certificate is verified against that CA (transport-level trust) *and* mapped to a principal by its subject CN or public-key hash (identity). A certificate that verifies against the CA but maps to no principal is rejected — trust and identity are checked independently. Alongside other methods, the client cert is optional, so bearer/keyring clients can still connect to the same port.
- **`peercred` only exists on Unix sockets.** It reads the connecting process's user id from the kernel — there is no network equivalent, so it is same-machine only and never part of a remote story.

A common, solid layout: a public TLS listener (`h2`/`h3`) accepting `mtls`, `bearer`, `keyring`, and `password`; a loopback cleartext listener (`h1`) for local health checks and admin scripts; and a Unix socket with `peercred` for co-located processes.

## A complete worked example

Here is a small but realistic config that uses every layer, followed by how a client presents each credential.

```yaml
secrets:
  - { name: keys, type: file, dir: ./secrets }     # keys:<name> reads ./secrets/<name>

tls:
  main:
    mode: files
    cert: ./tls/leaf.crt
    key:  ./tls/leaf.key
    client_ca: ./tls/ca.crt                         # enables mTLS

listeners:
  - { name: h2,   transport: h2,   address: 0.0.0.0:7777, tls: main, auth: [mtls, bearer, keyring, password] }
  - { name: local, transport: h1,  address: 127.0.0.1:7775,          auth: [bearer, none] }
  - { name: sock, transport: unix, address: ./quicsql.sock,          auth: [peercred, none] }

auth:
  authorized_keys: ./ops_keys              # optional SSH-style roster; each key's comment names its principal
  principals:
    - name: tourist
      methods:
        - bearer: { token_hash: "keys:tourist_token_sha256" }
        - mtls:   { subject_cn: tourist }
    - name: analyst
      methods:
        - password: { user: analyst, password_hash: "keys:analyst_bcrypt" }
    - name: signer
      methods:
        - keyring: { ed25519: "ssh-ed25519 AAAAC3Nza… signer" }

databases:
  - name: app
    backend: file
    path: app.db
    mode: rwc
    grants:
      - { principal: tourist, level: read-write }
      - { principal: analyst, level: read-only }
      - { principal: signer,  level: read-write }
  - name: public
    backend: file
    path: public.db
    grants:
      - { principal: "*", level: read-only }         # anyone, even anonymous, may read

control_plane:
  enabled: true
  admins: [tourist]

limits:
  rate: { per_principal_rps: 100 }                   # token bucket, scoped per principal
```

Read this the way the server does: `tourist` (bearer or mTLS) is read-write on `app` and a server-admin. `analyst` (password) is read-only on `app`. `signer` (an ed25519 key) is read-write on `app`. Everyone — named or anonymous — can read `public`. Nobody can write `public`. The token and password are stored only as hashes, pulled from files in `./secrets`.

### The matching client side

The client library (or the `database/sql` driver) presents credentials like this. Note the two that a URL **cannot** carry:

```go
import "quicsql.net/client"

// bearer over TLS (verify the private CA)
c := client.H2TLS("host:7777", false, client.WithRootCA(pool), client.WithBearer(rawToken))

// password over TLS
c := client.H2TLS("host:7777", false, client.WithRootCA(pool), client.WithBasicAuth("analyst", rawPassword))

// mTLS — the client certificate IS the identity
c := client.H2TLS("host:7777", false, client.WithRootCA(pool), client.WithClientCert(cert))

// keyring — the library fetches /_auth/challenge and signs it before each request
c := client.H2TLS("host:7777", false, client.WithRootCA(pool), client.WithEd25519(pubLine, priv))
```

Through the `database/sql` driver, a DSN can carry the two credentials expressible as text — `?token=<bearer>` or `?user=<u>&password=<p>` — but **mTLS and keyring cannot be written in a URL** (a certificate and a private key are not URL parameters). For those, build a `*client.Client` as above and hand it to `sqldriver.OpenConnectorClient`.

## Identity also scopes the rate limit

Because every request carries a principal, quicSQL uses that identity for more than access decisions. The per-principal rate limit (`limits.rate.per_principal_rps`) gives each principal its own token bucket, so one noisy client cannot starve the others, and the slow-query and audit logs record *who* ran what. Authentication is the hinge the rest of the safety rails hang on.

## What a client sees when it is denied

Failures are shaped like every other quicSQL error — a JSON envelope `{"error":{"message":"…"}}` — with a status code that tells you *which* layer said no:

| Status | Meaning | Typical cause |
| --- | --- | --- |
| `401 Unauthorized` | authentication failed | missing credential on a listener that requires one; a wrong token/password; a client cert that maps to no principal; an expired challenge |
| `403 Forbidden` | authenticated, but not allowed | a read-only principal attempting a write; any principal touching a database it has no grant on; a non-admin hitting `/_admin` |

A `401` also carries a `WWW-Authenticate: Bearer, Basic realm="quicsql"` header. The rule of thumb: **`401` means "I don't know who you are," `403` means "I know who you are, and the answer is no."**

## Choosing methods: a short recommendation

- **Local development:** open mode (no auth) or a single `none` listener on loopback. Fast, zero setup — just never expose it.
- **Service-to-service on a network:** `mtls`. No shared secrets, strong identity, and the certificate encrypts the channel. Rotate by reissuing certificates.
- **Scripts, CI, cron:** `bearer`. One token per job, stored as a hash server-side, revoked by removing the principal.
- **Humans and interactive tools:** `password`. Familiar, works with anything that speaks HTTP Basic.
- **Reusing a vault key as a network identity, or SSH-style key rosters:** `keyring`. The same ed25519 key that unlocks a vault becomes the network principal; a roster file (`authorized_keys`) lets ops manage identities SSH-style, one key per line, the comment naming the principal.
- **Co-located processes over a Unix socket:** `peercred`. The kernel vouches for the peer's uid; no secret to manage at all.

## Quick reference

**Auth method config keys** (each under a principal's `methods`):

| Method | Keys | Notes |
| --- | --- | --- |
| `bearer` | `token_hash` | hex sha256 of the token (or a `keys:` ref) |
| `password` | `user`, `password_hash` | bcrypt hash (or a ref) |
| `mtls` | `subject_cn` and/or `spki_sha256` | matched against the verified client cert |
| `keyring` | `ed25519` | an `ssh-ed25519 …` line; or list many in `auth.authorized_keys` |
| `peercred` | `uid` | numeric Unix user id; Unix-socket listeners only |

**Levels:** `none` (default, no access) · `read-only` · `read-write` · `admin` (per-database admin; server-wide if the principal is in `control_plane.admins`). Effective level = **max(named grant, `*` wildcard grant)**; open mode overrides everything to read-write until you configure any principal or grant.

**Public endpoints (no auth):** `GET /_health`, and `GET /_auth/challenge` on keyring-accepting listeners.

**Secrets:** any hash/key field (`token_hash`, `password_hash`, `ed25519`, vault keys) may be inline or a `<source>:<name>` reference resolved at startup from a `secrets` source (`env` / `file` / `kms`), so plaintext never needs to live in the config file.

## Related guides

- [Configuring mTLS in production](mtls-production.md) — end-to-end certificate setup, CN vs public-key pinning, rotation, and the client wiring for the zero-per-request auth method.
- [Using Hrana in production](hrana.md) — transactions, batches, and the session model, including how auth (and the keyring challenge cost) behaves over the pipeline.
