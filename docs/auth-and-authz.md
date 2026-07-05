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
                        │  accepts auth methods: [mtls, bearer, ...]  │
                        └───────────────────┬─────────────────────────┘
                                            │
                         ┌──────────────────▼───────────────────┐
                         │  AUTHENTICATION middleware           │
                         │  try each accepted method in order;  │
                         │  attach a Principal (or Anonymous)   │
                         └──────────────────┬───────────────────┘
                                            │  principal = "analyst"
                         ┌──────────────────▼───────────────────┐
                         │  HANDLER + AUTHORIZATION policy      │
                         │  level = policy.Level(principal, db) │
                         │  read needs ≥ read-only,             │
                         │  write needs ≥ read-write,           │
                         │  admin ops need admin                │
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

### The seven methods

| Method | The client presents… | The server stores… | Good for |
| --- | --- | --- | --- |
| `none` | nothing | nothing | local dev; a deliberately public read replica (with a wildcard grant) |
| `peercred` | *(nothing — the OS vouches)* | a Unix `uid` → principal | same-machine processes over a Unix socket |
| `bearer` | `Authorization: Bearer <token>` | `hex(sha256(token))` | services, scripts, CI |
| `password` | HTTP Basic `user:password` | a bcrypt hash | humans, `psql`-style tooling |
| `mtls` | a client TLS certificate | the cert's subject CN, or a hash of its public key | strong service identity, zero shared secrets |
| `keyring` | an ed25519 signature over a server challenge | an `ssh-ed25519` public key | reusing the same key that unlocks a vault; SSH-style key rosters |
| `session` | `Authorization: Bearer qs_…` (a token minted at `/_auth/session`) | nothing (self-contained token, HMAC-verified) | browsers, short-lived jobs — a bounded, revocable stand-in for a long-lived credential ([below](#session-tokens-short-lived-revocable-credentials)) |

Two properties are worth internalizing:

**The server never stores your secret in the clear.** For `bearer` it stores only `sha256` of the token; for `password` only a bcrypt hash. You compute the hash once when you write the config (or point it at a secret source) and hand the *raw* token/password to the client. A leaked config does not leak usable credentials. `mtls` and `keyring` are even stronger: they store only public material (a certificate subject or a public key), and the private half never leaves the client.

**A wrong credential is rejected, never downgraded.** If a listener accepts `bearer` and a request arrives *with* a `Bearer` header that does not match, the request is denied — it does **not** silently fall back to anonymous. This is the "hard method" rule: presenting a credential is a claim, and a failed claim is a `401`. The methods are tried in priority order `mtls → keyring → session → bearer → password`; the first one whose credential is *present* decides the outcome (`session` and `bearer` share the `Authorization` header — the `qs_` token prefix routes a value to exactly one of them). Two "soft" cases fall through instead of failing: an unmapped Unix `peercred` uid, and a CA-verified client certificate that maps to no principal (so a client with a general-purpose mTLS identity can still authenticate via `bearer`/`keyring` on a listener that accepts them — on an `mtls`-only listener nothing else matches, so it still ends in a `401`). `none` is the terminal fallback that yields the anonymous principal.

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
  │ ─────────────────────────────────────────────▶    │  mint a challenge:
  │                                                   │  base64url( nonce ‖ expiry ‖ HMAC(nonce ‖ expiry) )
  │  { "challenge": "…" }                             │  (no server-side state saved)
  │ ◀─────────────────────────────────────────────    │
  │                                                   │
  │  sign challenge‖method‖path‖query (ed25519)       │
  │  POST /app/query                                  │
  │    X-Quicsql-Key:       ssh-ed25519 AAAA…         │
  │    X-Quicsql-Challenge: <the challenge>           │
  │    X-Quicsql-Signature: <base64 signature>        │
  │ ─────────────────────────────────────────────▶    │  1. re-check the challenge's HMAC + expiry
  │                                                   │  2. look up the key → principal
  │                                                   │  3. verify the signature over challenge‖method‖path‖query
  │  result                                           │
  │ ◀─────────────────────────────────────────────    │
```

The challenge carries its own expiry and a keyed HMAC, so the server can validate it purely by recomputing the HMAC — it keeps no list of outstanding challenges. The HMAC key is random per process, so a challenge minted before a restart is refused after it (fail-closed). The signature is computed over the challenge **bound to the request's method, path, and raw query string**, so a captured signature cannot be replayed onto a different request — not onto a more privileged method or path, and not onto a different operation target expressed in the query (a signature captured for `?id=42` cannot be re-aimed at `?id=99`, nor a `?store=` swapped underneath it). Concretely, the signed input is the four fields joined by newlines — `challenge\nmethod\npath\nrawQuery` (`path` is the URL path, `rawQuery` the undecoded query string and empty when absent) — so a third-party client must join with `"\n"`, not bare concatenation. The challenge's short lifetime further bounds how long even the *identical* request could be replayed. Because the binding is per request — not per challenge — the client still caches and reuses one challenge across a burst of requests, signing each one separately. The client library does the whole dance for you before each request; you just supply the key.

Keep the keyring method on a TLS or Unix-socket listener. The query binding stops cross-target replay, but the request **body is deliberately not signed** — bodies stream (a blob write can be gigabytes), so neither side can pre-hash them. That leaves one residual vector, and only over cleartext: on an `h1`/`h2c` listener an observer sees the signature and can replay it onto the *same* method, path, and query with a *different* body — say a different statement to the same `/app/query` — for as long as the challenge lives, since the challenge is **not single-use**. Over TLS the signature never reaches the wire, so the vector closes. quicSQL therefore does not *forbid* keyring-over-cleartext (an operator may knowingly run it on a trusted network) but **warns loudly at startup** whenever a keyring method is bound to a cleartext listener — read that warning as "move this to TLS or a Unix socket."

### Session tokens: short-lived, revocable credentials

Some clients shouldn't hold a long-lived secret at all — a browser tab (where anything stored is one XSS away from leaking), a batch job, a support script. The `session` method lets such a client trade a *real* credential for a **short-lived, revocable token** once, then carry only the token:

```yaml
auth:
  session: { enabled: true, idle_ttl: 15m }   # idle_ttl defaults to 15m; max_ttl 0 ⇒ non-renewable
listeners:
  - { name: h2, transport: h2, address: 0.0.0.0:7777, tls: main, auth: [password, keyring, session] }
```

```
POST /_auth/session          (authenticated with any OTHER method: password, keyring, bearer, mtls, peercred)
  → { "token": "qs_…", "expires_at": "2026-07-04T18:00:00Z", "principal": "app" }

…then, on every request:      Authorization: Bearer qs_…

DELETE /_auth/session         (with the token in Authorization) → 204, token revoked
```

Properties worth knowing:

- **A token is a stand-in, not an upgrade.** It authenticates as the same principal that minted it, with the same grants. The anonymous principal cannot mint one (there is no identity for the token to represent).
- **A token cannot mint its successor.** The mint path deliberately refuses session-token authentication, so a leaked token dies with its TTL instead of living forever through self-renewal. When it expires, the client re-authenticates with the real credential and mints a new one.
- **Revocation is self-service, and cuts the whole session.** `DELETE /_auth/session` presenting *any* token in the session invalidates it immediately — a logout button, or cleanup at the end of a job. Every token in a renewal chain shares one session id, so this also revokes the tokens earlier renewals issued (see the sliding bullet): the session dies no matter which token the client happens to hold.
- **Stateless, like challenges and batons.** The token carries its own expiry and an HMAC under a random per-process key; the server keeps no per-token state except the revocation set. A server restart invalidates every outstanding token — fail-closed, and clients just re-mint.
- **Optionally sliding ("extend on use").** By default a token dies at `idle_ttl` and cannot be renewed — a leaked one can't outlive it. Set `max_ttl` to make tokens **renewable**: an *active* session slides forward while a still-idle one lapses at `idle_ttl`, but no renewal ever crosses `max_ttl` from the first mint, so the whole chain stays bounded. Two knobs, two timers: `idle_ttl` is the idle window, `max_ttl` is the absolute ceiling (must be ≥ `idle_ttl`). For a renewable token the mint/renew JSON also returns `max_expires_at` — that absolute ceiling — alongside `expires_at`. Renewal happens **transparently** — a request whose token is past the halfway point of its idle window gets a freshly-extended token back in an `X-Quicsql-Session` response header (its new expiry in `X-Quicsql-Session-Expires`), which `@quicsql/client` adopts automatically (fire `onSessionRenewed` to re-persist it) — or **explicitly** via `PUT /_auth/session` (`client.renewSession()`). This is opt-in precisely because it trades some of the "dies at `idle_ttl`" guarantee for convenience: pick `max_ttl` to bound a leaked token's blast radius. **Revocation still covers the whole session:** every token a renewal chain produces shares one session id, and `DELETE` on any of them revokes them all — so logging out with the token in hand also kills an earlier, possibly-leaked one. The session id lives inside the token (it is not server state beyond the small revocation set), so this holds without the server tracking sessions.
- **The endpoint follows the listener.** `/_auth/session` exists only on listeners whose `auth:` list includes `session`, and tokens only authenticate there. Minting on one listener and using the token on another works when both accept `session` — handy for "mint over the Unix socket, use over h2".
- **It is still a bearer secret.** Anyone holding the token is the principal until expiry or revocation. Serve it over TLS (the cleartext startup warning covers `session` like `bearer`), and keep the TTL short — that bounded lifetime is the whole point.
- **The `qs_` prefix is reserved.** On a listener accepting both `session` and `bearer`, an `Authorization: Bearer qs_…` value is always routed to the session method. Do not mint a *static* bearer token that begins with `qs_` — it would be treated as a (failed) session token and rejected, never reaching the bearer check. Any other prefix is fine.

### Device enrollment: self-service principals for public apps

A public client — a browser app with no backend, a fleet of devices — can't ship a credential, because anything in a public bundle is public. Enrollment inverts the flow: the client *generates* an ed25519 keypair on first run (in a browser, a non-extractable WebCrypto key) and registers the **public** half at `POST /_auth/enroll`, proving possession by signing a fresh challenge exactly like keyring auth. The server mints a principal with a **server-assigned name** (`u_<key-hash>` — never client-chosen, so nobody enrolls themselves as `admin`) and applies exactly the configured grants template:

```yaml
control_plane: { enabled: true, admins: [ops] }   # required: the enrolled set lives in the meta store
auth:
  enroll:
    enabled: true
    policy: token                                  # default; `open` admits any key holder (dev/demo)
    tokens: ["keys:join_code_hash"]                # hex(sha256(token)) or secret refs, like bearer
    max_principals: 1000                           # hard cap (default 1000)
    rate_per_ip: 0.1                               # sustained enrolls/sec per IP, burst 3 (default ≈6/min)
    grants:
      - { db: appdb, level: read-write }           # the ONLY grants an enrollee gets; never admin
listeners:
  - { name: h2, transport: h2, address: 0.0.0.0:7777, tls: main, auth: [keyring, session] }
```

The endpoint lives on keyring-accepting listeners (an enrolled key authenticates via `keyring` afterward). The request carries the same `X-Quicsql-*` header triple as keyring auth — key, challenge, signature over the request binding — plus, under `policy: token`, a body of `{"enroll_token": "…"}`. Responses: `200 {"principal": "u_…", "created": true}`; re-enrolling the same key is **idempotent** (`created: false`, same principal — a reinstalled app doesn't multiply identities); `401` for a failed possession proof, `403` for a bad enrollment token, `429` when the per-IP rate or the `max_principals` cap says no. Every outcome, including denials, is audited.

Three deliberate design points. **Enrollment refuses to exist on an open-mode server** — config validation demands explicit auth first, so registering the first dynamic principal can never be the event that flips enforcement on mid-flight. **Config identities always win**: an enrolled key can never shadow an operator-defined principal. **The grants template is the authorization truth** — it is re-applied from config at every startup, so changing the template in YAML re-scopes every enrollee on restart; the meta store only remembers *who* enrolled, never what they may do. Operators manage the enrolled set at [`/_admin/principals`](administration.md) (list, delete — deletion revokes the key and every grant at once).

#### A database per user

The `grants` template above puts every enrollee into *shared* databases. For a public app where users must **not** see each other's data, add a `provision` block: each enrollee gets their **own** database, created at enroll time and granted only to them.

```yaml
auth:
  enroll:
    enabled: true
    provision:
      enabled: true
      name_template: "{principal}"   # {principal} → the u_<hash> name; MUST appear (else users collide)
      backend: vault                 # default vault (encrypted at rest); file | memory-shared | mvcc | memdb
      vault: { key: keys:userdb }    # shared key ⇒ encryption at rest; isolation is by grant, not by key
      level: read-write              # the enrollee's grant on their own db (never admin)
      max_bytes: 104857600           # per-db size cap (PRAGMA max_page_count); 0 = no cap
      on_revoke: keep                # keep (default — data preserved) | drop (detach + delete the file)
```

The per-user database is a first-class persisted database (it survives restart, and its owner-grant reloads with it), so nothing special happens at startup — it is served like any seed. Everything a use-case might vary is a knob with a **safe default**: `on_revoke` defaults to **`keep`** (deleting an enrollee never destroys data — re-enrolling the same key restores access to the same database), the backend defaults to an **encrypted vault**, and there is no size cap unless you set `max_bytes`. Provisioning is part of the enroll transaction: if the database can't be created, the whole enrollment is rolled back, so a principal is never left without the database it was promised. (The shared `grants` template and per-user `provision` can be used together — a user gets both shared grants and their own database.)

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

- A **server-admin** is a principal named in `control_plane.admins`. Server-admins may run the control plane against *any* database: create and detach databases at runtime, list them, list databases and sessions, kill a session, and run vault maintenance — the `compact` (offline), `compact_online` (the online reclaim), `trim`, and `snapshot` ops. These operations live under `/_admin` (admin-only).
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

- **Cleartext transports (`h1`, `h2c`) carry credentials in the clear.** A bearer token or password sent over plain HTTP is visible to anyone on the path. Use them only on loopback or a trusted local socket. For anything crossing a network, put the listener behind a TLS profile (`h2`, `h3`). The server does not forbid this, but it **warns loudly at startup** whenever a cleartext listener accepts a secret-bearing method (`bearer`, `password`, `session`, or `keyring`) — a nudge to move that port to TLS. `keyring` gets its own, sterner warning: a cleartext keyring signature is not merely exposed but replayable within the challenge's lifetime (see the challenge walkthrough above). `mtls`, `peercred`, and `none` send no wire secret and are not flagged.
- **mTLS is both transport and identity.** When a listener has a `client_ca` in its TLS profile and lists `mtls`, the client's certificate is verified against that CA (transport-level trust) *and* mapped to a principal by its subject CN or public-key hash (identity). A certificate that verifies against the CA but maps to no principal is rejected — trust and identity are checked independently. Alongside other methods, the client cert is optional, so bearer/keyring clients can still connect to the same port.
- **`peercred` only exists on Unix sockets.** It reads the connecting process's user id from the kernel — there is no network equivalent, so it is same-machine only and never part of a remote story.

A common, solid layout: a public TLS listener (`h2`/`h3`) accepting `mtls`, `bearer`, `keyring`, and `password`; a loopback cleartext listener (`h1`) for local health checks and admin scripts; and a Unix socket with `peercred` for co-located processes.

### Browsers and CORS

A browser page from another origin cannot call quicSQL at all until the server opts in — browsers first send a credential-less `OPTIONS` *preflight*, and without approval headers the real request never happens. Enable the `cors:` block to serve browser apps:

```yaml
cors:
  enabled: true
  origins: ["https://app.example.com"]   # exact-match page origins; default "*" when omitted
  allow_headers: []                       # extra request headers to permit, added to the built-in
                                          #   Authorization / Content-Type / X-Quicsql-* set
  expose_headers: []                      # extra response headers scripts may read; the session
                                          #   headers (X-Quicsql-Session, -Session-Expires) are already exposed
  max_age: 2h                             # how long the browser may cache the preflight (default 2h)
```

The preflight is answered **before** authentication (it carries no credential by design — a `401` there would kill every cross-origin call), while the actual request still authenticates normally; CORS approval is never an authorization grant. The approved request headers include `Authorization` and the `X-Quicsql-*` keyring trio, so `bearer`, `session`, `password`, and `keyring` all work from a browser (`mtls` does not — browsers give scripts no client-certificate control). The `origins` list is matched exactly. A `"*"` origin is **refused at startup unless authentication is configured**: with no principals or grants the server is in open mode, and a wildcard origin would let *any* web page read and write an unauthenticated database — so the wildcard is only permitted once each request must present a credential of its own. When auth is configured, `"*"` is otherwise safe (quicSQL's header-based credentials are not cookie-style "credentials" to the browser), but narrow it when you can. Only the two session headers are exposed by default — add anything else your scripts read to `expose_headers`. Pair CORS with a TLS listener: pages on HTTPS can call `http://localhost` during development, but any non-localhost cleartext listener is blocked as mixed content.

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

#### The DSN refuses to leak a credential

A DSN is often a single opaque string handed to a library — `sql.Open("quicsql", dsn)`, or an ORM's `Open(dsn)` — so the driver treats a credential inside it as something it must not put on a readable wire carelessly. Two rules are **hard errors** (they fail the `sql.Open`/first connection, they are not warnings):

- **A credential over a cleartext or unverified channel is refused.** If the DSN carries a `?token=` or `?user=` and the transport is cleartext (`transport=h1` or `h2c`), or is `h2`/`h3` with `insecure=1` (TLS with certificate verification turned off, so a man-in-the-middle can read it), the open fails rather than sending the secret in the clear. Override it deliberately with `allow_insecure_auth=1` for a trusted local or dev link; a `unix` socket is local and never triggers the guard.

  ```
  quicsql://host:7775/app?transport=h1&token=SECRET                        → error  (cleartext)
  quicsql://host:7777/app?transport=h2&insecure=1&user=a&password=b        → error  (unverified TLS)
  quicsql://host:7775/app?transport=h1&token=SECRET&allow_insecure_auth=1  → allowed (you asked for it)
  quicsql://host:7777/app?transport=h2&token=SECRET                        → allowed (verified TLS)
  ```

- **URL userinfo is rejected outright.** A DSN written `quicsql://user:pw@host/app` is refused — the credential goes in the query params (`?user=&password=`), never in the `user:pw@host` position. Left alone, userinfo would send *no* credential at all (silently unauthenticated) *and* slip past the cleartext guard above, so the driver makes the mistake loud instead of silent.

The raw `*client.Client` constructors (`client.H1`, `H2C`, `H2TLS`, `H3`) apply the *same* transport check but only **warn**, they do not refuse: a caller reaching for the Go API chose both the transport and the credential explicitly, so the guard is advisory. The DSN path is stricter precisely because one opaque string hides those choices. (An mTLS client certificate — `WithClientCert` — is public material verified at the handshake, not a wire secret, so it triggers neither the refusal nor the warning.)

## Identity also scopes the rate limit

Because every request carries a principal, quicSQL uses that identity for more than access decisions. The per-principal rate limit (`limits.rate.per_principal_rps`) gives each principal its own token bucket, so one noisy client cannot starve the others, and the slow-query and audit logs record *who* ran what. Authentication is the hinge the rest of the safety rails hang on.

## What a client sees when it is denied

Failures are shaped like every other quicSQL error — a JSON envelope `{"error":{"message":"…"}}` — with a status code that tells you *which* layer said no:

| Status | Meaning | Typical cause |
| --- | --- | --- |
| `401 Unauthorized` | authentication failed | missing credential on a listener that requires one; a wrong token/password; a client cert that maps to no principal on an `mtls`-only listener; an expired challenge |
| `403 Forbidden` | authenticated, but not allowed | a read-only principal attempting a write; any principal touching a database it has no grant on; a non-admin hitting `/_admin` |

A `401` also carries a `WWW-Authenticate: Bearer, Basic realm="quicsql"` header. The rule of thumb: **`401` means "I don't know who you are," `403` means "I know who you are, and the answer is no."**

## Choosing methods: a short recommendation

- **Local development:** open mode (no auth) or a single `none` listener on loopback. Fast, zero setup — just never expose it.
- **Service-to-service on a network:** `mtls`. No shared secrets, strong identity, and the certificate encrypts the channel. Rotate by reissuing certificates.
- **Scripts, CI, cron:** `bearer`. One token per job, stored as a hash server-side, revoked by removing the principal.
- **Humans and interactive tools:** `password`. Familiar, works with anything that speaks HTTP Basic.
- **Reusing a vault key as a network identity, or SSH-style key rosters:** `keyring`. The same ed25519 key that unlocks a vault becomes the network principal; a roster file (`authorized_keys`) lets ops manage identities SSH-style, one key per line, the comment naming the principal.
- **Co-located processes over a Unix socket:** `peercred`. The kernel vouches for the peer's uid; no secret to manage at all.
- **Browsers and anything that shouldn't hold a durable secret:** `session`. Sign in once with a real credential, mint a short-lived token at `/_auth/session`, keep only the token in the page (plus `cors:` so the browser may call at all).

## Quick reference

**Auth method config keys** (each under a principal's `methods`):

| Method | Keys | Notes |
| --- | --- | --- |
| `bearer` | `token_hash` | hex sha256 of the token (or a `keys:` ref) |
| `password` | `user`, `password_hash` | bcrypt hash (or a ref) |
| `mtls` | `subject_cn` and/or `spki_sha256` | matched against the verified client cert |
| `keyring` | `ed25519` | an `ssh-ed25519 …` line; or list many in `auth.authorized_keys` |
| `peercred` | `uid` | numeric Unix user id; Unix-socket listeners only |

`session` has no per-principal keys — enable it server-wide with `auth.session: { enabled: true, idle_ttl: 15m }` (add `max_ttl` for renewable sliding sessions) and list it in a listener's `auth:`; tokens are minted at `POST /_auth/session` from any other credential, renewed at `PUT /_auth/session`, and revoked at `DELETE /_auth/session`.

**Levels:** `none` (default, no access) · `read-only` · `read-write` · `admin` (per-database admin; server-wide if the principal is in `control_plane.admins`). Effective level = **max(named grant, `*` wildcard grant)**; open mode overrides everything to read-write until you configure any principal or grant.

**Public endpoints (no auth):** `GET /_health`, and `GET /_auth/challenge` on keyring-accepting listeners. (`/_auth/session` exists on session-accepting listeners and `/_auth/enroll` on keyring-accepting listeners when enabled, but both prove identity inside their handlers; CORS preflights, when `cors:` is enabled, are answered pre-auth by design.)

**Secrets:** any hash/key field (`token_hash`, `password_hash`, `ed25519`, vault keys) may be inline or a `<source>:<name>` reference resolved at startup from a `secrets` source, so plaintext never needs to live in the config file. Three source types are supported: `env` (reads the named environment variable), `file` (reads `<dir>/<name>`, contained to `dir` — a `..` or absolute path that escapes is rejected), and `kms`, which execs an operator-provided `command` that wraps a real KMS (AWS KMS, GCP KMS, HashiCorp Vault Transit, `age`, …). The `kms` command runs with **no shell**, receives the reference name in `$QUICSQL_SECRET_NAME`, and must write exactly the key bytes to stdout (verbatim — use `printf`, not `echo`). This integrates any KMS without quicSQL linking a cloud SDK; a thin wrapper script is all it takes.

## Related guides

- [Configuring mTLS in production](mtls-production.md) — end-to-end certificate setup, CN vs public-key pinning, rotation, and the client wiring for the zero-per-request auth method.
- [Using Hrana in production](hrana.md) — transactions, batches, and the session model, including how auth (and the keyring challenge cost) behaves over the pipeline.
