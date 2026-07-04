# Configuring mTLS in production

Mutual TLS (mTLS) is the strongest auth quicSQL offers and the one with **zero per-request cost**: the client proves its identity with a certificate at the TLS handshake, so there is no shared secret to leak, no token to rotate, and no extra round trip. This guide takes you from "no certificates" to a working, hardened mTLS deployment, with copy-pasteable commands and config. If you only want the concepts, read the [auth & authz guide](auth-and-authz.md) first; this is the hands-on production recipe.

## What you are building

mTLS involves four pieces. Keep them straight and the rest is mechanical:

```
   ┌─────────────┐   signs    ┌────────────────┐        trusts        ┌──────────────┐
   │  server CA  │ ─────────▶ │  server leaf   │ ◀─────────────────── │  the client  │  (client puts server CA in RootCAs)
   └─────────────┘            │  (SANs = the   │                      │              │
                              │   hostnames    │   presents its cert  │              │
                              │   clients dial)│ ◀─────────────────── │              │
   ┌─────────────┐   signs    └────────────────┘                      └──────────────┘
   │  client CA  │ ─────────▶  client certs  ────────────────────────────────▲
   └─────────────┘             (CN or key = the principal)                   │
        ▲                                                                    │
        └──────────── the server trusts this CA (client_ca) and maps ────────┘
                      each verified cert to a principal
```

- A **server CA** signs the server's leaf certificate. Clients trust this CA so they can verify they are talking to the real server.
- A **server leaf certificate** whose SANs list every hostname/IP clients will dial. This is standard TLS — it encrypts the channel and authenticates the *server* to clients.
- A **client CA** signs the client certificates. The server trusts this CA (`client_ca`) to decide which client certs are genuine.
- **Client certificates**, one per identity. The server maps each verified cert to a **principal** by its subject Common Name (CN) or by a hash of its public key.

The server CA and client CA **can be the same CA**, but in production they are usually separate: that way, being able to issue a client cert does not also let you mint a server certificate. This guide uses two CAs.

## Step 1 — create the two CAs

Any PKI works (your org's CA, `step-ca`, Vault, cfssl). Here it is with plain `openssl` and ECDSA P-256 keys, which every TLS client accepts:

```sh
# Server CA — signs the server leaf that clients verify.
openssl ecparam -name prime256v1 -genkey -noout -out server-ca.key
openssl req -x509 -new -key server-ca.key -sha256 -days 3650 -subj "/CN=quicsql server CA" -out server-ca.crt

# Client CA — signs client certs; the server trusts this to admit clients.
openssl ecparam -name prime256v1 -genkey -noout -out client-ca.key
openssl req -x509 -new -key client-ca.key -sha256 -days 3650 -subj "/CN=quicsql client CA" -out client-ca.crt
```

Guard the two `*-ca.key` files like root passwords — whoever holds the client CA key can mint an identity the server will trust (subject to a matching principal, see Step 4).

## Step 2 — the server leaf certificate

The leaf's **SANs must contain every name or address clients dial**, or their TLS verification fails. Include DNS names and any bare IPs:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=db.example.com" -out server.csr

cat > server.ext <<'EOF'
subjectAltName = DNS:db.example.com, DNS:*.db.internal, IP:203.0.113.10
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in server.csr -CA server-ca.crt -CAkey server-ca.key -CAcreateserial \
  -days 825 -sha256 -extfile server.ext -out server.crt
```

## Step 3 — a client certificate per identity

Give each identity its own key and certificate. The simplest mapping is **CN = the principal name**:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out analyst.key
openssl req -new -key analyst.key -subj "/CN=analyst" -out analyst.csr

cat > client.ext <<'EOF'
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in analyst.csr -CA client-ca.crt -CAkey client-ca.key -CAcreateserial \
  -days 90 -sha256 -extfile client.ext -out analyst.crt
```

Short client-cert lifetimes (weeks, not years) are good practice — rotation *is* your revocation story (see below). If you plan to pin the exact public key instead of the CN, compute its hash now:

```sh
openssl x509 -in analyst.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
# → the hex string you put in spki_sha256
```

## Step 4 — the quicSQL config

Now wire it together. The `tls` profile carries the server leaf and the client CA; the listener uses that profile and accepts `mtls`; each principal declares which certificate identifies it; grants say what each may do.

```yaml
tls:
  prod:
    mode: files
    cert: /etc/quicsql/tls/server.crt
    key:  /etc/quicsql/tls/server.key
    client_ca: /etc/quicsql/tls/client-ca.crt    # the server verifies client certs against THIS
    min_version: "1.3"                            # require TLS 1.3 in production

listeners:
  - name: h2
    transport: h2
    address: 0.0.0.0:7777
    tls: prod
    auth: [mtls]                                  # sole method → a valid client cert is MANDATORY

auth:
  principals:
    - name: analyst
      methods:
        - mtls: { subject_cn: analyst }           # map by certificate CN
    - name: reporting
      methods:
        - mtls: { spki_sha256: "3b0c…" }          # map by exact public key (pin)

databases:
  - name: app
    backend: file
    path: /var/lib/quicsql/app.db
    mode: rwc
    grants:
      - { principal: analyst,   level: read-write }
      - { principal: reporting, level: read-only }
```

Two behaviors decided by that `auth` list are worth understanding precisely:

- **`auth: [mtls]` (mTLS is the only method)** → the listener requires and verifies a client certificate on *every* connection. No cert, no connection. Use this for a locked-down service port.
- **`auth: [mtls, bearer, keyring]` (mTLS alongside others)** → a presented client cert is verified and, if it maps to a principal, authenticates the request; but clients using bearer or keyring may still connect *without* a cert. Use this when one port serves mixed client types.

Either way, verification and identity are checked independently: a certificate that chains to the trusted client CA but maps to **no principal** is rejected. The principal table is the real gate.

## CN pinning vs public-key (SPKI) pinning

You map a cert to a principal two ways, and the choice affects rotation:

| Map by | Config | Rotation | Trust model |
| --- | --- | --- | --- |
| **Subject CN** | `subject_cn: analyst` | Reissue a new cert with the same CN (new key is fine) and nothing in the config changes | Trusts your client CA to only issue the CNs you intend |
| **Public key hash** | `spki_sha256: "3b0c…"` | Rotating the keypair changes the hash, so you must update the config | Pins the exact key; even the CA cannot mint an accepted cert for a different key |

CN pinning is operationally friendlier (rotate certs without touching quicSQL). SPKI pinning is stricter and useful when you do not fully trust the CA's issuance process, or for a handful of high-value identities. You can mix both across principals.

## The client side (Go)

The client verifies the **server** against the server CA (`WithRootCA`) and presents its own **client** certificate (`WithClientCert`):

```go
import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"quicsql.net/client"
)

caPEM, _ := os.ReadFile("server-ca.crt")          // the CA that signed the SERVER leaf
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(caPEM)

cert, _ := tls.LoadX509KeyPair("analyst.crt", "analyst.key")  // THIS identity

c := client.H2TLS("db.example.com:7777", false,   // false = verify the server (never true in prod)
	client.WithRootCA(pool),
	client.WithClientCert(cert))
defer c.Close()
```

A DSN cannot carry a certificate and a private key, so the `database/sql` driver reaches mTLS by building this `*client.Client` and handing it to `sqldriver.OpenConnectorClient(c, "app")` — see the [Hrana guide](hrana.md) and the driver docs.

mTLS also sidesteps the driver's credential guards. Those guards refuse a text credential (`?token=`/`?user=`) sent over a cleartext or unverified channel — see [the auth guide](auth-and-authz.md) — but a client certificate is public material verified at the handshake, not a secret sent in a header, so it triggers neither the DSN refusal nor the raw-constructor warning. The one rule that still bites you here is the ordinary TLS one: keep `insecure=false` / never pass `true` to `H2TLS`/`H3`. mTLS proves the *client* to the server; verifying the server's own certificate is still your job, and skipping it hands the channel (and any data on it) to a man-in-the-middle.

## Testing from the command line

`curl` speaks mTLS, so you can validate the whole chain without writing code:

```sh
curl --cacert server-ca.crt --cert analyst.crt --key analyst.key \
  https://db.example.com:7777/app/query \
  -H 'content-type: application/json' \
  -d '{"sql":"SELECT 1"}'
```

A `401` means the cert verified but maps to no principal (or you omitted it on a mandatory-mTLS port); a TLS handshake error means the server CA or SANs are wrong.

## Production practices

- **Require TLS 1.3** (`min_version: "1.3"`). h3/QUIC listeners are 1.3 by definition.
- **Separate the client CA from the server CA**, so issuing client identities cannot also forge servers.
- **Short-lived client certs + rotation.** quicSQL verifies the chain and maps the identity; it does not consult CRLs or OCSP. So your revocation levers are, in order of speed: (1) **remove the principal** (or its `mtls` method) from the config and reload — a valid, unexpired cert becomes useless the instant no principal maps it; (2) rotate/renumber the **client CA** to invalidate everything it signed; (3) let short lifetimes expire. Design around (1): the principal table is your kill switch.
- **Rotating the server leaf** (files mode loads certificates at startup) needs a process restart. Do it as a rolling restart behind a load balancer for zero downtime. Keep the SANs stable so clients don't need changes.
- **Store keys with tight permissions** (`0600`, owned by the quicSQL user) and outside the repo. Pull them from a secret manager in your deployment rather than baking them into an image.
- **Never ship the dev credentials.** The example modules embed a fixed dev CA and client cert for convenience; replace every one of them.
- **Give each identity the least grant it needs**, per database. mTLS answers "who," but the `grants` still decide "what" — a read-only reporting cert should hold only `read-only`.

## Minimal checklist

1. Two CAs created; CA keys stored securely.
2. Server leaf issued with SANs covering every dialed name/IP.
3. One client cert per identity; CN (or pinned SPKI) chosen.
4. `tls` profile with `cert`, `key`, `client_ca`, `min_version: "1.3"`.
5. Listener on `h2`/`h3` with `auth: [mtls]` (or mtls plus others).
6. A principal per cert (`subject_cn` or `spki_sha256`) and a per-database grant for each.
7. Client uses `WithRootCA(serverCA)` + `WithClientCert(cert)`; verified (`insecure=false`).
