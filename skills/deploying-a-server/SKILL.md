---
name: deploying-a-server
description: Use when standing up or configuring a quicSQL server — writing the YAML config, running the cmd/quicsql daemon, choosing listeners and transports, binding to an interface, or composing a server programmatically with serverd.Run (including a custom SQL function).
---

# Deploying a quicSQL server

A quicSQL server hosts many databases behind one HTTP handler on any mix of transports. Two ways to run it: the **standalone daemon** (config file only) or a **custom `main()`** (when you need Go — a custom SQL function, a bespoke extension set).

## The standalone daemon

```
quicsql --config quicsql.yaml
```

`cmd/quicsql` loads the config, imports the standard extension bundle, and serves. Minimal config:

```yaml
server:
  data_dir: /var/lib/quicsql
listeners:
  - { name: h1, transport: h1, address: 127.0.0.1:7775, auth: [none] }
databases:
  - { name: app, backend: file, path: app.db, mode: rwc, pragmas_preset: recommended }
```

Transports (bind `0.0.0.0` to reach from other machines): `h1` (7775), `h2c` (7776), `h2` + `h3` (both on 7777 — QUIC/UDP shares h2's TLS/TCP port, as HTTPS does on :443; need a `tls:` profile), `unix` (a socket path). Canonical port 7775, sequencing up. h2/h3 require a TLS profile — see the `auth-and-tls` skill.

```yaml
listeners:
  - { name: h2,   transport: h2,   address: 0.0.0.0:7777, tls: main, auth: [mtls, bearer] }
  - { name: h3,   transport: h3,   address: 0.0.0.0:7777, tls: main, auth: [mtls, bearer], advertise: true }   # shares the h2 port; advertise ⇒ Alt-Svc
  - { name: unix, transport: unix, address: /run/quicsql/sql.sock, auth: [peercred, none] }
```

## Composing programmatically (serverd.Run)

Use this when a config file can't express what you need — most often a **server-side custom SQL function** (registered before the server opens any connection), or a custom extension set. This is how server-side functions/VFS/extensions reach remote clients: the server runs them; clients call them via SQL.

```go
import (
    sqlite "gosqlite.org"
    "quicsql.net/config"
    _ "quicsql.net/extensions" // regexp, fts5, vec0, spellfix1, rtree, …
    "quicsql.net/serverd"
)

sqlite.RegisterAutoHook(func(c *sqlite.Conn) error {          // runs on every connection
    return c.RegisterFunc("greet", func(s string) string { return "hi " + s }, true)
})

cfg := &config.Config{ /* Server, Databases, Listeners, TLS, Auth, … */ }
srv, err := serverd.Run(cfg, slog.Default())                 // returns *Instance
// … serve …
srv.Shutdown(ctx)                                            // graceful drain; returns nothing
```

`examples/charged-server` is the full worked example — vault encryption + compression, every transport and auth method, control plane, limits, a custom function — and the reference `charged.yaml` mirrors it for the daemon. Run it with `just charged -hosts your.host,IP`.

## Then

- **Pick backends** (file / in-memory / encrypted vault) → the `databases-and-backends` skill.
- **Add auth + TLS** → the `auth-and-tls` skill.
- **Turn on the control plane, limits, metrics** → the `operating-a-server` skill.

`-hosts` / the TLS SANs must include every hostname or IP clients dial, or TLS verification fails from another machine.
