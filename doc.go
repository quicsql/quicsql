// Package quicsql is the quicSQL server: a SQLite network server / multiplexer
// that owns local databases (plain files, in-memory, and vfs/vault containers)
// and fans many network clients into ONE long-lived open handle per database —
// the single-owner discipline that makes a vault file safely shareable.
//
// quicSQL is its own module, quicsql.net, built on gosqlite (gosqlite.org) — the
// CGo-free SQLite engine it embeds. During co-development it resolves gosqlite
// from the sibling checkout via the replaces in go.mod.
//
// Live today (Phases 0-7): the config/backend/registry/engine core, the
// native-JSON and libSQL Hrana protocols (execute/batch/interactive
// transactions over baton sessions), the full transport matrix — HTTP/1.1,
// cleartext h2c, h2 over TLS, HTTP/3 over QUIC, and Unix sockets, all serving
// one http.Handler — authentication + authorization (a principal/capability
// model with per-database grants and read-only enforced in depth, across
// no-auth, Unix peer credentials, bearer token, HTTP-basic password, mTLS, and
// an ed25519 challenge/response reusing crypto/keyring), every open mode through
// config (plain file, read-only, private and shared in-memory, vfs/mvcc and
// vfs/memdb, and vfs/vault plain / compressed / encrypted / multi-recipient /
// authenticated-writer), a control plane at /_admin (runtime create / detach /
// list databases and vault maintenance — offline compact, online reclaim, trim,
// snapshot — with a meta store and audit log), and observability + safety rails:
// a /_metrics OpenMetrics endpoint, /_admin introspection (info / stats /
// sessions / kill), a slow-query log (driver TraceProfile, params redacted), a
// per-principal rate limit and per-database concurrency cap, and statement /
// transaction timeouts that interrupt a runaway or disconnected query.
package quicsql
