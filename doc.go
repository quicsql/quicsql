// Package server is the quicSQL nursery: a SQLite network server / multiplexer
// that owns local databases (plain files, in-memory, and vfs/vault containers)
// and fans many network clients into ONE long-lived open handle per database —
// the single-owner discipline that makes a vault file safely shareable.
//
// It is developed in-repo as gosqlite.org/server and is NOT exposed from the
// gosqlite public surface; the trajectory is extraction into the standalone
// quicSQL product. The full design lives in .plans/plan-quicsql-server.md.
//
// Live today (Phases 0-6): the config/backend/registry/engine core, the
// native-JSON and libSQL Hrana protocols (execute/batch/interactive
// transactions over baton sessions), the full transport matrix — HTTP/1.1,
// cleartext h2c, h2 over TLS, HTTP/3 over QUIC, and Unix sockets, all serving
// one http.Handler — authentication + authorization (a principal/capability
// model with per-database grants and read-only enforced in depth, across
// no-auth, Unix peer credentials, bearer token, HTTP-basic password, mTLS, and
// an ed25519 challenge/response reusing crypto/keyring), every open mode through
// config (plain file, read-only, private and shared in-memory, vfs/mvcc and
// vfs/memdb, and vfs/vault plain / compressed / encrypted / multi-recipient /
// authenticated-writer), and a control plane at /_admin: runtime create / detach
// / list databases and vault maintenance (offline compact, online reclaim, trim,
// snapshot), backed by a meta store that persists runtime-created databases and
// an admin audit log. Still a seam for the last phase: observability /
// introspection / limits (Phase 7).
package server
