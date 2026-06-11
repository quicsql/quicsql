// Package server is the quicSQL nursery: a SQLite network server / multiplexer
// that owns local databases (plain files, in-memory, and vfs/vault containers)
// and fans many network clients into ONE long-lived open handle per database —
// the single-owner discipline that makes a vault file safely shareable.
//
// It is developed in-repo as gosqlite.org/server and is NOT exposed from the
// gosqlite public surface; the trajectory is extraction into the standalone
// quicSQL product. The full design lives in .plans/plan-quicsql-server.md.
//
// Live today (Phases 0-5): the config/backend/registry/engine core, the
// native-JSON and libSQL Hrana protocols (execute/batch/interactive
// transactions over baton sessions), the full transport matrix — HTTP/1.1,
// cleartext h2c, h2 over TLS, HTTP/3 over QUIC, and Unix sockets, all serving
// one http.Handler — authentication + authorization (a principal/capability
// model with per-database grants and read-only enforced in depth, across
// no-auth, Unix peer credentials, bearer token, HTTP-basic password, mTLS, and
// an ed25519 challenge/response reusing crypto/keyring), and every open mode
// through config: plain file, read-only, private and shared in-memory, the
// vfs/mvcc and vfs/memdb VFSes, and vfs/vault (plain / compressed / encrypted /
// multi-recipient / authenticated-writer), with secrets resolved eagerly from
// env / file sources. Still seams for later phases: the control plane (Phase 6)
// and observability/introspection (Phase 7).
package server
