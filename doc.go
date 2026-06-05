// Package server is the quicSQL nursery: a SQLite network server / multiplexer
// that owns local databases (plain files, in-memory, and vfs/vault containers)
// and fans many network clients into ONE long-lived open handle per database —
// the single-owner discipline that makes a vault file safely shareable.
//
// It is developed in-repo as gosqlite.org/server and is NOT exposed from the
// gosqlite public surface; the trajectory is extraction into the standalone
// quicSQL product. The full design lives in .plans/plan-quicsql-server.md.
//
// Live today (Phases 0-3): the config/backend/registry/engine core, the
// native-JSON and libSQL Hrana protocols (execute/batch/interactive
// transactions over baton sessions), and the full transport matrix — HTTP/1.1,
// cleartext h2c, h2 over TLS, HTTP/3 over QUIC, and Unix sockets, all serving
// one http.Handler. Still seams for later phases: auth (Phase 4), the remaining
// open modes / vault options (Phase 5), the control plane (Phase 6), and
// observability/introspection (Phase 7).
package server
