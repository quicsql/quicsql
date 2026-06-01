// Package server is the quicSQL nursery: a SQLite network server / multiplexer
// that owns local databases (plain files, in-memory, and vfs/vault containers)
// and fans many network clients into ONE long-lived open handle per database —
// the single-owner discipline that makes a vault file safely shareable.
//
// It is developed in-repo as gosqlite.org/server and is NOT exposed from the
// gosqlite public surface; the trajectory is extraction into the standalone
// quicSQL product. The full design lives in .plans/plan-quicsql-server.md.
//
// This is the Phase 0 scaffold: transport-free, it wires config + backend +
// registry + engine, exercised by unit tests. Every later phase attaches to the
// same (registry, engine) pair and fills one seam — the http.Handler and the
// Hrana/native protocols (Phases 1-2), the transport matrix (Phase 3), auth
// (Phase 4), all open modes and vault options (Phase 5), the control plane
// (Phase 6), and observability/introspection (Phase 7).
package server
