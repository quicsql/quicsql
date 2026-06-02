// Package session is the interactive-transaction seam. Phase 2 fills it: a
// Session pins a *sqlite.Conn (via DB.PinConn) for the life of a BEGIN…COMMIT
// spanning multiple requests, addressed by an unforgeable, server-signed Hrana
// baton — or held directly on a long-lived WebSocket / QUIC stream. The Store
// also enforces the write-slot governance (bounded write-sessions, idle-timeout
// reaper) that the single vault writer slot requires.
package session

import (
	"context"

	"gosqlite.org/server/registry"
)

// Session is a pinned-connection interactive transaction. Fields are added in
// Phase 2 (pinned conn, release func, deadline, in-transaction flag).
type Session struct {
	Baton string
	DB    *registry.DB
}

// Store issues and resumes sessions. Phase 2 provides the concrete baton store
// and reaper AND wires it into the protocol layer; the interface is defined here
// so that wiring is a drop-in. Nothing depends on it yet.
type Store interface {
	// Open starts a new session on db and returns its baton.
	Open(ctx context.Context, db *registry.DB) (baton string, s *Session, err error)
	// Resume looks up an existing session by baton (rotating it per response).
	Resume(baton string) (*Session, error)
	// Close ends a session, rolling back any open transaction and releasing the
	// pinned conn.
	Close(baton string) error
}
