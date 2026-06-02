package backend

import (
	"context"

	"gosqlite.org"
)

// memoryBackend opens an in-memory database. shared uses OpenShared so every
// session sees the same rows (the useful multiplexer mode); private ":memory:"
// is per-connection and only meaningful at max_open=1, kept here for parity.
type memoryBackend struct {
	name   string
	shared bool
}

func (b *memoryBackend) Open(ctx context.Context) (*sqlite.DB, error) {
	if b.shared {
		return sqlite.OpenShared(b.name)
	}
	// Private :memory: is per-connection; pin the pool to ONE connection so every
	// request sees the same database instead of a fresh empty one per pooled conn.
	return sqlite.Open(sqlite.Config{Path: sqlite.InMemory, MaxOpenConns: 1})
}

func (b *memoryBackend) Kind() string {
	if b.shared {
		return "memory-shared"
	}
	return "memory"
}

func (b *memoryBackend) ReadOnly() bool { return false }
