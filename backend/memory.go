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
	return sqlite.OpenInMemory()
}

func (b *memoryBackend) Kind() string {
	if b.shared {
		return "memory-shared"
	}
	return "memory"
}

func (b *memoryBackend) ReadOnly() bool { return false }
