package backend

import (
	"context"

	"gosqlite.org"
)

// fileBackend opens a plain on-disk (or read-only) SQLite database.
type fileBackend struct {
	cfg sqlite.Config
	ro  bool
}

func (b *fileBackend) Open(ctx context.Context) (*sqlite.DB, error) { return sqlite.Open(b.cfg) }
func (b *fileBackend) Kind() string                                 { return "file" }
func (b *fileBackend) ReadOnly() bool                               { return b.ro }
