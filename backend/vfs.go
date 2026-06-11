package backend

import (
	"context"
	"fmt"
	"io"

	"gosqlite.org"
	"gosqlite.org/server/config"
	"gosqlite.org/vfs/memdb"
	"gosqlite.org/vfs/mvcc"
)

// vfsBackend opens an in-memory registered-VFS database (mvcc or memdb). Each
// Open registers a fresh VFS and hosts one shared in-memory database (a
// leading-slash path is shared across the pool's connections, so every session
// sees the same rows); the registration is torn down via VFSCloser when the
// handle closes. Re-opening after a close yields a fresh, empty database, as an
// in-memory store implies.
type vfsBackend struct {
	name    string // logical database name (also the shared in-memory DB name)
	kind    string // "mvcc" | "memdb"
	pool    config.Pool
	pragmas sqlite.Pragmas
}

func newVFSBackend(db config.Database) *vfsBackend {
	return &vfsBackend{name: db.Name, kind: db.Backend, pool: db.Pool, pragmas: pragmas(db)}
}

func (b *vfsBackend) Open(ctx context.Context) (*sqlite.DB, error) {
	var (
		name   string
		closer io.Closer
		err    error
	)
	switch b.kind {
	case "mvcc":
		var fs *mvcc.FS
		name, fs, err = mvcc.New(mvcc.Options{})
		closer = fs
	case "memdb":
		var fs *memdb.FS
		name, fs, err = memdb.New(memdb.Options{})
		closer = fs
	default:
		return nil, fmt.Errorf("backend: %q is not a registered-VFS backend", b.kind)
	}
	if err != nil {
		return nil, fmt.Errorf("backend: register %s VFS: %w", b.kind, err)
	}
	// These VFSes are memory-backed and reject a journal/WAL open (there is no
	// on-disk journal file), so drop any operator-set journal_mode rather than
	// letting it fail the open.
	pr := b.pragmas
	pr.JournalMode = ""
	cfg := sqlite.Config{
		Path:         "/" + b.name, // leading slash → shared across the pool's connections
		VFS:          name,
		VFSCloser:    closer,
		MaxOpenConns: b.pool.MaxOpen,
		TxLock:       b.pool.TxLock,
		Pragmas:      pr,
	}
	db, err := sqlite.Open(cfg)
	if err != nil {
		_ = closer.Close()
		return nil, err
	}
	return db, nil
}

func (b *vfsBackend) Kind() string   { return b.kind }
func (b *vfsBackend) ReadOnly() bool { return false }
