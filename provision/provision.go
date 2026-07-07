// Package provision materializes a database into the live registry, meta store,
// and change feed — and tears it back down. It is the programmatic create/detach
// core behind self-service enroll-time database-per-user provisioning (the control
// plane's /_admin/create runs its own equivalent sequence over HTTP).
//
// It is authorization-agnostic: grants ride in the spec's Grants (so they reload
// with the database at startup) and are applied to the live policy by the caller.
package provision

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/meta"
	"quicsql.net/registry"
	"quicsql.net/secret"
)

// FeedRegistry is the change-feed hook: a provisioned database becomes observable,
// a dropped one stops. A nil FeedRegistry disables the hook.
type FeedRegistry interface {
	Register(name, path string)
	Forget(name string)
}

// Metrics forgets a dropped database's series so scrapes don't accrue it. A nil
// Metrics disables the hook.
type Metrics interface {
	Forget(name string)
}

// Provisioner creates and drops databases at runtime against the shared registry,
// meta store, change feed, and metrics.
type Provisioner struct {
	reg     *registry.Registry
	store   *meta.Store  // may be nil (no persistence)
	feed    FeedRegistry // may be nil
	metrics Metrics      // may be nil
	sec     secret.Resolver
	dataDir string
	log     *slog.Logger
}

// New builds a Provisioner. store/feed/metrics may be nil.
func New(reg *registry.Registry, store *meta.Store, feed FeedRegistry, metrics Metrics, sec secret.Resolver, dataDir string, log *slog.Logger) *Provisioner {
	if log == nil {
		log = slog.Default()
	}
	return &Provisioner{reg: reg, store: store, feed: feed, metrics: metrics, sec: sec, dataDir: dataDir, log: log}
}

// ErrBadSpec wraps a client-caused Create failure — an invalid spec, a path that
// escapes data_dir, an unbuildable backend, or a database that won't open. A
// caller maps it to 400. registry.ErrExists is returned unwrapped for a name
// clash (map to 409); anything else is a server-side error (500).
var ErrBadSpec = errors.New("provision: invalid or unopenable database")

// Create materializes db into the registry, verifies it opens, persists it, and
// registers its change feed — the create sequence minus HTTP and authorization.
// It re-validates the spec and confines an on-disk path to data_dir. Returns
// registry.ErrExists if the name is already served, ErrBadSpec for a client-fault
// spec, or a plain error for a persist/registry failure.
func (p *Provisioner) Create(ctx context.Context, db config.Database) error {
	if err := config.ValidateDatabase(db); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSpec, err)
	}
	if config.UsesPath(db.Backend) && db.Path != "" {
		if _, ok := config.WithinDir(p.dataDir, db.Path); !ok {
			return fmt.Errorf("%w: database %q path %q escapes data_dir", ErrBadSpec, db.Name, db.Path)
		}
	}
	be, err := backend.For(db, p.sec, p.dataDir)
	if err != nil {
		return fmt.Errorf("%w: build backend for %q: %v", ErrBadSpec, db.Name, err)
	}
	if err := p.reg.Add(db.Name, be); err != nil {
		return err // ErrExists (or another registry error), unwrapped for the caller
	}
	// Register the feed AFTER Add succeeds (so a duplicate can't clobber an existing
	// database's feed) but BEFORE the first Get opens a connection (hooks install at
	// connection open, and an unobserved first connection would write invisibly).
	feedRollback := func() {}
	if p.feed != nil {
		if pa, ok := be.(backend.Pather); ok {
			p.feed.Register(db.Name, pa.Path())
			feedRollback = func() { p.feed.Forget(db.Name) }
		}
	}
	// Verify it opens before persisting, so a bad spec fails now, not on first use.
	if _, release, gerr := p.reg.Get(ctx, db.Name); gerr != nil {
		_ = p.reg.Remove(db.Name)
		feedRollback()
		return fmt.Errorf("%w: open %q: %v", ErrBadSpec, db.Name, gerr)
	} else {
		release()
	}
	if p.store != nil {
		if err := p.store.Put(db); err != nil {
			_ = p.reg.Remove(db.Name)
			feedRollback()
			return fmt.Errorf("provision: persist %q: %w", db.Name, err)
		}
	}
	return nil
}

// Drop removes name from the registry, change feed, metrics, and (if persisted)
// the meta store. When deleteFile is true, the backing file and its -wal/-shm
// sidecars are deleted too. Returns registry.ErrBusy (active users) or
// registry.ErrUnknownDB (absent) unwrapped.
func (p *Provisioner) Drop(name string, deleteFile bool) error {
	// Capture the on-disk path BEFORE removing so the file can be deleted after.
	var path string
	if deleteFile {
		if be := p.reg.Backend(name); be != nil {
			if pa, ok := be.(backend.Pather); ok {
				path = pa.Path()
			}
		}
	}
	if err := p.reg.Remove(name); err != nil {
		return err
	}
	if p.feed != nil {
		p.feed.Forget(name)
	}
	if p.metrics != nil {
		p.metrics.Forget(name)
	}
	if p.store != nil {
		// A failed delete leaves the persisted record, so reconcile would resurrect
		// the database on restart — log rather than swallow.
		if err := p.store.Delete(name); err != nil {
			p.log.Warn("provision: could not delete persisted database record (may resurrect on restart)", "db", name, "err", err)
		}
	}
	if deleteFile && path != "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			p.log.Warn("provision: could not delete database file", "db", name, "path", path, "err", err)
		}
		_ = os.Remove(path + "-wal")
		_ = os.Remove(path + "-shm")
	}
	return nil
}
