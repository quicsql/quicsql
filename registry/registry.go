// Package registry owns exactly ONE open handle per logical database and fans
// every session through it — the single-owner invariant that makes a vault file
// safely shareable. Handles open lazily on first use, are reference-counted
// while in use, and can be reserved for the offline vault ops (Rekey/Rewrap/
// Compact) that require the container to be closed.
//
// Concurrency contract: every field of an entry is read and written only under
// r.mu, EXCEPT the blocking backend.Open call, which runs with the lock
// released while the entry is marked opening (and pre-counted with one ref).
// That single carve-out is what keeps a slow open from stalling other
// databases without exposing e.db/e.err to a data race.
package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"gosqlite.org/server/backend"
)

// ErrReserved is returned by Get while a database is held for an offline op.
var ErrReserved = errors.New("registry: database reserved for an offline operation")

// ErrBusy is returned by Reserve when the handle is opening or still has users.
var ErrBusy = errors.New("registry: database busy (opening or has active users)")

// Registry is the process-wide database registry.
type Registry struct {
	mu       sync.Mutex
	entries  map[string]*entry
	backends map[string]backend.Backend
	log      *slog.Logger
}

type entry struct {
	name     string
	be       backend.Backend
	ready    chan struct{} // closed once the open attempt completes (or for a reserved placeholder)
	opening  bool
	db       *DB
	err      error
	refs     int
	last     time.Time
	reserved bool
}

// New builds a registry over a name→Backend map.
func New(backends map[string]backend.Backend, log *slog.Logger) *Registry {
	if log == nil {
		log = slog.Default()
	}
	return &Registry{
		entries:  make(map[string]*entry),
		backends: backends,
		log:      log,
	}
}

// Get returns the shared handle for name, opening it lazily on first use, plus a
// release func the caller must invoke exactly once when done. The blocking open
// runs OUTSIDE the mutex behind a per-entry latch (the entry pre-counts one ref
// and is marked opening), so a slow open never stalls other databases and never
// races Reserve/Close/List.
func (r *Registry) Get(ctx context.Context, name string) (*DB, func(), error) {
	r.mu.Lock()
	e := r.entries[name]
	if e == nil {
		be := r.backends[name]
		if be == nil {
			r.mu.Unlock()
			return nil, nil, fmt.Errorf("registry: unknown database %q", name)
		}
		// We are the opener: pre-count a ref (for the handle we'll return) and
		// mark opening so Reserve/Close see the in-flight open.
		e = &entry{name: name, be: be, ready: make(chan struct{}), opening: true, refs: 1}
		r.entries[name] = e
		r.mu.Unlock()

		h, err := be.Open(ctx) // blocking; no lock held, no shared-entry field touched

		r.mu.Lock()
		e.opening = false
		if err != nil {
			// Drop the poisoned entry so a later Get can retry once the fault clears.
			e.err = err
			e.refs = 0
			delete(r.entries, name)
			r.mu.Unlock()
			close(e.ready)
			r.log.Error("registry: open failed", "db", name, "err", err)
			return nil, nil, err
		}
		e.db = &DB{Name: name, Kind: be.Kind(), ReadOnly: be.ReadOnly(), Handle: h}
		e.last = time.Now()
		r.mu.Unlock()
		close(e.ready)
		return e.db, r.releaseFunc(e), nil
	}
	r.mu.Unlock()

	// An open is in flight (or done): wait for it, honoring ctx.
	select {
	case <-e.ready:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if e.err != nil {
		return nil, nil, e.err
	}
	if e.reserved {
		return nil, nil, ErrReserved
	}
	e.refs++
	e.last = time.Now()
	return e.db, r.releaseFunc(e), nil
}

// releaseFunc returns a single-use decrement for one Get. Each Get gets its own
// func (own sync.Once), so total decrements equal successful Gets.
func (r *Registry) releaseFunc(e *entry) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			e.refs--
			e.last = time.Now()
			r.mu.Unlock()
		})
	}
}

// Reserve takes exclusive ownership of name for an offline vault op, mirroring
// vault's own reservePath: it fails (ErrBusy) if the handle is opening or has
// active users, else drains and closes it and blocks new Gets until the returned
// release runs.
func (r *Registry) Reserve(name string) (release func(), err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.backends[name] == nil {
		return nil, fmt.Errorf("registry: unknown database %q", name)
	}
	if e := r.entries[name]; e != nil {
		if e.opening || e.refs > 0 || e.reserved {
			return nil, ErrBusy
		}
		if e.db != nil {
			_ = e.db.Handle.Close()
		}
		delete(r.entries, name)
	}
	ph := &entry{name: name, reserved: true, ready: make(chan struct{})}
	close(ph.ready)
	r.entries[name] = ph
	return func() {
		r.mu.Lock()
		delete(r.entries, name)
		r.mu.Unlock()
	}, nil
}

// List snapshots the registry for the _server introspection interface.
func (r *Registry) List() []DBInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]DBInfo, 0, len(r.backends))
	for name, be := range r.backends {
		info := DBInfo{Name: name, Kind: be.Kind()}
		if e := r.entries[name]; e != nil {
			info.Open = e.db != nil
			info.Refs = e.refs
		}
		out = append(out, info)
	}
	return out
}

// Close drains and closes every open handle, waiting for any in-flight open to
// publish first so nothing leaks. Callers must have stopped accepting new work
// (listeners down) before calling; Phase 7 adds session-draining and WAL
// checkpointing.
func (r *Registry) Close() error {
	r.mu.Lock()
	pending := make([]*entry, 0, len(r.entries))
	for _, e := range r.entries {
		pending = append(pending, e)
	}
	r.entries = make(map[string]*entry)
	r.mu.Unlock()

	var errs []error
	for _, e := range pending {
		<-e.ready // let a concurrent opener finish publishing (closed already for placeholders)
		if e.db != nil {
			if err := e.db.Handle.Close(); err != nil {
				errs = append(errs, fmt.Errorf("registry: close %q: %w", e.name, err))
			}
		}
	}
	return errors.Join(errs...)
}
