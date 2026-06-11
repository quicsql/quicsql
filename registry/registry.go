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
	"sort"
	"sync"
	"time"

	"gosqlite.org/server/backend"
)

// ErrUnknownDB is returned (wrapped) when a name has no configured backend.
var ErrUnknownDB = errors.New("registry: unknown database")

// ErrReserved is returned by Get while a database is held for an offline op.
var ErrReserved = errors.New("registry: database reserved for an offline operation")

// ErrBusy is returned by Reserve when the handle is opening or still has users.
var ErrBusy = errors.New("registry: database busy (opening or has active users)")

// ErrExists is returned by Add when the name is already registered.
var ErrExists = errors.New("registry: database already exists")

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
			return nil, nil, fmt.Errorf("%w: %q", ErrUnknownDB, name)
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

// Warm eagerly opens every configured database so a bad seed (missing file,
// wrong key) fails at STARTUP rather than on a client's first request. Each
// handle is released immediately (it stays open at ref 0). Returns the first
// open error, honoring ctx.
func (r *Registry) Warm(ctx context.Context) error {
	r.mu.Lock()
	names := make([]string, 0, len(r.backends))
	for name := range r.backends {
		names = append(names, name)
	}
	r.mu.Unlock()
	sort.Strings(names)
	for _, name := range names {
		_, release, err := r.Get(ctx, name)
		if err != nil {
			return fmt.Errorf("registry: warm %q: %w", name, err)
		}
		release()
	}
	return nil
}

// Reserve takes exclusive ownership of name for an offline vault op, mirroring
// vault's own reservePath: it fails (ErrBusy) if the handle is opening or still
// has active users; otherwise it closes the idle handle and blocks new Gets
// until the returned release runs. It does not drain active users — it refuses.
func (r *Registry) Reserve(name string) (release func(), err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.backends[name] == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownDB, name)
	}
	if err := r.dropIdleEntryLocked(name); err != nil {
		return nil, err
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

// dropIdleEntryLocked closes and forgets name's open handle IF it is idle, or
// returns ErrBusy if it is opening / has active users / is reserved. It is the
// shared teardown of Reserve and Remove; the caller must hold r.mu, and a name
// with no live entry is a no-op success.
func (r *Registry) dropIdleEntryLocked(name string) error {
	e := r.entries[name]
	if e == nil {
		return nil
	}
	if e.opening || e.refs > 0 || e.reserved {
		return ErrBusy
	}
	if e.db != nil {
		_ = e.db.Handle.Close()
	}
	delete(r.entries, name)
	return nil
}

// Add registers a new database at runtime (the control-plane create/attach op).
// The handle opens lazily on first Get, exactly like a seed entry.
func (r *Registry) Add(name string, be backend.Backend) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.backends[name] != nil {
		return fmt.Errorf("%w: %q", ErrExists, name)
	}
	r.backends[name] = be
	return nil
}

// Remove detaches a database at runtime: it refuses (ErrBusy) while the handle
// is opening, has active users, or is reserved; otherwise it closes any idle
// handle and forgets the backend. The database file itself is untouched.
func (r *Registry) Remove(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.backends[name] == nil {
		return fmt.Errorf("%w: %q", ErrUnknownDB, name)
	}
	if err := r.dropIdleEntryLocked(name); err != nil {
		return err
	}
	delete(r.backends, name)
	return nil
}

// Backend returns the backend registered under name (nil if unknown), for the
// control plane's maintenance ops.
func (r *Registry) Backend(name string) backend.Backend {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.backends[name]
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
