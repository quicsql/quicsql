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

	"quicsql.net/backend"
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
	onClose  func(*DB) // fired (outside r.mu) when a handle is closed, so caches keyed by it can evict
}

// SetCloseHook installs a callback invoked (outside the registry mutex) whenever
// a handle is closed — by Reserve, Remove, the idle reaper, or Close. Caches
// keyed by the *DB (e.g. the blob-store cache) register it to drop stale entries
// instead of pinning a closed handle. At most one hook; nil clears it.
func (r *Registry) SetCloseHook(fn func(*DB)) {
	r.mu.Lock()
	r.onClose = fn
	r.mu.Unlock()
}

// closeHandle fires the close hook then closes a detached handle. Called OUTSIDE
// r.mu because Handle.Close() can checkpoint WAL — slow I/O that must not block
// every other database's Get/Reserve/Remove.
func (r *Registry) closeHandle(db *DB) error {
	if db == nil {
		return nil
	}
	r.mu.Lock()
	hook := r.onClose
	r.mu.Unlock()
	if hook != nil {
		hook(db)
	}
	return db.Handle.Close()
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
	for {
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
		// Re-check the entry under the lock: while we waited on e.ready (lock
		// released) a concurrent Reserve/Remove may have closed this handle and
		// deleted or replaced the entry. Using the captured e would hand back a
		// closed *sqlite.DB and violate Reserve's exclusive ownership — so retry
		// from the top, which re-resolves to the opener, reserved, unknown, or a
		// freshly reopened handle as appropriate.
		if r.entries[name] != e {
			r.mu.Unlock()
			continue
		}
		if e.err != nil {
			r.mu.Unlock()
			return nil, nil, e.err
		}
		if e.reserved {
			r.mu.Unlock()
			return nil, nil, ErrReserved
		}
		e.refs++
		e.last = time.Now()
		db, release := e.db, r.releaseFunc(e)
		r.mu.Unlock()
		return db, release, nil
	}
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

// Warm eagerly opens the named databases so a bad seed (missing file, wrong
// key) fails at STARTUP rather than on a client's first request. Callers pass
// the config-declared seeds ONLY — never the meta-restored runtime-created set,
// which must open lazily on first Get (a fleet of per-account databases would
// otherwise all open on every boot). Each handle is released immediately (it
// stays open at ref 0). Returns the first open error, honoring ctx.
func (r *Registry) Warm(ctx context.Context, names []string) error {
	names = append([]string(nil), names...)
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
	if r.backends[name] == nil {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", ErrUnknownDB, name)
	}
	db, err := r.detachIdleLocked(name)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	// Install the reserved placeholder atomically with the detach so no Get can
	// slip in, then release the lock and close the old handle (slow I/O) — the
	// reservation is already in place, blocking new users.
	ph := &entry{name: name, reserved: true, ready: make(chan struct{})}
	close(ph.ready)
	r.entries[name] = ph
	r.mu.Unlock()
	_ = r.closeHandle(db)
	return func() {
		r.mu.Lock()
		delete(r.entries, name)
		r.mu.Unlock()
	}, nil
}

// detachIdleLocked removes name's entry from the map IF it is idle and returns
// its handle for the caller to close via closeHandle OUTSIDE r.mu; it returns
// ErrBusy if the handle is opening / has active users / is reserved, and (nil,
// nil) for a name with no live handle. The caller MUST hold r.mu. It is the
// shared detach of Reserve and Remove; closing under the lock (a WAL checkpoint)
// would stall every other database, so the close is deferred to the caller.
func (r *Registry) detachIdleLocked(name string) (*DB, error) {
	e := r.entries[name]
	if e == nil {
		return nil, nil
	}
	if e.opening || e.refs > 0 || e.reserved {
		return nil, ErrBusy
	}
	delete(r.entries, name)
	return e.db, nil // e.db may be nil (a placeholder / never-opened entry)
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
	if r.backends[name] == nil {
		r.mu.Unlock()
		return fmt.Errorf("%w: %q", ErrUnknownDB, name)
	}
	db, err := r.detachIdleLocked(name)
	if err != nil {
		r.mu.Unlock()
		return err
	}
	delete(r.backends, name)
	r.mu.Unlock()
	_ = r.closeHandle(db) // outside the lock (WAL checkpoint on close)
	return nil
}

// ReapIdle closes every open handle idle longer than idleTTL (refs==0, not
// opening/reserved), returning the count closed. The backend stays registered —
// only the open handle is dropped, so the next Get reopens lazily. A non-positive
// idleTTL is a no-op. Uses entry.last (bumped by Get and release).
func (r *Registry) ReapIdle(idleTTL time.Duration) int {
	if idleTTL <= 0 {
		return 0
	}
	now := time.Now()
	var toClose []*DB
	r.mu.Lock()
	for name, e := range r.entries {
		if e.opening || e.refs > 0 || e.reserved || e.db == nil || now.Sub(e.last) < idleTTL {
			continue
		}
		delete(r.entries, name)
		toClose = append(toClose, e.db)
	}
	r.mu.Unlock()
	for _, db := range toClose {
		_ = r.closeHandle(db) // outside the lock
	}
	return len(toClose)
}

// StartIdleReaper runs ReapIdle every interval until ctx is done, bounding how
// long an unused handle (e.g. a control-plane-created database touched once) stays
// open. A non-positive idleTTL or interval disables it.
func (r *Registry) StartIdleReaper(ctx context.Context, interval, idleTTL time.Duration) {
	if idleTTL <= 0 || interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n := r.ReapIdle(idleTTL); n > 0 {
					r.log.Debug("registry: reaped idle handles", "count", n)
				}
			}
		}
	}()
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
// (listeners down) before calling; a future revision adds session-draining and WAL
// checkpointing.
func (r *Registry) Close() error {
	r.mu.Lock()
	pending := make([]*entry, 0, len(r.entries))
	for _, e := range r.entries {
		pending = append(pending, e)
	}
	r.entries = make(map[string]*entry)
	hook := r.onClose
	r.mu.Unlock()

	var errs []error
	for _, e := range pending {
		<-e.ready // let a concurrent opener finish publishing (closed already for placeholders)
		if e.db != nil {
			if hook != nil {
				hook(e.db)
			}
			if err := e.db.Handle.Close(); err != nil {
				errs = append(errs, fmt.Errorf("registry: close %q: %w", e.name, err))
			}
		}
	}
	return errors.Join(errs...)
}
