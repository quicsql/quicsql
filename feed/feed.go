// Package feed is the change-notification broker: it observes committed writes
// through per-connection SQLite hooks and fans them out to subscribers (the
// /<db>/changes SSE endpoint). Events are buffered per connection during a
// transaction and published atomically at COMMIT — a rolled-back write is never
// emitted. Each database's feed carries a monotonic sequence number and a ring
// buffer, so a briefly-disconnected subscriber resumes by sequence instead of
// refetching the world.
//
// Attribution: hooks are per-connection, and a connection knows only its file
// path — so the broker maps registered database paths to logical names at
// startup (and at runtime create). Databases without a stable path (private
// in-memory backends) cannot be observed and are skipped with a warning.
package feed

import (
	"log/slog"
	"path/filepath"
	"sync"

	sqlite "gosqlite.org"
)

// SQLite preupdate opcodes (stable C ABI values).
const (
	opInsert = 18
	opUpdate = 23
	opDelete = 9
)

// Event is one committed row change. Values (old/new column data) are
// deliberately absent in v1 — subscribers re-read what they care about, and the
// feed never becomes an accidental data-exfiltration channel.
//
// A Reset event (Op "" / Reset true) is a sequenced marker meaning "the change
// detail here was dropped — refetch": it is published when a single transaction
// overflowed the per-transaction buffer (a huge bulk write). It still advances
// the sequence, so replay stays contiguous.
type Event struct {
	Seq   uint64 `json:"seq"`
	Table string `json:"table"`
	Op    string `json:"op"` // insert | update | delete
	Rowid int64  `json:"rowid"`
	Reset bool   `json:"reset,omitempty"`
}

// Broker routes committed changes from connections to per-database feeds.
type Broker struct {
	buffer  int
	maxSubs int
	log     *slog.Logger

	mu     sync.RWMutex
	byPath map[string]*dbFeed // cleaned absolute path → feed
	byName map[string]*dbFeed
}

// maxPending bounds how many buffered row-events one transaction may accumulate
// before commit. A bulk write (DELETE/UPDATE/INSERT…SELECT over millions of
// rows) would otherwise retain one event per row in RAM until COMMIT — a
// writer-side memory-amplification vector independent of any subscriber. On
// overflow the buffer is dropped and the commit publishes a single `reset`
// marker instead, telling subscribers to refetch.
const maxPending = 8192

// New builds a broker: buffer is the per-database replay ring size, maxSubs the
// per-database subscriber cap. A non-positive buffer is floored to 1 so the ring
// never has a zero capacity (which would panic on the first publish).
func New(buffer, maxSubs int, log *slog.Logger) *Broker {
	if log == nil {
		log = slog.Default()
	}
	if buffer < 1 {
		buffer = 1
	}
	return &Broker{
		buffer: buffer, maxSubs: maxSubs, log: log,
		byPath: map[string]*dbFeed{}, byName: map[string]*dbFeed{},
	}
}

// Register makes a database observable: name is the logical database, path its
// on-disk file (as the connection will report it). Safe to call at runtime for
// control-plane-created databases — only connections opened AFTER registration
// are hooked, which at create time is all of them.
func (b *Broker) Register(name, path string) {
	if path == "" {
		b.log.Warn("feed: database has no stable path — change feed unavailable", "db", name)
		return
	}
	f := &dbFeed{name: name, ring: make([]Event, b.buffer), cap: b.buffer, subs: map[*Subscriber]struct{}{}}
	b.mu.Lock()
	b.byPath[canonicalPath(path)] = f
	b.byName[name] = f
	b.mu.Unlock()
}

// canonicalPath normalizes a database path the same way for registration and
// for the path a connection reports — absolute, symlinks resolved (macOS's
// /var → /private/var would otherwise split the two), cleaned. The file may
// not exist yet at registration, so symlinks are resolved on the directory.
func canonicalPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	dir, base := filepath.Split(p)
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		p = filepath.Join(resolved, base)
	}
	return filepath.Clean(p)
}

// Forget stops observing a database (control-plane detach). Existing
// subscribers are closed.
func (b *Broker) Forget(name string) {
	b.mu.Lock()
	f := b.byName[name]
	delete(b.byName, name)
	for p, pf := range b.byPath {
		if pf == f {
			delete(b.byPath, p)
		}
	}
	b.mu.Unlock()
	if f != nil {
		f.closeAll()
	}
}

// Install arms the process-wide connection hook. Call once, BEFORE any
// database opens (like the security AutoHook), so no writing connection can
// predate its observer.
func (b *Broker) Install() {
	sqlite.RegisterAutoHook(func(c *sqlite.Conn) error {
		name := c.Filename("main")
		if name == "" {
			return nil // in-memory / temp — never observable
		}
		b.mu.RLock()
		f := b.byPath[canonicalPath(name)]
		b.mu.RUnlock()
		if f == nil {
			return nil // not an observed database (meta store, memory, …)
		}
		// Hooks fire on the connection's own goroutine, so these need no lock:
		// preupdate appends, commit publishes+clears, rollback clears. `overflow`
		// caps a single transaction's buffered events (memory-amplification guard):
		// past the cap we stop retaining detail and publish one reset at commit.
		var pending []Event
		overflow := false
		c.RegisterPreUpdateHook(func(d sqlite.SQLitePreUpdateData) {
			if overflow {
				return
			}
			var op string
			var rowid int64
			switch d.Op {
			case opInsert:
				op, rowid = "insert", d.NewRowID
			case opUpdate:
				op, rowid = "update", d.NewRowID
			case opDelete:
				op, rowid = "delete", d.OldRowID
			default:
				return
			}
			if len(pending) >= maxPending {
				overflow = true
				pending = nil // release the buffer; a reset at commit stands in for it
				return
			}
			pending = append(pending, Event{Table: d.TableName, Op: op, Rowid: rowid})
		})
		c.RegisterCommitHook(func() int32 {
			switch {
			case overflow:
				f.publish([]Event{{Reset: true}})
			case len(pending) > 0:
				f.publish(pending)
			}
			pending, overflow = nil, false
			return 0 // never veto the commit
		})
		c.RegisterRollbackHook(func() {
			pending, overflow = nil, false
		})
		return nil
	})
}

// Subscribe attaches a subscriber to a database's feed, replaying buffered
// events after `since` first. ok=false when the database is not observed;
// full=true when the subscriber cap is reached. When `since` has already left
// the ring, reset=true tells the client its world is stale (refetch, then
// follow from the returned events). seq is the feed's current sequence at the
// instant of attach — the point the subscriber now follows from (replay covers up
// to it, live events arrive after it) — so the caller needs no second locked
// lookup to report it.
func (b *Broker) Subscribe(db string, since uint64) (s *Subscriber, replay []Event, reset bool, ok, full bool, seq uint64) {
	b.mu.RLock()
	f := b.byName[db]
	b.mu.RUnlock()
	if f == nil {
		return nil, nil, false, false, false, 0
	}
	return f.subscribe(since, b.maxSubs)
}

// Observed reports whether db has a feed.
func (b *Broker) Observed(db string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.byName[db] != nil
}

// subscriberBuf bounds how far a slow consumer may lag before it is dropped
// (it reconnects and resumes by sequence).
const subscriberBuf = 256

// Subscriber is one attached consumer. Read events from C; a closed C means
// the subscriber was dropped (slow, or the database was detached) — reconnect
// with the last seen sequence.
type Subscriber struct {
	C    <-chan Event
	c    chan Event
	feed *dbFeed
}

// Close detaches the subscriber. Idempotent.
func (s *Subscriber) Close() {
	s.feed.unsubscribe(s)
}

// dbFeed retains the last `cap` events in a fixed circular buffer: the event with
// sequence s (1-based, monotonic) lives at ring[(s-1) % cap]. This overwrites the
// oldest slot in place on each publish rather than reslicing (`ring[1:]`), which —
// once the ring was full — reallocated and copied the whole buffer on every commit.
type dbFeed struct {
	name string
	cap  int

	mu   sync.Mutex
	seq  uint64
	ring []Event // fixed length == cap
	subs map[*Subscriber]struct{}
}

// retained reports how many of the most-recent events are still in the ring
// (everything, until `cap` have been published). Caller holds f.mu.
func (f *dbFeed) retained() uint64 {
	if f.seq < uint64(f.cap) {
		return f.seq
	}
	return uint64(f.cap)
}

func (f *dbFeed) publish(events []Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range events {
		f.seq++
		events[i].Seq = f.seq
		f.ring[(f.seq-1)%uint64(f.cap)] = events[i] // overwrite the oldest slot in place
		for s := range f.subs {
			select {
			case s.c <- events[i]:
			default:
				// A consumer this far behind is better served by a reconnect-and
				// -resume than by blocking every other subscriber's commit path.
				delete(f.subs, s)
				close(s.c)
			}
		}
	}
}

func (f *dbFeed) subscribe(since uint64, maxSubs int) (s *Subscriber, replay []Event, reset bool, ok, full bool, seq uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if maxSubs > 0 && len(f.subs) >= maxSubs {
		return nil, nil, false, true, true, f.seq
	}
	switch {
	case since > f.seq:
		// A sequence from a previous server incarnation — the client's world is
		// stale even though it looks "ahead".
		reset = true
	case since > 0 && since < f.seq:
		oldest := f.seq - f.retained() + 1 // oldest sequence still in the ring
		if since+1 < oldest {
			reset = true // the requested horizon has left the ring
		} else {
			for sq := since + 1; sq <= f.seq; sq++ {
				replay = append(replay, f.ring[(sq-1)%uint64(f.cap)])
			}
		}
	}
	sub := &Subscriber{c: make(chan Event, subscriberBuf), feed: f}
	sub.C = sub.c
	f.subs[sub] = struct{}{}
	return sub, replay, reset, true, false, f.seq
}

func (f *dbFeed) unsubscribe(s *Subscriber) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, live := f.subs[s]; live {
		delete(f.subs, s)
		close(s.c)
	}
}

func (f *dbFeed) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for s := range f.subs {
		delete(f.subs, s)
		close(s.c)
	}
}
