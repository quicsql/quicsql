// Package session implements Hrana's interactive-transaction streams: a Session
// pins one *sql.Conn for the life of a BEGIN…COMMIT spanning multiple pipeline
// requests, addressed by an unforgeable, server-signed *baton*. The baton is an
// HMAC over (session id, generation); every response rotates the generation, so
// an old baton is rejected — which enforces the serial, single-in-flight use
// Hrana requires and guards against replay. Idle streams and streams that exceed
// a maximum lifetime are reaped (rolling back any open transaction), the reaper
// skips a session with a request in flight, and the number of concurrent
// sessions is bounded PER DATABASE.
package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	sqlite "gosqlite.org"
	"quicsql.net/backend"
	"quicsql.net/registry"
)

var (
	// ErrBadBaton covers a forged, malformed, replayed, or expired baton.
	ErrBadBaton = errors.New("session: invalid or expired baton")
	// ErrTooMany is returned when a database's concurrent-session cap is reached.
	ErrTooMany = errors.New("session: too many open sessions for this database")
	// ErrPrincipalMismatch is returned when a baton is resumed by a different
	// principal than the one that opened the session — a stolen/misused baton.
	ErrPrincipalMismatch = errors.New("session: baton belongs to a different principal")
)

const (
	idLen                = 16
	closeRollbackTimeout = 5 * time.Second // bound the ROLLBACK-on-close of an abandoned tx
)

// Session is one interactive stream: a pinned connection plus its server-side
// SQL cache. A single request is in flight at a time (enforced by generation
// rotation in the Store), so its fields need no per-session lock; busy marks
// that in-flight request so the reaper won't close the conn under it.
type Session struct {
	id        [idLen]byte
	gen       uint64
	conn      *sql.Conn
	release   func() // returns the registry handle ref held for this session
	dbName    string
	principal string // the principal that opened the stream (baton is bound to it)
	readOnly  bool   // pinned conn carries the write-denying authorizer
	attach    bool   // DEV-ONLY: pinned conn permits ATTACH/DETACH (server-admin only)
	created   time.Time
	lastUsed  time.Time
	busy      bool
	sql       map[int32]string // store_sql cache
	// capture is an attached SESSION for changeset capture, if any. Unlike the
	// other fields it is touched by two goroutines — the request path
	// (SetCapture/TakeCapture) and the teardown goroutine (TakeCapture in
	// closeLocked, which runs on shutdown even for a busy session) — so its access
	// is guarded by captureMu, and TakeCapture ensures exactly one owner closes it.
	captureMu sync.Mutex
	capture   *sqlite.Session
}

// Conn returns the pinned connection the engine runs statements on.
func (s *Session) Conn() *sql.Conn { return s.conn }

// SetCapture attaches (or clears) a SESSION handle used to capture a changeset on
// this stream's pinned connection. The Store closes it (via TakeCapture) when the
// stream ends, so a stream that starts a capture and never fetches the changeset
// does not leak it.
func (s *Session) SetCapture(c *sqlite.Session) {
	s.captureMu.Lock()
	s.capture = c
	s.captureMu.Unlock()
}

// Capture reports whether a capture is attached (for the "already open" guard).
func (s *Session) Capture() *sqlite.Session {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	return s.capture
}

// TakeCapture atomically clears and returns the attached SESSION handle, so
// exactly one caller — the request path (session_changeset) or teardown
// (closeLocked) — owns and closes it, even if shutdown races an in-flight capture.
func (s *Session) TakeCapture() *sqlite.Session {
	s.captureMu.Lock()
	c := s.capture
	s.capture = nil
	s.captureMu.Unlock()
	return c
}

// DBName is the database this session is bound to.
func (s *Session) DBName() string { return s.dbName }

// AllowsAttach reports whether this session may run ATTACH/DETACH (DEV-ONLY;
// server-admin writer sessions when auth.sql_policy.allow_attach is on).
func (s *Session) AllowsAttach() bool { return s.attach }

// Principal is the name of the principal that opened this session.
func (s *Session) Principal() string { return s.principal }

// StoreSQL / LookupSQL / DropSQL back Hrana's store_sql / sql_id / close_sql.
func (s *Session) StoreSQL(id int32, sql string) { s.sql[id] = sql }
func (s *Session) LookupSQL(id int32) (string, bool) {
	v, ok := s.sql[id]
	return v, ok
}
func (s *Session) DropSQL(id int32) { delete(s.sql, id) }

// Store owns all live sessions and mints/verifies batons.
type Store struct {
	mu       sync.Mutex
	sessions map[[idLen]byte]*Session
	perDB    map[string]int // live session count per database (the cap)
	key      []byte         // HMAC key for baton signatures
	ttl      time.Duration  // idle timeout
	maxLife  time.Duration  // absolute session lifetime (caps a kept-alive open tx)
	max      int            // per-database session cap
	closing  sync.WaitGroup // in-flight conn-teardown goroutines (CloseAll waits)
}

// NewStore builds a session store with a random baton-signing key. ttl is the
// idle timeout; maxLife caps a session's total lifetime (so a client can't hold
// the writer forever with keepalives); max bounds concurrent sessions per db.
// Each of ttl/maxLife/max defaults to a safe value when non-positive — in
// particular a zero ttl must NOT mean "reap every idle session each tick"
// (reapable treats Since(lastUsed) > ttl as idle), so it defaults like the rest.
func NewStore(ttl, maxLife time.Duration, max int) (*Store, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if max <= 0 {
		max = 64
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if maxLife <= 0 {
		maxLife = 5 * time.Minute
	}
	return &Store{
		sessions: map[[idLen]byte]*Session{},
		perDB:    map[string]int{},
		key:      key, ttl: ttl, maxLife: maxLife, max: max,
	}, nil
}

// Open starts a session on db by pinning a connection. release is the registry
// ref for db, owned by the session and dropped on Close/reap (after the pinned
// conn) so the database can't be closed while a session holds a connection into
// it. The per-db cap is reserved BEFORE pinning a pool connection, so the cap —
// not the pool — is the first limit to bite. principal binds the baton to its
// owner; readOnly puts the pinned connection in read-only mode for the stream's
// life (a read-only principal's interactive transaction cannot write). The
// returned session is marked busy (a request is about to run on it); the caller
// clears that via Baton/Close.
func (st *Store) Open(ctx context.Context, db *registry.DB, release func(), principal string, readOnly, allowAttach bool) (*Session, error) {
	st.mu.Lock()
	if st.perDB[db.Name] >= st.max {
		st.mu.Unlock()
		return nil, ErrTooMany
	}
	st.perDB[db.Name]++ // reserve the slot before the (blocking) pin
	st.mu.Unlock()

	conn, err := db.Handle.Conn(ctx)
	if err != nil {
		st.releaseSlot(db.Name)
		return nil, err
	}
	// allowAttach is DEV-ONLY and only reaches here for a server-admin writer session
	// (httpapi gates it); it permits ATTACH/DETACH on this pinned connection, cleaned
	// up by ClearAttach on close. A read-only session never enables it.
	attach := allowAttach && !readOnly
	switch {
	case readOnly:
		if err := backend.SetConnMode(ctx, conn, true); err != nil {
			_ = conn.Close()
			st.releaseSlot(db.Name)
			return nil, err
		}
	case attach:
		if err := backend.SetConnAttach(ctx, conn); err != nil {
			_ = conn.Close()
			st.releaseSlot(db.Name)
			return nil, err
		}
	}

	st.mu.Lock()
	var id [idLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		st.perDB[db.Name]--
		st.mu.Unlock()
		_ = conn.Close()
		return nil, err
	}
	now := time.Now()
	s := &Session{
		id: id, gen: 1, conn: conn, release: release, dbName: db.Name,
		principal: principal, readOnly: readOnly, attach: attach,
		created: now, lastUsed: now, busy: true, sql: map[int32]string{},
	}
	st.sessions[id] = s
	st.mu.Unlock()
	return s, nil
}

func (st *Store) releaseSlot(db string) {
	st.mu.Lock()
	if st.perDB[db] > 0 {
		st.perDB[db]--
	}
	st.mu.Unlock()
}

// Resume validates a baton and returns its session, atomically consuming the
// baton (bumping the generation) so an old baton — a replay or a concurrent
// second request — is rejected with ErrBadBaton. The session is marked busy for
// the duration of the request the caller is about to run.
//
// The database and principal bindings are checked BEFORE the generation is
// bumped: a baton presented for the wrong database or by a different principal
// is rejected WITHOUT consuming it, so such a request can't burn (invalidate)
// the legitimate owner's live baton.
func (st *Store) Resume(baton, dbName, principal string) (*Session, error) {
	id, gen, err := st.verify(baton)
	if err != nil {
		return nil, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.sessions[id]
	if s == nil || s.gen != gen {
		return nil, ErrBadBaton
	}
	if s.busy {
		// A current-generation baton can coexist with an in-flight request only
		// because the cursor endpoint hands the baton out in its response prelude,
		// before the batch finishes (PeekBaton). Hrana requires serial use — the
		// client must read the whole response before its next request — so a
		// resume inside that window is refused, WITHOUT consuming the baton: it
		// becomes usable the moment the in-flight request completes.
		return nil, ErrBadBaton
	}
	if st.reapable(s) {
		st.closeLocked(id)
		return nil, ErrBadBaton
	}
	if s.dbName != dbName {
		return nil, ErrBadBaton // a baton is bound to the database it was minted for
	}
	if s.principal != principal {
		return nil, ErrPrincipalMismatch // a baton is bound to the principal that minted it
	}
	s.gen++
	s.busy = true
	s.lastUsed = time.Now()
	return s, nil
}

// Baton clears the in-flight flag, refreshes the idle clock, and returns the
// current baton for s (handed back so the client can make the next request).
func (st *Store) Baton(s *Session) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	s.busy = false
	s.lastUsed = time.Now()
	return st.mint(s.id, s.gen)
}

// PeekBaton mints the current baton for s WITHOUT clearing the in-flight flag.
// The cursor endpoint streams its response and must place the baton in the
// first line (the prelude) while the batch is still executing: the session
// stays busy for the rest of the stream — so the reaper and Kill leave the
// pinned connection alone — and Resume refuses a busy session, so the peeked
// baton is honored only once the request finishes (Baton clears the flag and
// keeps the same baton current).
func (st *Store) PeekBaton(s *Session) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.mint(s.id, s.gen)
}

// Close ends a session: rolls back any open transaction and returns the pinned
// connection to the pool.
func (st *Store) Close(s *Session) {
	st.mu.Lock()
	st.closeLocked(s.id)
	st.mu.Unlock()
}

// Info is a point-in-time snapshot of one live session for introspection.
type Info struct {
	ID        string
	DBName    string
	Principal string
	ReadOnly  bool
	Busy      bool
	Age       time.Duration
	IdleFor   time.Duration
}

// List snapshots the live sessions. If dbFilter is non-nil, only sessions on a
// database for which it returns true are included (the authz view predicate).
func (st *Store) List(dbFilter func(db string) bool) []Info {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	out := make([]Info, 0, len(st.sessions))
	for id, s := range st.sessions {
		if dbFilter != nil && !dbFilter(s.dbName) {
			continue
		}
		out = append(out, Info{
			ID:        base64.RawURLEncoding.EncodeToString(id[:]),
			DBName:    s.dbName,
			Principal: s.principal,
			ReadOnly:  s.readOnly,
			Busy:      s.busy,
			Age:       now.Sub(s.created),
			IdleFor:   now.Sub(s.lastUsed),
		})
	}
	return out
}

// Count returns the number of live sessions (for the metrics gauge).
func (st *Store) Count() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.sessions)
}

// KillResult reports the outcome of a Kill.
type KillResult int

const (
	KillNotFound KillResult = iota // no session with that id
	KillBusy                       // a request is in flight; refused (bounded by the statement timeout)
	Killed                         // rolled back and closed
)

// Kill closes the session with the given (base64url) id — the admin KILL: it
// rolls back any open transaction and returns the pinned connection to the pool,
// making the baton unresumable. It REFUSES a session with a request in flight
// (KillBusy): tearing down a connection under an in-flight statement would misuse
// database/sql, and a runaway statement is already bounded by the per-statement
// timeout, after which the session becomes killable (or the reaper takes it).
func (st *Store) Kill(idStr string) KillResult {
	raw, err := base64.RawURLEncoding.DecodeString(idStr)
	if err != nil || len(raw) != idLen {
		return KillNotFound
	}
	var id [idLen]byte
	copy(id[:], raw)
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.sessions[id]
	if s == nil {
		return KillNotFound
	}
	if s.busy {
		return KillBusy
	}
	st.closeLocked(id)
	return Killed
}

// CloseAll tears down every idle session and WAITS for their connections to be
// rolled back and returned to their pools. The wait matters at shutdown: the
// caller closes the registry (which closes the pools, checkpointing WAL) right
// after, so the pinned connections must be back before that — otherwise the pool
// would be closed out from under an in-flight ROLLBACK.
//
// A busy session (a request in flight on its pinned conn) is deliberately skipped
// — the same rule reap and Kill follow: running ROLLBACK/Close on that conn here
// would race the in-flight request. Listeners are already draining by the time
// this runs, so a still-busy session's conn is rolled back and closed when its
// request finishes and the pool closes under it.
func (st *Store) CloseAll() {
	st.mu.Lock()
	for id, s := range st.sessions {
		if s.busy {
			continue
		}
		st.closeLocked(id)
	}
	st.mu.Unlock()
	st.closing.Wait()
}

func (st *Store) closeLocked(id [idLen]byte) {
	s := st.sessions[id]
	if s == nil {
		return
	}
	delete(st.sessions, id)
	if st.perDB[s.dbName] > 0 {
		st.perDB[s.dbName]--
	}
	// Roll back any open interactive transaction, restore the base authorizer on a
	// read-only conn (so the next pool borrower isn't left in read-only mode),
	// return the conn to the pool, then drop the registry ref. All best-effort (a
	// no-tx ROLLBACK just errors). Tracked by st.closing so CloseAll can wait.
	st.closing.Add(1)
	go func(c *sql.Conn, release func(), readOnly, attach bool, capture *sqlite.Session) {
		defer st.closing.Done()
		ctx, cancel := context.WithTimeout(context.Background(), closeRollbackTimeout)
		defer cancel()
		if capture != nil {
			_ = capture.Close() // close the SESSION handle before its connection
		}
		_, _ = c.ExecContext(ctx, "ROLLBACK")
		switch {
		case readOnly:
			// Restore base mode on a fresh context, not the ROLLBACK's (which a slow
			// rollback may have already consumed): a failed restore would return a
			// still-read-only conn to the pool, breaking a later borrower's writes.
			_ = backend.SetConnMode(context.Background(), c, false)
		case attach:
			// DETACH everything and restore the deny-ATTACH authorizer BEFORE the conn
			// returns to the pool, so an attachment from this session can't leak onto a
			// later borrower. Fresh context, same rationale as the read-only restore.
			if err := backend.ClearAttach(context.Background(), c); err != nil {
				// Cleanup was incomplete — a DETACH failed (e.g. a stuck transaction the
				// ROLLBACK couldn't clear) or the deny authorizer couldn't be restored.
				// Either leaves a fail-open connection: poison it so database/sql
				// DISCARDS it instead of returning the leaked attachment to the pool.
				_ = c.Raw(func(any) error { return driver.ErrBadConn })
			}
		}
		_ = c.Close()
		if release != nil {
			release()
		}
	}(s.conn, s.release, s.readOnly, s.attach, s.TakeCapture())
}

// StartReaper runs a background loop that closes idle / over-lifetime sessions
// until ctx is done, then tears down all remaining sessions.
func (st *Store) StartReaper(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				st.CloseAll()
				return
			case <-t.C:
				st.reap()
			}
		}
	}()
}

func (st *Store) reap() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for id, s := range st.sessions {
		if st.reapable(s) {
			st.closeLocked(id)
		}
	}
}

// reapable reports whether a session may be closed: it must NOT have a request
// in flight, and must be either idle past ttl or older than maxLife.
func (st *Store) reapable(s *Session) bool {
	if s.busy {
		return false
	}
	return time.Since(s.lastUsed) > st.ttl || time.Since(s.created) > st.maxLife
}

// mint builds an HMAC-signed baton over (id, generation).
func (st *Store) mint(id [idLen]byte, gen uint64) string {
	payload := make([]byte, idLen+8)
	copy(payload, id[:])
	binary.BigEndian.PutUint64(payload[idLen:], gen)
	mac := hmac.New(sha256.New, st.key)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(payload))
}

// verify checks a baton's signature and decodes (id, generation).
func (st *Store) verify(baton string) (id [idLen]byte, gen uint64, err error) {
	tok, e := base64.RawURLEncoding.DecodeString(baton)
	if e != nil || len(tok) != idLen+8+sha256.Size {
		return id, 0, ErrBadBaton
	}
	payload, sig := tok[:idLen+8], tok[idLen+8:]
	mac := hmac.New(sha256.New, st.key)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return id, 0, ErrBadBaton
	}
	copy(id[:], payload[:idLen])
	gen = binary.BigEndian.Uint64(payload[idLen:])
	return id, gen, nil
}
