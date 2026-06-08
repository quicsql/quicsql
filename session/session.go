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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"gosqlite.org/server/backend"
	"gosqlite.org/server/registry"
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
	created   time.Time
	lastUsed  time.Time
	busy      bool
	sql       map[int32]string // store_sql cache
}

// Conn returns the pinned connection the engine runs statements on.
func (s *Session) Conn() *sql.Conn { return s.conn }

// DBName is the database this session is bound to.
func (s *Session) DBName() string { return s.dbName }

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
}

// NewStore builds a session store with a random baton-signing key. ttl is the
// idle timeout; maxLife caps a session's total lifetime (so a client can't hold
// the writer forever with keepalives); max bounds concurrent sessions per db.
func NewStore(ttl, maxLife time.Duration, max int) (*Store, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if max <= 0 {
		max = 64
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
func (st *Store) Open(ctx context.Context, db *registry.DB, release func(), principal string, readOnly bool) (*Session, error) {
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
	if readOnly {
		if err := backend.SetConnMode(ctx, conn, true); err != nil {
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
		principal: principal, readOnly: readOnly,
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

// Close ends a session: rolls back any open transaction and returns the pinned
// connection to the pool.
func (st *Store) Close(s *Session) {
	st.mu.Lock()
	st.closeLocked(s.id)
	st.mu.Unlock()
}

// CloseAll tears down every session (server shutdown).
func (st *Store) CloseAll() {
	st.mu.Lock()
	for id := range st.sessions {
		st.closeLocked(id)
	}
	st.mu.Unlock()
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
	// no-tx ROLLBACK just errors).
	go func(c *sql.Conn, release func(), readOnly bool) {
		ctx, cancel := context.WithTimeout(context.Background(), closeRollbackTimeout)
		defer cancel()
		_, _ = c.ExecContext(ctx, "ROLLBACK")
		if readOnly {
			_ = backend.SetConnMode(ctx, c, false)
		}
		_ = c.Close()
		if release != nil {
			release()
		}
	}(s.conn, s.release, s.readOnly)
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
