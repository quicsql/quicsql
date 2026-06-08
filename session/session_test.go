package session

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"gosqlite.org/server/backend"
	"gosqlite.org/server/config"
	"gosqlite.org/server/registry"
	"gosqlite.org/server/secret"
)

func testDB(t *testing.T) (*registry.DB, func()) {
	t.Helper()
	sec, _ := secret.New(nil)
	be, err := backend.For(config.Database{Name: "d", Backend: "file", Path: filepath.Join(t.TempDir(), "d.db")}, sec, "")
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{"d": be}, nil)
	db, release, err := reg.Get(context.Background(), "d")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return db, func() { release(); _ = reg.Close() }
}

func TestBatonMintVerifyAndForgery(t *testing.T) {
	st, _ := NewStore(time.Minute, time.Minute, 10)
	var id [idLen]byte
	id[0], id[15] = 1, 9
	b := st.mint(id, 5)
	gotID, gen, err := st.verify(b)
	if err != nil || gotID != id || gen != 5 {
		t.Fatalf("roundtrip: id=%v gen=%d err=%v", gotID, gen, err)
	}
	if _, _, err := st.verify("X" + b[1:]); err != ErrBadBaton { // tampered
		t.Fatalf("forged baton: want ErrBadBaton, got %v", err)
	}
	if _, _, err := st.verify("!!not-base64!!"); err != ErrBadBaton {
		t.Fatalf("garbage baton: want ErrBadBaton, got %v", err)
	}
}

func TestResumeConsumesBatonAndRejectsReplay(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()
	st, _ := NewStore(time.Minute, time.Minute, 10)
	s, err := st.Open(context.Background(), db, func() {}, "", false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	b0 := st.Baton(s)
	if _, err := st.Resume(b0, "d", ""); err != nil { // consumes b0, bumps gen
		t.Fatalf("Resume: %v", err)
	}
	if _, err := st.Resume(b0, "d", ""); err != ErrBadBaton { // replay of consumed baton
		t.Fatalf("replay: want ErrBadBaton, got %v", err)
	}
	if _, err := st.Resume(st.Baton(s), "d", ""); err != nil { // the rotated baton works
		t.Fatalf("rotated baton: %v", err)
	}
}

// TestResumeBindingChecksDoNotConsume regresses the DoS where a wrong-principal
// (or wrong-database) resume attempt burned the owner's live baton: the binding
// checks must reject WITHOUT bumping the generation, so the owner's baton stays
// valid.
func TestResumeBindingChecksDoNotConsume(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()
	st, _ := NewStore(time.Minute, time.Minute, 10)
	s, err := st.Open(context.Background(), db, func() {}, "owner", false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	b := st.Baton(s)
	if _, err := st.Resume(b, "d", "intruder"); err != ErrPrincipalMismatch {
		t.Fatalf("wrong principal: want ErrPrincipalMismatch, got %v", err)
	}
	if _, err := st.Resume(b, "other-db", "owner"); err != ErrBadBaton {
		t.Fatalf("wrong database: want ErrBadBaton, got %v", err)
	}
	// The baton was NOT consumed by the rejected attempts — the owner can use it.
	if _, err := st.Resume(b, "d", "owner"); err != nil {
		t.Fatalf("owner baton should survive rejected attempts: %v", err)
	}
}

func TestResumeExpiry(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()
	st, _ := NewStore(time.Millisecond, time.Minute, 10)
	s, err := st.Open(context.Background(), db, func() {}, "", false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	b0 := st.Baton(s)
	time.Sleep(15 * time.Millisecond)
	if _, err := st.Resume(b0, "d", ""); err != ErrBadBaton {
		t.Fatalf("expired baton: want ErrBadBaton, got %v", err)
	}
}

func TestReaperRollsBackAndReleases(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()
	released := make(chan struct{})
	st, _ := NewStore(time.Millisecond, time.Minute, 10)
	s, err := st.Open(context.Background(), db, func() { close(released) }, "", false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	for _, sql := range []string{"CREATE TABLE t(x)", "BEGIN", "INSERT INTO t VALUES(1)"} {
		if _, err := s.Conn().ExecContext(ctx, sql); err != nil {
			t.Fatalf("%q: %v", sql, err)
		}
	}
	st.Baton(s) // clear the in-flight (busy) flag so the reaper may act
	time.Sleep(10 * time.Millisecond)
	st.reap()

	select {
	case <-released: // pinned conn returned + registry ref dropped
	case <-time.After(2 * time.Second):
		t.Fatal("reaper did not release the session")
	}
	var n int
	if err := db.Handle.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil {
		t.Fatalf("query after reap: %v", err)
	}
	if n != 0 {
		t.Fatalf("reaper should have rolled back the open tx: count %d", n)
	}
}

func TestReaperSkipsInFlightSession(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()
	st, _ := NewStore(time.Millisecond, time.Minute, 10)
	s, err := st.Open(context.Background(), db, func() {}, "", false) // busy=true (a request is "in flight")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	st.reap()
	st.mu.Lock()
	_, present := st.sessions[s.id]
	st.mu.Unlock()
	if !present {
		t.Fatal("reaper closed a session with a request in flight")
	}
	st.Baton(s) // finish the request → now reapable
	time.Sleep(10 * time.Millisecond)
	st.reap()
	st.mu.Lock()
	_, present = st.sessions[s.id]
	st.mu.Unlock()
	if present {
		t.Fatal("reaper failed to close an idle session")
	}
}

func TestOpenTooMany(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()
	st, _ := NewStore(time.Minute, time.Minute, 1)
	if _, err := st.Open(context.Background(), db, func() {}, "", false); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := st.Open(context.Background(), db, func() {}, "", false); err != ErrTooMany {
		t.Fatalf("second Open: want ErrTooMany, got %v", err)
	}
}
