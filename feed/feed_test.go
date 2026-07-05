package feed

import (
	"path/filepath"
	"testing"
	"time"

	sqlite "gosqlite.org"
)

func sqliteOpen(path string) (*sqlite.DB, error) {
	return sqlite.Open(sqlite.Config{Path: path})
}

func collect(t *testing.T, s *Subscriber, n int) []Event {
	t.Helper()
	out := make([]Event, 0, n)
	timeout := time.After(5 * time.Second)
	for len(out) < n {
		select {
		case e, ok := <-s.C:
			if !ok {
				t.Fatalf("subscriber closed after %d/%d events", len(out), n)
			}
			out = append(out, e)
		case <-timeout:
			t.Fatalf("timed out after %d/%d events", len(out), n)
		}
	}
	return out
}

// The real thing: a file-backed database with the AutoHook installed — commits
// publish, rollbacks vanish, sequences are monotonic.
func TestHooksEndToEnd(t *testing.T) {
	b := New(64, 8, nil)
	b.Install()
	path := filepath.Join(t.TempDir(), "feed.db")
	b.Register("appdb", path)

	db, err := sqlite.Open(sqlite.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}

	sub, replay, reset, ok, full, _ := b.Subscribe("appdb", 0)
	if !ok || full || reset || len(replay) != 0 {
		t.Fatalf("subscribe: ok=%v full=%v reset=%v replay=%d", ok, full, reset, len(replay))
	}
	defer sub.Close()

	// Autocommit inserts/updates/deletes each publish at their implicit commit.
	if _, err := db.Exec(`INSERT INTO t(v) VALUES ('a')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE t SET v = 'b' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM t WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	got := collect(t, sub, 3)
	wantOps := []string{"insert", "update", "delete"}
	for i, e := range got {
		if e.Op != wantOps[i] || e.Table != "t" || e.Rowid != 1 || e.Seq != uint64(i+1) {
			t.Fatalf("event %d = %+v", i, e)
		}
	}

	// A rolled-back transaction must publish nothing; the next commit publishes
	// only its own writes.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO t(v) VALUES ('ghost')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx2, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx2.Exec(`INSERT INTO t(v) VALUES ('real1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx2.Exec(`INSERT INTO t(v) VALUES ('real2')`); err != nil {
		t.Fatal(err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatal(err)
	}
	got = collect(t, sub, 2)
	if got[0].Op != "insert" || got[1].Op != "insert" || got[0].Seq != 4 || got[1].Seq != 5 {
		t.Fatalf("post-rollback events = %+v", got)
	}
}

func TestReplayAndReset(t *testing.T) {
	b := New(4, 8, nil) // tiny ring to force reset
	b.Register("db", "/x/db.sqlite")
	f := b.byName["db"]

	events := make([]Event, 10)
	for i := range events {
		events[i] = Event{Table: "t", Op: "insert", Rowid: int64(i + 1)}
	}
	f.publish(events) // seq 1..10, ring holds 7..10

	// A recent horizon replays exactly the missed events.
	_, replay, reset, ok, _, _ := b.Subscribe("db", 8)
	if !ok || reset || len(replay) != 2 || replay[0].Seq != 9 || replay[1].Seq != 10 {
		t.Fatalf("replay from 8: reset=%v replay=%+v", reset, replay)
	}
	// A horizon that left the ring gets reset.
	if _, _, reset, _, _, _ := b.Subscribe("db", 2); !reset {
		t.Fatal("expected reset for an evicted horizon")
	}
	// A horizon from a previous incarnation (ahead of seq) also resets.
	if _, _, reset, _, _, _ := b.Subscribe("db", 99); !reset {
		t.Fatal("expected reset for a future horizon")
	}
	// Caught up exactly: no replay, no reset.
	if _, replay, reset, _, _, _ := b.Subscribe("db", 10); reset || len(replay) != 0 {
		t.Fatalf("caught-up subscribe: reset=%v replay=%d", reset, len(replay))
	}
}

func TestSubscriberCapAndSlowConsumerDrop(t *testing.T) {
	b := New(16, 1, nil)
	b.Register("db", "/x/cap.sqlite")
	f := b.byName["db"]

	s1, _, _, ok, full, _ := b.Subscribe("db", 0)
	if !ok || full {
		t.Fatal("first subscribe should succeed")
	}
	if _, _, _, _, full, _ := b.Subscribe("db", 0); !full {
		t.Fatal("second subscribe should hit the cap")
	}

	// Fill the subscriber's channel past capacity without reading: it gets
	// dropped (closed) instead of blocking the publisher.
	burst := make([]Event, subscriberBuf+1)
	for i := range burst {
		burst[i] = Event{Table: "t", Op: "insert", Rowid: int64(i)}
	}
	f.publish(burst)
	drained := 0
	for range s1.C {
		drained++
	}
	if drained != subscriberBuf {
		t.Fatalf("drained %d, want %d then close", drained, subscriberBuf)
	}
	// The dropped subscriber's slot is free again.
	if _, _, _, ok, full, _ := b.Subscribe("db", 0); !ok || full {
		t.Fatal("slot should be free after drop")
	}
}

// A single transaction that overflows the per-transaction buffer must publish
// exactly ONE reset marker (not per-row events, not an OOM's worth of retained
// rows), and subscribers keep following afterward.
func TestPendingOverflowPublishesReset(t *testing.T) {
	b := New(64, 8, nil)
	b.Install()
	path := filepath.Join(t.TempDir(), "overflow.db")
	b.Register("db", path)

	db, err := sqlite.Open(sqlite.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}

	sub, _, _, _, _, _ := b.Subscribe("db", 0)
	defer sub.Close()
	// Drain the CREATE TABLE's (zero) events; then one big transaction of more
	// than maxPending inserts.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO t DEFAULT VALUES`)
	if err != nil {
		t.Fatal(err)
	}
	for range maxPending + 50 {
		if _, err := stmt.Exec(); err != nil {
			t.Fatal(err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Exactly one reset, no per-row events.
	e := collect(t, sub, 1)[0]
	if !e.Reset {
		t.Fatalf("overflow should publish a reset marker, got %+v", e)
	}
	// A subsequent normal write still flows as a change event on the next seq.
	if _, err := db.Exec(`INSERT INTO t DEFAULT VALUES`); err != nil {
		t.Fatal(err)
	}
	next := collect(t, sub, 1)[0]
	if next.Reset || next.Op != "insert" || next.Seq != e.Seq+1 {
		t.Fatalf("post-overflow event = %+v (reset seq was %d)", next, e.Seq)
	}
}

func TestForgetClosesSubscribers(t *testing.T) {
	b := New(16, 8, nil)
	b.Register("db", "/x/f.sqlite")
	s, _, _, _, _, _ := b.Subscribe("db", 0)
	b.Forget("db")
	if _, open := <-s.C; open {
		t.Fatal("subscriber should be closed on Forget")
	}
	if b.Observed("db") {
		t.Fatal("db should no longer be observed")
	}
}
