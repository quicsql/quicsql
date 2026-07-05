package client_test

import (
	"context"
	"fmt"
	"testing"

	"quicsql.net/client"
	"quicsql.net/config"
)

// TestChangesetCaptureApply proves the SESSION/changeset wire protocol: capture a
// changeset of writes on one database (over a pinned stream), then replicate it
// onto a second database by applying the bytes.
func TestChangesetCaptureApply(t *testing.T) {
	skipUnderRace(t)
	addr := freeTCP(t)
	runServer(t, &config.Config{
		Databases: []config.Database{
			{Name: "src", Backend: "memory-shared"},
			{Name: "dst", Backend: "memory-shared"},
		},
		Listeners: []config.Listener{{Name: "h1", Transport: "h1", Address: addr}},
	})
	ctx := context.Background()

	cl := client.H1(addr)
	defer cl.Close()

	const ddl = `CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)`
	if _, err := cl.Exec(ctx, "src", ddl); err != nil {
		t.Fatalf("create src: %v", err)
	}
	if _, err := cl.Exec(ctx, "dst", ddl); err != nil {
		t.Fatalf("create dst: %v", err)
	}

	// Capture the inserts on src over a pinned stream.
	st := cl.OpenStream("src")
	if err := st.SessionStart(ctx, []string{"t"}); err != nil {
		t.Fatalf("session start: %v", err)
	}
	if _, err := st.Exec(ctx, `INSERT INTO t(id, v) VALUES(1, 'ada')`, nil); err != nil {
		t.Fatalf("insert 1: %v", err)
	}
	if _, err := st.Exec(ctx, `INSERT INTO t(id, v) VALUES(2, 'grace')`, nil); err != nil {
		t.Fatalf("insert 2: %v", err)
	}
	cs, err := st.SessionChangeset(ctx)
	if err != nil {
		t.Fatalf("changeset: %v", err)
	}
	if err := st.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(cs) == 0 {
		t.Fatal("captured changeset is empty")
	}

	// dst is empty before apply.
	if res, _ := cl.Query(ctx, "dst", `SELECT count(*) FROM t`); fmt.Sprint(res.Rows[0][0]) != "0" {
		t.Fatalf("dst not empty before apply: %v", res.Rows)
	}

	// Apply to dst and verify the two rows replicated.
	if err := cl.ApplyChangeset(ctx, "dst", cs); err != nil {
		t.Fatalf("apply: %v", err)
	}
	res, err := cl.Query(ctx, "dst", `SELECT v FROM t ORDER BY id`)
	if err != nil {
		t.Fatalf("query dst: %v", err)
	}
	if len(res.Rows) != 2 || fmt.Sprint(res.Rows[0][0]) != "ada" || fmt.Sprint(res.Rows[1][0]) != "grace" {
		t.Fatalf("dst rows after apply = %v, want [ada grace]", res.Rows)
	}
}

// TestChangesetApplyOptions exercises the on_conflict policy and the table filter:
// a changeset whose id=1 collides with a pre-seeded row is aborted by default,
// skipped under "omit", and overwrites under "replace"; a tables filter applies
// only the named table.
func TestChangesetApplyOptions(t *testing.T) {
	skipUnderRace(t)
	addr := freeTCP(t)
	runServer(t, &config.Config{
		Databases: []config.Database{
			{Name: "src", Backend: "memory-shared"},
			{Name: "d_abort", Backend: "memory-shared"},
			{Name: "d_omit", Backend: "memory-shared"},
			{Name: "d_replace", Backend: "memory-shared"},
			{Name: "d_tables", Backend: "memory-shared"},
		},
		Listeners: []config.Listener{{Name: "h1", Transport: "h1", Address: addr}},
	})
	ctx := context.Background()
	cl := client.H1(addr)
	defer cl.Close()

	const ddl = `CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); CREATE TABLE u(id INTEGER PRIMARY KEY, v TEXT)`
	for _, db := range []string{"src", "d_abort", "d_omit", "d_replace", "d_tables"} {
		if _, err := cl.Exec(ctx, db, ddl); err != nil {
			t.Fatalf("ddl %s: %v", db, err)
		}
	}
	// Pre-seed a CONFLICTING row (id=1) in the conflict-policy targets.
	for _, db := range []string{"d_abort", "d_omit", "d_replace"} {
		if _, err := cl.Exec(ctx, db, `INSERT INTO t(id, v) VALUES(1, 'OLD')`); err != nil {
			t.Fatalf("seed %s: %v", db, err)
		}
	}

	// Capture a changeset on src touching BOTH tables: t gets id=1 (will collide) +
	// id=2; u gets id=9.
	st := cl.OpenStream("src")
	if err := st.SessionStart(ctx, nil); err != nil { // nil ⇒ track all tables
		t.Fatalf("session start: %v", err)
	}
	if _, err := st.Exec(ctx, `INSERT INTO t(id, v) VALUES(1, 'ada'), (2, 'grace')`, nil); err != nil {
		t.Fatalf("insert t: %v", err)
	}
	if _, err := st.Exec(ctx, `INSERT INTO u(id, v) VALUES(9, 'nine')`, nil); err != nil {
		t.Fatalf("insert u: %v", err)
	}
	cs, err := st.SessionChangeset(ctx)
	if err != nil {
		t.Fatalf("changeset: %v", err)
	}
	if err := st.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	// abort (default): the id=1 conflict rolls the WHOLE apply back → error, target unchanged.
	if err := cl.ApplyChangeset(ctx, "d_abort", cs); err == nil {
		t.Fatal("apply with default abort should fail on the PK conflict")
	}
	if got := scalar(t, cl, "d_abort", `SELECT count(*) FROM t`); got != "1" {
		t.Fatalf("d_abort t count = %s, want 1 (apply rolled back)", got)
	}

	// omit: the conflicting id=1 is skipped, id=2 applied.
	if err := cl.ApplyChangeset(ctx, "d_omit", cs, client.OnConflict("omit")); err != nil {
		t.Fatalf("apply omit: %v", err)
	}
	if got := scalar(t, cl, "d_omit", `SELECT v FROM t WHERE id=1`); got != "OLD" {
		t.Fatalf("omit should keep id=1: got %s, want OLD", got)
	}
	if got := scalar(t, cl, "d_omit", `SELECT v FROM t WHERE id=2`); got != "grace" {
		t.Fatalf("omit should apply id=2: got %s, want grace", got)
	}

	// replace: the conflicting id=1 is overwritten.
	if err := cl.ApplyChangeset(ctx, "d_replace", cs, client.OnConflict("replace")); err != nil {
		t.Fatalf("apply replace: %v", err)
	}
	if got := scalar(t, cl, "d_replace", `SELECT v FROM t WHERE id=1`); got != "ada" {
		t.Fatalf("replace should overwrite id=1: got %s, want ada", got)
	}

	// tables filter: only table t is applied; u is untouched.
	if err := cl.ApplyChangeset(ctx, "d_tables", cs, client.ApplyToTables("t")); err != nil {
		t.Fatalf("apply tables filter: %v", err)
	}
	if got := scalar(t, cl, "d_tables", `SELECT count(*) FROM t`); got != "2" {
		t.Fatalf("tables filter: t count = %s, want 2", got)
	}
	if got := scalar(t, cl, "d_tables", `SELECT count(*) FROM u`); got != "0" {
		t.Fatalf("tables filter: u count = %s, want 0 (filtered out)", got)
	}
}

// scalar runs a single-value query and returns the first cell as a string.
func scalar(t *testing.T, cl *client.Client, db, sql string) string {
	t.Helper()
	res, err := cl.Query(context.Background(), db, sql)
	if err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	if len(res.Rows) == 0 || len(res.Rows[0]) == 0 {
		t.Fatalf("query %q returned no cell", sql)
	}
	return fmt.Sprint(res.Rows[0][0])
}
