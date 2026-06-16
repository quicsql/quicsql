package client_test

import (
	"context"
	"fmt"
	"testing"

	"gosqlite.org/server/client"
	"gosqlite.org/server/config"
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
