package client_test

import (
	"bytes"
	"context"
	"database/sql"
	"testing"

	sqlite "gosqlite.org" // registers the local "sqlite" driver for the round-trip
	"gosqlite.org/server/client"
	"gosqlite.org/server/config"
)

// TestExportRoundTrip proves the /export endpoint returns a real SQLite image: it
// seeds a remote database, exports it, then deserializes the bytes into a fresh
// LOCAL database and reads the rows back.
func TestExportRoundTrip(t *testing.T) {
	skipUnderRace(t)
	addr := freeTCP(t)
	runServer(t, &config.Config{
		Databases: []config.Database{{Name: "app", Backend: "memory-shared"}},
		Listeners: []config.Listener{{Name: "h1", Transport: "h1", Address: addr}},
	})
	ctx := context.Background()

	cl := client.H1(addr)
	defer cl.Close()
	if _, err := cl.Exec(ctx, "app", `CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, n := range []string{"ada", "grace", "linus"} {
		if _, err := cl.Exec(ctx, "app", `INSERT INTO t(name) VALUES(?)`, n); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	data, err := cl.Export(ctx, "app")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("SQLite format 3\x00")) {
		t.Fatalf("export is not a SQLite image (len=%d)", len(data))
	}

	// Round-trip: deserialize into a fresh local database and read the rows back.
	// The round-trip runs on one pinned connection: Deserialize targets a single
	// connection, and (only because this test shares a process with the server) we
	// clear the server's process-global ATTACH/DETACH authorizer on it, which
	// Deserialize would otherwise trip. A real client process has no such hook.
	local, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open local: %v", err)
	}
	defer local.Close()
	local.SetMaxOpenConns(1)
	conn, err := local.Conn(ctx)
	if err != nil {
		t.Fatalf("local conn: %v", err)
	}
	defer conn.Close()
	if err := conn.Raw(func(dc any) error {
		c := dc.(*sqlite.Conn)
		c.RegisterAuthorizer(func(int, string, string, string, string) int { return sqlite.SQLITE_OK })
		return c.Deserialize(data)
	}); err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("query restored db: %v", err)
	}
	if n != 3 {
		t.Fatalf("restored row count = %d, want 3", n)
	}

	// The endpoint is gated: an unknown database is refused.
	if _, err := cl.Export(ctx, "nope"); err == nil {
		t.Fatal("export of an unknown database should error")
	}
}
