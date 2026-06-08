package backend

import (
	"context"
	"path/filepath"
	"testing"

	"gosqlite.org/server/config"
	"gosqlite.org/server/secret"
)

// TestReadOnlyConnBlocksWrites verifies the connection-level read-only guard: a
// connection put in read-only mode rejects DML/DDL AND a writing PRAGMA, and
// restoring the base mode lets writes through again.
func TestReadOnlyConnBlocksWrites(t *testing.T) {
	sec, _ := secret.New(nil)
	be, err := For(config.Database{Name: "d", Backend: "file", Path: filepath.Join(t.TempDir(), "d.db")}, sec, "")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	db, err := be.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "CREATE TABLE t(x)"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	defer conn.Close()
	if err := SetConnMode(ctx, conn, true); err != nil {
		t.Fatalf("SetConnMode ro: %v", err)
	}

	// DML is denied.
	if _, err := conn.ExecContext(ctx, "INSERT INTO t VALUES(1)"); err == nil {
		t.Fatal("read-only conn allowed INSERT")
	}
	// A writing PRAGMA is denied (the header-writing case the DML authorizer alone misses).
	if _, err := conn.ExecContext(ctx, "PRAGMA user_version = 5"); err == nil {
		t.Fatal("read-only conn allowed a writing PRAGMA (user_version)")
	}
	// VACUUM is exempt from the authorizer entirely; query_only must block it.
	if _, err := conn.ExecContext(ctx, "VACUUM"); err == nil {
		t.Fatal("read-only conn allowed VACUUM")
	}
	// A read is still allowed (Scan fully consumes the row so the conn is released).
	var n int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM t").Scan(&n); err != nil {
		t.Fatalf("read-only conn blocked a SELECT: %v", err)
	}

	// user_version is unchanged.
	var uv int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&uv); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if uv != 0 {
		t.Fatalf("writing PRAGMA leaked: user_version = %d", uv)
	}

	// Restoring the base mode lets writes through again (no residual read-only state).
	if err := SetConnMode(ctx, conn, false); err != nil {
		t.Fatalf("SetConnMode restore: %v", err)
	}
	if _, err := conn.ExecContext(ctx, "INSERT INTO t VALUES(2)"); err != nil {
		t.Fatalf("restored conn blocked INSERT: %v", err)
	}
}
