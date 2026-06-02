package engine

import (
	"context"
	"testing"

	"gosqlite.org"
)

// pinnedMem opens a one-connection in-memory DB so all statements share it.
func pinnedMem(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(sqlite.Config{Path: sqlite.InMemory, MaxOpenConns: 1})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestResultCaps regresses the unbounded-buffer DoS: a result is bounded by both
// the row cap and the byte cap, marking Truncated.
func TestResultCaps(t *testing.T) {
	db := pinnedMem(t)
	ctx := context.Background()
	e := New(3, 0) // 3-row cap; default byte cap
	if _, err := e.Exec(ctx, db, Statement{SQL: "CREATE TABLE t(x)"}); err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		if _, err := e.Exec(ctx, db, Statement{SQL: "INSERT INTO t VALUES(?)", Args: []Value{Int(int64(i))}}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := e.Query(ctx, db, Statement{SQL: "SELECT x FROM t"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Rows) != 3 {
		t.Fatalf("row cap: want truncated with 3 rows, got truncated=%v rows=%d", res.Truncated, len(res.Rows))
	}

	eb := New(0, 10) // 10-byte cap; each int cell counts as 8
	rb, err := eb.Query(ctx, db, Statement{SQL: "SELECT x FROM t"})
	if err != nil {
		t.Fatal(err)
	}
	if !rb.Truncated {
		t.Fatalf("byte cap: want truncated, got %d rows not truncated", len(rb.Rows))
	}
}

// TestRunDeniesAttach regresses the ATTACH/DETACH filesystem-escape.
func TestRunDeniesAttach(t *testing.T) {
	db := pinnedMem(t)
	ctx := context.Background()
	for _, sql := range []string{"ATTACH DATABASE '/tmp/x.db' AS y", "  detach database y"} {
		if _, err := New(0, 0).Run(ctx, db, Statement{SQL: sql}); err == nil {
			t.Errorf("%q: want denial, got nil", sql)
		}
	}
	// A normal statement is not denied.
	if _, err := New(0, 0).Run(ctx, db, Statement{SQL: "SELECT 1"}); err != nil {
		t.Errorf("SELECT denied unexpectedly: %v", err)
	}
}
