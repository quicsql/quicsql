package sqldriver_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// TestNamedParamsRejected proves the driver rejects a named parameter (the wire
// endpoints bind positionally, so a silent coercion to ordinal would mis-bind).
func TestNamedParamsRejected(t *testing.T) {
	h1, _ := startServer(t)
	ctx := context.Background()
	db, err := sql.Open("quicsql", "quicsql://"+h1+"/app?transport=h1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	_, err = db.QueryContext(ctx, "SELECT :x", sql.Named("x", 1))
	if err == nil {
		t.Fatal("expected a named parameter to be rejected")
	}
	if !strings.Contains(err.Error(), "named parameter") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestFloatBindsReal is the CODEC-1 end-to-end guard: an
// integral float64 (100.0) bound through the driver must store as REAL both on the
// stateless native endpoint (autocommit) and on the Hrana pinned stream (inside a
// transaction). Before the shared wire codec, the native path stored it as INTEGER.
func TestFloatBindsReal(t *testing.T) {
	h1, _ := startServer(t)
	ctx := context.Background()

	db, err := sql.Open("quicsql", "quicsql://"+h1+"/app?transport=h1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	var got string
	if err := db.QueryRowContext(ctx, "SELECT typeof(?)", 100.0).Scan(&got); err != nil {
		t.Fatalf("autocommit query: %v", err)
	}
	if got != "real" {
		t.Fatalf("autocommit typeof(100.0) = %q, want real", got)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.QueryRowContext(ctx, "SELECT typeof(?)", 100.0).Scan(&got); err != nil {
		t.Fatalf("tx query: %v", err)
	}
	if got != "real" {
		t.Fatalf("transaction typeof(100.0) = %q, want real", got)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
