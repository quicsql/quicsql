package extensions_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"

	"gosqlite.org/server/client"
	"gosqlite.org/server/config"
	_ "gosqlite.org/server/extensions" // registers the bundle on every server connection
	"gosqlite.org/server/serverd"
)

func freeTCP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// TestBundleThroughServer proves the standard bundle's extensions are usable via
// SQL on a live server: a function extension (REGEXP), a bundled virtual-table
// extension (vec0), and the engine-native FTS5.
func TestBundleThroughServer(t *testing.T) {
	addr := freeTCP(t)
	cfg := &config.Config{
		Databases: []config.Database{{Name: "app", Backend: "memory-shared"}},
		Listeners: []config.Listener{{Name: "h1", Transport: "h1", Address: addr}},
	}
	srv, err := serverd.Run(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("serverd.Run: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })

	cl := client.H1(addr)
	defer cl.Close()
	ctx := context.Background()

	// REGEXP (gosqlite.org/ext/regexp) — a scalar function extension. A missing
	// function would surface "no such function: regexp".
	res, err := cl.Query(ctx, "app", `SELECT 'foobar' REGEXP '^foo'`)
	if err != nil {
		t.Fatalf("REGEXP query: %v", err)
	}
	if len(res.Rows) != 1 || fmt.Sprint(res.Rows[0][0]) != "1" {
		t.Fatalf("REGEXP result = %v, want [[1]]", res.Rows)
	}

	// vec0 (gosqlite.org/vec) — a virtual-table extension.
	if _, err := cl.Exec(ctx, "app", `CREATE VIRTUAL TABLE v USING vec0(embedding float[3])`); err != nil {
		t.Fatalf("vec0 create: %v", err)
	}

	// FTS5 — built into the engine, so it works with no bundle import at all.
	if _, err := cl.Exec(ctx, "app", `CREATE VIRTUAL TABLE docs USING fts5(body)`); err != nil {
		t.Fatalf("fts5 create: %v", err)
	}
}
