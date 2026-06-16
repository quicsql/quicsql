package client_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"gosqlite.org/server/client"
	"gosqlite.org/server/config"
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

// TestClientRoundTripH1AndUnix starts an in-process server over HTTP/1.1 and a
// Unix socket, then exercises the client's CRUD surface over both wires against a
// shared in-memory database (so a write on one is visible on the other).
func TestClientRoundTripH1AndUnix(t *testing.T) {
	h1 := freeTCP(t)
	sock := filepath.Join(t.TempDir(), "q.sock")
	cfg := &config.Config{
		Databases: []config.Database{{Name: "app", Backend: "memory-shared"}},
		Listeners: []config.Listener{
			{Name: "h1", Transport: "h1", Address: h1},
			{Name: "u", Transport: "unix", Address: sock},
		},
	}
	srv, err := serverd.Run(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("serverd.Run: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })

	ctx := context.Background()
	h := client.H1(h1)
	defer h.Close()
	u := client.Unix(sock)
	defer u.Close()

	// Write over HTTP/1.1.
	if _, err := h.Exec(ctx, "app", "CREATE TABLE kv(k TEXT PRIMARY KEY, v TEXT, n INT, b BLOB)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := h.Exec(ctx, "app", "INSERT INTO kv VALUES(?,?,?,?)", "a", "hello", 7, []byte{1, 2, 3}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Read it back over the Unix socket (shared in-memory → visible across wires).
	res, err := u.Query(ctx, "app", "SELECT k, v, n, b FROM kv")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Rows) != 1 || len(res.Rows[0]) != 4 {
		t.Fatalf("want 1 row of 4 cols, got %+v", res.Rows)
	}
	row := res.Rows[0]
	if row[0] != "a" || row[1] != "hello" {
		t.Fatalf("text cells: %+v", row)
	}
	if n, ok := row[2].(interface{ Int64() (int64, error) }); ok {
		if v, _ := n.Int64(); v != 7 {
			t.Fatalf("int cell = %v, want 7", v)
		}
	} else {
		t.Fatalf("int cell type %T", row[2])
	}
	if b, ok := row[3].([]byte); !ok || len(b) != 3 || b[0] != 1 {
		t.Fatalf("blob cell = %v (%T)", row[3], row[3])
	}

	// A SQL error surfaces as an error.
	if _, err := h.Query(ctx, "app", "SELECT * FROM does_not_exist"); err == nil {
		t.Fatal("expected an error for a missing table")
	}
	// An unknown database is a transport error (404).
	if _, err := h.Query(ctx, "nope", "SELECT 1"); err == nil {
		t.Fatal("expected an error for an unknown database")
	}
}
