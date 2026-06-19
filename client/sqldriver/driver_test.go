package sqldriver_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"quicsql.net/config"
	"quicsql.net/serverd"

	_ "quicsql.net/client/sqldriver"
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

// startServer stands up an in-process server with one shared-memory database
// "app" over HTTP/1.1 and a Unix socket, both with Hrana sessions enabled.
func startServer(t *testing.T) (h1, sock string) {
	t.Helper()
	h1 = freeTCP(t)
	sock = filepath.Join(t.TempDir(), "q.sock")
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
	return h1, sock
}

// TestDatabaseSQLDriver proves ordinary database/sql code connects to a remote
// quicSQL database over the "quicsql" driver — the same API you'd use for a local
// file — over both HTTP/1.1 and a Unix socket.
func TestDatabaseSQLDriver(t *testing.T) {
	h1, sock := startServer(t)
	ctx := context.Background()

	db, err := sql.Open("quicsql", "quicsql://"+h1+"/app?transport=h1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := db.ExecContext(ctx, "INSERT INTO t(name) VALUES(?)", "ada")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if id, _ := res.LastInsertId(); id != 1 {
		t.Fatalf("last insert id = %d, want 1", id)
	}

	var name string
	if err := db.QueryRowContext(ctx, "SELECT name FROM t WHERE id=?", 1).Scan(&name); err != nil {
		t.Fatalf("queryrow: %v", err)
	}
	if name != "ada" {
		t.Fatalf("name = %q, want ada", name)
	}

	// A second handle over the Unix socket sees the same shared in-memory rows.
	dbu, err := sql.Open("quicsql", "quicsql:///app?transport=unix&socket="+sock)
	if err != nil {
		t.Fatalf("sql.Open unix: %v", err)
	}
	defer dbu.Close()
	var n int
	if err := dbu.QueryRowContext(ctx, "SELECT count(*) FROM t").Scan(&n); err != nil {
		t.Fatalf("count over unix: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}

	// A bad DSN (unknown transport / wrong scheme) is rejected eagerly.
	if _, err := sql.Open("quicsql", "quicsql://x/app?transport=ftp"); err == nil {
		t.Fatal("sql.Open should reject an unknown transport")
	}
	if _, err := sql.Open("quicsql", "ftp://x/app"); err == nil {
		t.Fatal("sql.Open should reject a non-quicsql scheme")
	}
}

// TestGosqliteDispatchHook proves that importing the driver lets the built-in
// gosqlite "sqlite" driver open a quicsql:// DSN — the seamless-switch path for
// existing gosqlite users.
func TestGosqliteDispatchHook(t *testing.T) {
	h1, _ := startServer(t)
	ctx := context.Background()

	db, err := sql.Open("sqlite", "quicsql://"+h1+"/app?transport=h1")
	if err != nil {
		t.Fatalf("sql.Open sqlite: %v", err)
	}
	defer db.Close()
	var got int
	if err := db.QueryRowContext(ctx, "SELECT 42").Scan(&got); err != nil {
		t.Fatalf("query over sqlite driver: %v", err)
	}
	if got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
}

// TestTransaction proves a database/sql transaction is session-pinned: BEGIN and
// the following statements land on the same server-side connection, a rollback
// discards its writes, and a commit persists them.
func TestTransaction(t *testing.T) {
	h1, _ := startServer(t)
	ctx := context.Background()
	db, err := sql.Open("quicsql", "quicsql://"+h1+"/app?transport=h1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "CREATE TABLE acct(id INTEGER PRIMARY KEY, bal INTEGER)"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Rolled-back transaction leaves no trace. Reading the row back inside the
	// same transaction proves BEGIN and the INSERT ran on one pinned session (a
	// stateless autocommit request would not see the uncommitted row).
	txr, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := txr.ExecContext(ctx, "INSERT INTO acct(id, bal) VALUES(1, 100)"); err != nil {
		t.Fatalf("insert in tx: %v", err)
	}
	var own int
	if err := txr.QueryRowContext(ctx, "SELECT count(*) FROM acct").Scan(&own); err != nil {
		t.Fatalf("read own write in tx: %v", err)
	}
	if own != 1 {
		t.Fatalf("in-tx count = %d, want 1 (statements not pinned to one session)", own)
	}
	if err := txr.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var afterRollback int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM acct").Scan(&afterRollback); err != nil {
		t.Fatalf("count after rollback: %v", err)
	}
	if afterRollback != 0 {
		t.Fatalf("rollback did not discard: count=%d", afterRollback)
	}

	// Committed transaction persists.
	txc, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin 2: %v", err)
	}
	if _, err := txc.ExecContext(ctx, "INSERT INTO acct(id, bal) VALUES(2, 250)"); err != nil {
		t.Fatalf("insert 2: %v", err)
	}
	var inTx int
	if err := txc.QueryRowContext(ctx, "SELECT bal FROM acct WHERE id=2").Scan(&inTx); err != nil {
		t.Fatalf("read own write in tx: %v", err)
	}
	if inTx != 250 {
		t.Fatalf("in-tx read = %d, want 250", inTx)
	}
	if err := txc.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var bal int
	if err := db.QueryRowContext(ctx, "SELECT bal FROM acct WHERE id=2").Scan(&bal); err != nil {
		t.Fatalf("read after commit: %v", err)
	}
	if bal != 250 {
		t.Fatalf("committed balance = %d, want 250", bal)
	}
}

// TestConstraintErrorSurface proves a UNIQUE violation surfaces an error that
// exposes SQLite's extended result code — both on the autocommit path and inside
// a transaction (the Hrana path) — which is what an ORM keys off to classify it.
func TestConstraintErrorSurface(t *testing.T) {
	h1, _ := startServer(t)
	ctx := context.Background()
	db, err := sql.Open("quicsql", "quicsql://"+h1+"/app?transport=h1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "CREATE TABLE u(id INTEGER PRIMARY KEY, email TEXT UNIQUE)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO u(id, email) VALUES(1, 'a@x')"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const uniqueExt = 2067 // SQLITE_CONSTRAINT_UNIQUE

	// Autocommit path.
	_, err = db.ExecContext(ctx, "INSERT INTO u(id, email) VALUES(2, 'a@x')")
	if got := extendedCode(err); got != uniqueExt {
		t.Fatalf("autocommit: extended code = %d, want %d (err=%v)", got, uniqueExt, err)
	}

	// Transaction (Hrana) path.
	txx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer txx.Rollback()
	_, err = txx.ExecContext(ctx, "INSERT INTO u(id, email) VALUES(3, 'a@x')")
	if got := extendedCode(err); got != uniqueExt {
		t.Fatalf("in-tx: extended code = %d, want %d (err=%v)", got, uniqueExt, err)
	}
}

// extendedCode extracts a SQLite extended result code from err via the
// ExtendedCode() interface the driver's error type implements.
func extendedCode(err error) int {
	if ec, ok := errors.AsType[interface {
		error
		ExtendedCode() int
	}](err); ok {
		return ec.ExtendedCode()
	}
	return -1
}
