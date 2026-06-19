package client_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"quicsql.net/client"
	"quicsql.net/config"
)

// TestBatch runs several statements in one request and verifies they all execute
// in order and persist — i.e. the batch really ran on the server, not locally.
func TestBatch(t *testing.T) {
	addr := freeTCP(t)
	runServer(t, &config.Config{
		Databases: []config.Database{{Name: "app", Backend: "memory-shared"}},
		Listeners: []config.Listener{{Name: "h1", Transport: "h1", Address: addr}},
	})
	ctx := context.Background()
	c := client.H1(addr)
	defer c.Close()

	if _, err := c.Exec(ctx, "app", `CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := c.Batch(ctx, "app", []client.Statement{
		{SQL: `INSERT INTO t VALUES (1, 'a')`},
		{SQL: `INSERT INTO t VALUES (?, ?)`, Args: []any{2, "b"}},
		{SQL: `INSERT INTO t VALUES (3, 'c')`},
		{SQL: `SELECT count(*) FROM t`},
	})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if len(res) != 4 {
		t.Fatalf("got %d results, want 4 (one per statement, close ack dropped)", len(res))
	}
	if got := fmt.Sprint(res[3].Rows[0][0]); got != "3" {
		t.Fatalf("count(*) = %s, want 3", got)
	}
	// The writes are visible to a later, separate request — the batch committed on
	// the server and its session was torn down without leaking.
	q, err := c.Query(ctx, "app", `SELECT v FROM t ORDER BY id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(q.Rows) != 3 {
		t.Fatalf("got %d rows after batch, want 3", len(q.Rows))
	}
}

// TestBatchErrorIndex proves a failing statement surfaces as an error tagged with
// its position, and that the batch is not atomic (earlier statements stand).
func TestBatchErrorIndex(t *testing.T) {
	addr := freeTCP(t)
	runServer(t, &config.Config{
		Databases: []config.Database{{Name: "app", Backend: "memory-shared"}},
		Listeners: []config.Listener{{Name: "h1", Transport: "h1", Address: addr}},
	})
	ctx := context.Background()
	c := client.H1(addr)
	defer c.Close()

	if _, err := c.Exec(ctx, "app", `CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := c.Exec(ctx, "app", `INSERT INTO t VALUES (1, 'seed')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := c.Batch(ctx, "app", []client.Statement{
		{SQL: `INSERT INTO t VALUES (2, 'ok')`},  // succeeds
		{SQL: `INSERT INTO t VALUES (1, 'dup')`}, // primary-key violation → error at index 1
		{SQL: `INSERT INTO t VALUES (3, 'c')`},
	})
	if err == nil {
		t.Fatal("batch with a duplicate key: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "statement 1") {
		t.Fatalf("error %q does not name the failing statement index", err.Error())
	}
	// Statement 0 ran before the failure and is not rolled back (non-atomic).
	q, err := c.Query(ctx, "app", `SELECT count(*) FROM t WHERE id = 2`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got := fmt.Sprint(q.Rows[0][0]); got != "1" {
		t.Fatalf("row from statement 0 count = %s, want 1 (batch is not atomic)", got)
	}
}

// TestKeyringChallengeCached proves the keyring method fetches a challenge at most
// once for a burst of requests within its reuse window, rather than once per
// request. It points the client at a fake server that only counts challenge
// fetches, so the assertion is independent of the real query path.
func TestKeyringChallengeCached(t *testing.T) {
	var chalHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/_auth/challenge", func(w http.ResponseWriter, _ *http.Request) {
		chalHits.Add(1)
		_, _ = w.Write([]byte(`{"challenge":"cached-challenge-value"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`)) // any query → 200; body is irrelevant to this test
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(ts.URL, "http://")
	c := client.H1(host, client.WithEd25519("ssh-ed25519 AAAAtest comment", priv))
	defer c.Close()

	ctx := context.Background()
	for range 5 {
		_, _ = c.Query(ctx, "app", "SELECT 1") // the query decode is immaterial; auth runs first
	}
	if got := chalHits.Load(); got != 1 {
		t.Fatalf("challenge fetched %d times for 5 requests, want 1 (cached and reused)", got)
	}
}
