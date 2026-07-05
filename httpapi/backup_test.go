package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	sqlite "gosqlite.org"
	"quicsql.net/authz"
	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/engine"
	"quicsql.net/httpapi"
	"quicsql.net/registry"
	"quicsql.net/secret"
)

func TestBackupStreamsValidSQLite(t *testing.T) {
	sec, _ := secret.New(nil)
	be, err := backend.For(config.Database{
		Name: "app", Backend: "file", Path: filepath.Join(t.TempDir(), "app.db"),
		Pragmas: map[string]any{"journal_mode": "WAL"},
	}, sec, "")
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{"app": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	h := httpapi.New(reg, engine.New(0, 0), config.Routing{ByPath: true}) // open mode

	if rec := postAs(t, h, "", "/app/query", `{"sql":"CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)"}`); rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := postAs(t, h, "", "/app/query", `{"sql":"INSERT INTO t(v) VALUES ('alpha'),('beta'),('gamma')"}`); rec.Code != http.StatusOK {
		t.Fatalf("insert: %d %s", rec.Code, rec.Body)
	}

	req := httptest.NewRequest(http.MethodGet, "/app/backup", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("backup: %d %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}

	body := rec.Body.Bytes()
	// Every SQLite database file begins with this 16-byte magic header.
	if len(body) < 512 || string(body[:16]) != "SQLite format 3\x00" {
		t.Fatalf("response is not a SQLite image (%d bytes)", len(body))
	}

	// Open the downloaded image and confirm the data round-tripped.
	out := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(out, body, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(sqlite.Config{Path: out, Mode: sqlite.ModeReadOnly})
	if err != nil {
		t.Fatalf("open backup image: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil || n != 3 {
		t.Fatalf("backup row count = %d err=%v (want 3)", n, err)
	}
	var v string
	if err := db.QueryRow("SELECT v FROM t WHERE id = 2").Scan(&v); err != nil || v != "beta" {
		t.Fatalf("backup data: v=%q err=%v (want beta)", v, err)
	}
}

func TestBackupRequiresRead(t *testing.T) {
	h := newAuthHandler(t) // writer=read-write, reader=read-only, others=none
	if rec := postAs(t, h, "writer", "/app/query", `{"sql":"CREATE TABLE t(x)"}`); rec.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", rec.Code, rec.Body)
	}
	get := func(name string) int {
		req := httptest.NewRequest(http.MethodGet, "/app/backup", nil)
		if name != "" {
			req = req.WithContext(authz.NewContext(req.Context(), &authz.Principal{Name: name, Method: "test"}))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := get("reader"); code != http.StatusOK {
		t.Fatalf("read-only principal backup: %d, want 200", code)
	}
	if code := get("stranger"); code != http.StatusForbidden {
		t.Fatalf("no-grant principal backup: %d, want 403", code)
	}
}
