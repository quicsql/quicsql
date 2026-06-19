package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quicsql.net/authz"
	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/engine"
	"quicsql.net/httpapi"
	"quicsql.net/registry"
	"quicsql.net/secret"
	"quicsql.net/session"
)

// newAuthHandler builds a handler over db "app" with an enforcing policy:
// writer=read-write, reader=read-only, and no grant for anyone else.
func newAuthHandler(t *testing.T) *httpapi.Handler {
	t.Helper()
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

	pol := authz.NewPolicy(false)
	pol.Grant("app", "writer", authz.ReadWrite)
	pol.Grant("app", "reader", authz.ReadOnly)

	store, err := session.NewStore(time.Minute, time.Minute, 16)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	eng := engine.New(0, 0)
	return httpapi.New(reg, eng, config.Routing{ByPath: true},
		httpapi.WithPolicy(pol), httpapi.WithSessions(store))
}

func postAs(t *testing.T, h http.Handler, name, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if name != "" {
		req = req.WithContext(authz.NewContext(req.Context(), &authz.Principal{Name: name, Method: "test"}))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestReadOnlyPrincipalCannotWriteNative(t *testing.T) {
	h := newAuthHandler(t)
	// Writer seeds the schema + a row.
	if rec := postAs(t, h, "writer", "/app/query", `{"sql":"CREATE TABLE t(x INTEGER)"}`); rec.Code != http.StatusOK {
		t.Fatalf("writer create: %d %s", rec.Code, rec.Body)
	}
	if rec := postAs(t, h, "writer", "/app/query", `{"sql":"INSERT INTO t VALUES(1)"}`); rec.Code != http.StatusOK {
		t.Fatalf("writer insert: %d %s", rec.Code, rec.Body)
	}

	// Reader can read.
	if rec := postAs(t, h, "reader", "/app/query", `{"sql":"SELECT count(*) FROM t"}`); rec.Code != http.StatusOK {
		t.Fatalf("reader select: %d %s", rec.Code, rec.Body)
	}
	// Reader cannot write — a single write statement is forbidden.
	if rec := postAs(t, h, "reader", "/app/query", `{"sql":"INSERT INTO t VALUES(2)"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("reader insert: got %d, want 403 (%s)", rec.Code, rec.Body)
	}
	// Reader cannot write via a batch that hides the write behind a read, either
	// (the connection authorizer denies it at compile time).
	if rec := postAs(t, h, "reader", "/app/query",
		`{"statements":[{"sql":"SELECT 1"},{"sql":"INSERT INTO t VALUES(3)"}]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("reader batch write: got %d, want 403 (%s)", rec.Code, rec.Body)
	}
	// The row count is unchanged — no write slipped through.
	rec := postAs(t, h, "reader", "/app/query", `{"sql":"SELECT count(*) FROM t"}`)
	if !strings.Contains(rec.Body.String(), "[[1]]") {
		t.Fatalf("read-only writes leaked: %s", rec.Body)
	}
}

func TestNoGrantPrincipalDenied(t *testing.T) {
	h := newAuthHandler(t)
	if rec := postAs(t, h, "stranger", "/app/query", `{"sql":"SELECT 1"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("stranger read: got %d, want 403 (%s)", rec.Code, rec.Body)
	}
	// Anonymous (no principal) also has no grant → forbidden.
	if rec := postAs(t, h, "", "/app/query", `{"sql":"SELECT 1"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous read: got %d, want 403 (%s)", rec.Code, rec.Body)
	}
}

func TestReadOnlyPrincipalCannotWriteHrana(t *testing.T) {
	h := newAuthHandler(t)
	if rec := postAs(t, h, "writer", "/app/query", `{"sql":"CREATE TABLE h(x)"}`); rec.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", rec.Code, rec.Body)
	}
	// Reader opens a Hrana stream and attempts a write via execute.
	body := `{"requests":[{"type":"execute","stmt":{"sql":"INSERT INTO h VALUES(1)"}}]}`
	rec := postAs(t, h, "reader", "/app/v3/pipeline", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("pipeline status %d: %s", rec.Code, rec.Body)
	}
	// The execute must be an error result (write denied on the read-only conn).
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("read-only Hrana write should error: %s", rec.Body)
	}
	// And the row must not exist.
	check := postAs(t, h, "writer", "/app/query", `{"sql":"SELECT count(*) FROM h"}`)
	if !strings.Contains(check.Body.String(), "[[0]]") {
		t.Fatalf("read-only Hrana write leaked: %s", check.Body)
	}
}

func TestBatonBoundToPrincipal(t *testing.T) {
	h := newAuthHandler(t)
	// Writer opens a stream (no close) and gets a baton.
	rec := postAs(t, h, "writer", "/app/v3/pipeline",
		`{"requests":[{"type":"execute","stmt":{"sql":"SELECT 1"}}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("open: %d %s", rec.Code, rec.Body)
	}
	var resp struct {
		Baton *string `json:"baton"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Baton == nil {
		t.Fatalf("no baton: %v (%s)", err, rec.Body)
	}

	// A different principal presenting the same baton is rejected (403).
	steal := postAs(t, h, "reader", "/app/v3/pipeline",
		`{"baton":"`+*resp.Baton+`","requests":[{"type":"execute","stmt":{"sql":"SELECT 1"}}]}`)
	if steal.Code != http.StatusForbidden {
		t.Fatalf("baton reuse by another principal: got %d, want 403 (%s)", steal.Code, steal.Body)
	}

	// The owner can still resume it.
	ok := postAs(t, h, "writer", "/app/v3/pipeline",
		`{"baton":"`+*resp.Baton+`","requests":[{"type":"execute","stmt":{"sql":"SELECT 1"}},{"type":"close"}]}`)
	if ok.Code != http.StatusOK {
		t.Fatalf("owner resume: got %d (%s)", ok.Code, ok.Body)
	}
}

// TestSharedMemoryAcrossSessions exercises the plan's exit criterion: rows written
// by one client session are visible to another, over a shared in-memory backend.
func TestSharedMemoryAcrossSessions(t *testing.T) {
	sec, _ := secret.New(nil)
	be, err := backend.For(config.Database{Name: "cache", Backend: "memory-shared", Pool: config.Pool{MaxOpen: 4}}, sec, "")
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{"cache": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	h := httpapi.New(reg, engine.New(0, 0), config.Routing{ByPath: true})

	// Session 1 writes.
	if rec := postAs(t, h, "", "/cache/query", `{"sql":"CREATE TABLE t(x)"}`); rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := postAs(t, h, "", "/cache/query", `{"sql":"INSERT INTO t VALUES(1)"}`); rec.Code != http.StatusOK {
		t.Fatalf("insert: %d %s", rec.Code, rec.Body)
	}
	// Session 2 reads — sees the row.
	rec := postAs(t, h, "", "/cache/query", `{"sql":"SELECT count(*) FROM t"}`)
	if !strings.Contains(rec.Body.String(), "[[1]]") {
		t.Fatalf("shared memory not visible across sessions: %s", rec.Body)
	}
}

func TestAdminMountAndGating(t *testing.T) {
	sec, _ := secret.New(nil)
	be, _ := backend.For(config.Database{Name: "app", Backend: "memory-shared"}, sec, "")
	reg := registry.New(map[string]backend.Backend{"app": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })

	// Without WithAdmin, /_admin is not available.
	off := httpapi.New(reg, engine.New(0, 0), config.Routing{ByPath: true})
	if rec := do(t, off, http.MethodGet, "/_admin/databases", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled control plane: got %d, want 404", rec.Code)
	}

	// With WithAdmin, /_admin routes to the mounted handler.
	sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admin:" + r.URL.Path))
	})
	on := httpapi.New(reg, engine.New(0, 0), config.Routing{ByPath: true}, httpapi.WithAdmin(sentinel))
	rec := do(t, on, http.MethodGet, "/_admin/databases", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "admin:/_admin/databases") {
		t.Fatalf("admin mount: %d %s", rec.Code, rec.Body)
	}
}

func TestOpenModeStillServes(t *testing.T) {
	// A handler with no explicit policy defaults to open mode: an anonymous
	// request is read-write, preserving the pre-auth behavior.
	sec, _ := secret.New(nil)
	be, _ := backend.For(config.Database{Name: "app", Backend: "file", Path: filepath.Join(t.TempDir(), "o.db")}, sec, "")
	reg := registry.New(map[string]backend.Backend{"app": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	h := httpapi.New(reg, engine.New(0, 0), config.Routing{ByPath: true})
	if rec := postAs(t, h, "", "/app/query", `{"sql":"CREATE TABLE t(x)"}`); rec.Code != http.StatusOK {
		t.Fatalf("open-mode write: %d %s", rec.Code, rec.Body)
	}
}
