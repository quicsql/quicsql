package admin_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlite "gosqlite.org"
	"quicsql.net/admin"
	"quicsql.net/authz"
	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/registry"
	"quicsql.net/secret"
	"quicsql.net/session"
)

func newAdmin(t *testing.T, admins []string, open bool, seed map[string]backend.Backend, sec secret.Resolver, dataDir string) (*admin.Handler, *registry.Registry, *authz.Policy) {
	t.Helper()
	if seed == nil {
		seed = map[string]backend.Backend{}
	}
	reg := registry.New(seed, nil)
	t.Cleanup(func() { _ = reg.Close() })
	pol := authz.NewPolicy(open)
	if sec == nil {
		sec, _ = secret.New(nil)
	}
	return admin.New(reg, pol, nil, nil, sec, nil, dataDir, admins, time.Now(), nil), reg, pol
}

func as(t *testing.T, h http.Handler, name, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if name != "" {
		req = req.WithContext(authz.NewContext(req.Context(), &authz.Principal{Name: name, Method: "test"}))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCreateRequiresServerAdmin(t *testing.T) {
	h, reg, _ := newAdmin(t, []string{"root"}, false, nil, nil, "")

	// A non-admin cannot create.
	if rec := as(t, h, "nobody", http.MethodPost, "/_admin/create", `{"database":{"name":"x","backend":"memory-shared"}}`); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin create: got %d, want 403 (%s)", rec.Code, rec.Body)
	}
	// The server-admin can.
	rec := as(t, h, "root", http.MethodPost, "/_admin/create", `{"database":{"name":"sales","backend":"memory-shared"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin create: got %d (%s)", rec.Code, rec.Body)
	}
	if reg.Backend("sales") == nil {
		t.Fatal("created database not registered")
	}
	// It actually opens and serves.
	if _, release, err := reg.Get(context.Background(), "sales"); err != nil {
		t.Fatalf("created database does not open: %v", err)
	} else {
		release()
	}
	// Re-creating the same name conflicts.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/create", `{"database":{"name":"sales","backend":"memory-shared"}}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create: got %d, want 409 (%s)", rec.Code, rec.Body)
	}
	// A reserved name is rejected.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/create", `{"database":{"name":"_meta","backend":"memory-shared"}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("reserved name: got %d, want 400 (%s)", rec.Code, rec.Body)
	}
}

func TestCreateAppliesGrants(t *testing.T) {
	h, _, pol := newAdmin(t, []string{"root"}, false, nil, nil, "")
	body := `{"database":{"name":"g","backend":"memory-shared"},"grants":[{"principal":"reader","level":"read-only"}]}`
	if rec := as(t, h, "root", http.MethodPost, "/_admin/create", body); rec.Code != http.StatusOK {
		t.Fatalf("create with grants: %d (%s)", rec.Code, rec.Body)
	}
	if got := pol.Level(&authz.Principal{Name: "reader"}, "g"); got != authz.ReadOnly {
		t.Fatalf("grant not applied: got %v", got)
	}
}

func TestDetach(t *testing.T) {
	h, reg, _ := newAdmin(t, []string{"root"}, false, nil, nil, "")
	as(t, h, "root", http.MethodPost, "/_admin/create", `{"database":{"name":"tmp","backend":"memory-shared"}}`)

	// Busy detach is refused.
	_, release, err := reg.Get(context.Background(), "tmp")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec := as(t, h, "root", http.MethodPost, "/_admin/detach", `{"database":"tmp"}`); rec.Code != http.StatusConflict {
		t.Fatalf("busy detach: got %d, want 409 (%s)", rec.Code, rec.Body)
	}
	release()

	// Idle detach succeeds and forgets the backend.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/detach", `{"database":"tmp"}`); rec.Code != http.StatusOK {
		t.Fatalf("idle detach: got %d (%s)", rec.Code, rec.Body)
	}
	if reg.Backend("tmp") != nil {
		t.Fatal("detached database still registered")
	}
	// Detaching an unknown database is 404.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/detach", `{"database":"ghost"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("detach unknown: got %d, want 404", rec.Code)
	}
}

func TestListFiltersByAdmin(t *testing.T) {
	sec, _ := secret.New(nil)
	be, _ := backend.For(config.Database{Name: "public", Backend: "memory-shared"}, sec, "")
	be2, _ := backend.For(config.Database{Name: "secret", Backend: "memory-shared"}, sec, "")
	h, _, pol := newAdmin(t, nil, false, map[string]backend.Backend{"public": be, "secret": be2}, sec, "")
	pol.Grant("public", "alice", authz.Admin)
	pol.Grant("secret", "bob", authz.Admin)

	rec := as(t, h, "alice", http.MethodGet, "/_admin/databases", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var resp struct {
		Databases []struct {
			Name string `json:"name"`
		} `json:"databases"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Databases) != 1 || resp.Databases[0].Name != "public" {
		t.Fatalf("alice should see only 'public': %s", rec.Body)
	}
}

func TestMaintenanceAuthz(t *testing.T) {
	sec, _ := secret.New(nil)
	be, _ := backend.For(config.Database{Name: "d", Backend: "memory-shared"}, sec, "")
	h, _, pol := newAdmin(t, []string{"root"}, false, map[string]backend.Backend{"d": be}, sec, "")
	pol.Grant("d", "dba", authz.Admin)

	// A stranger with no admin grant is refused.
	if rec := as(t, h, "stranger", http.MethodPost, "/_admin/maintenance", `{"database":"d","op":"snapshot","dest":"/tmp/x"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("stranger maintenance: got %d, want 403", rec.Code)
	}
	// A db-admin is allowed (op fails later for a non-abs dest, but past the authz gate → not 403).
	if rec := as(t, h, "dba", http.MethodPost, "/_admin/maintenance", `{"database":"d","op":"compact"}`); rec.Code == http.StatusForbidden {
		t.Fatalf("db-admin should pass the authz gate, got 403 (%s)", rec.Body)
	}
}

func TestVaultOfflineCompact(t *testing.T) {
	dir := t.TempDir()
	sdir := t.TempDir()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	_ = os.WriteFile(filepath.Join(sdir, "k"), key, 0o600)
	sec, _ := secret.New([]config.SecretSource{{Name: "f", Type: "file", Dir: sdir}})

	dbcfg := config.Database{Name: "v", Backend: "vault", Path: "v.vault", Mode: "rwc",
		Vault: &config.VaultConfig{Key: "f:k", Compression: "best"}}
	be, err := backend.For(dbcfg, sec, dir)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	h, reg, _ := newAdmin(t, []string{"root"}, false, map[string]backend.Backend{"v": be}, sec, dir)

	// Materialize the container + a row, then release so it is idle (compact reserves).
	dbh, release, err := reg.Get(context.Background(), "v")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := dbh.Handle.Exec("CREATE TABLE t(x); INSERT INTO t VALUES(1);"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	release()

	rec := as(t, h, "root", http.MethodPost, "/_admin/maintenance", `{"database":"v","op":"compact"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("offline compact: got %d (%s)", rec.Code, rec.Body)
	}
	// The container reopens cleanly and the row survived.
	dbh2, release2, err := reg.Get(context.Background(), "v")
	if err != nil {
		t.Fatalf("reopen after compact: %v", err)
	}
	defer release2()
	var n int
	if err := dbh2.Handle.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil || n != 1 {
		t.Fatalf("row lost across compact: n=%d err=%v", n, err)
	}
}

func TestCheckpoint(t *testing.T) {
	dir := t.TempDir()
	sec, _ := secret.New(nil)
	be, _ := backend.For(config.Database{Name: "c", Backend: "file", Path: "c.db", Mode: "rwc", PragmasPreset: "recommended"}, sec, dir)
	h, reg, _ := newAdmin(t, []string{"root"}, false, map[string]backend.Backend{"c": be}, sec, dir)

	dbh, release, _ := reg.Get(context.Background(), "c")
	if _, err := dbh.Handle.Exec("CREATE TABLE t(x); INSERT INTO t VALUES(1),(2),(3);"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	release()

	rec := as(t, h, "root", http.MethodPost, "/_admin/maintenance", `{"database":"c","op":"checkpoint","mode":"truncate"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("checkpoint: got %d (%s)", rec.Code, rec.Body)
	}
	var out struct {
		Status, Mode       string
		WALFrames          int `json:"wal_frames"`
		CheckpointedFrames int `json:"checkpointed_frames"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body)
	}
	if out.Status != "checkpointed" || out.Mode != "truncate" {
		t.Fatalf("checkpoint response = %+v", out)
	}
	// An unknown mode is a 400.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/maintenance", `{"database":"c","op":"checkpoint","mode":"bogus"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad checkpoint mode: got %d, want 400", rec.Code)
	}
	// Default (empty) mode is passive and succeeds.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/maintenance", `{"database":"c","op":"checkpoint"}`); rec.Code != http.StatusOK {
		t.Fatalf("default-mode checkpoint: got %d (%s)", rec.Code, rec.Body)
	}
}

func TestLogicalReclaim(t *testing.T) {
	dir := t.TempDir()
	sdir := t.TempDir()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	_ = os.WriteFile(filepath.Join(sdir, "k"), key, 0o600)
	sec, _ := secret.New([]config.SecretSource{{Name: "f", Type: "file", Dir: sdir}})
	dbcfg := config.Database{Name: "v", Backend: "vault", Path: "v.vault", Mode: "rwc", Vault: &config.VaultConfig{Key: "f:k"}}
	be, err := backend.For(dbcfg, sec, dir)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	// A file backend for the negative case (logical reclaim is vault-only).
	fbe, _ := backend.For(config.Database{Name: "f", Backend: "file", Path: "f.db", Mode: "rwc"}, sec, dir)
	h, reg, _ := newAdmin(t, []string{"root"}, false, map[string]backend.Backend{"v": be, "f": fbe}, sec, dir)

	dbh, release, err := reg.Get(context.Background(), "v")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := dbh.Handle.Exec("CREATE TABLE t(x)"); err != nil {
		t.Fatalf("seed schema: %v", err)
	}
	for range 500 {
		if _, err := dbh.Handle.Exec("INSERT INTO t VALUES(zeroblob(1024))"); err != nil {
			t.Fatalf("seed rows: %v", err)
		}
	}
	if _, err := dbh.Handle.Exec("DELETE FROM t"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	release()

	// The read-only probe reports a (non-negative) reclaimable figure.
	rec := as(t, h, "root", http.MethodPost, "/_admin/maintenance", `{"database":"v","op":"reclaimable"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reclaimable: got %d (%s)", rec.Code, rec.Body)
	}
	var probe struct {
		ReclaimableBytes int64 `json:"reclaimable_bytes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &probe); err != nil {
		t.Fatalf("decode probe: %v (%s)", err, rec.Body)
	}
	if probe.ReclaimableBytes < 0 {
		t.Fatalf("reclaimable_bytes = %d, want ≥ 0", probe.ReclaimableBytes)
	}

	// The online logical compaction runs and reports bytes freed.
	rec = as(t, h, "root", http.MethodPost, "/_admin/maintenance", `{"database":"v","op":"compact_logical"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("compact_logical: got %d (%s)", rec.Code, rec.Body)
	}

	// The row count survives the compaction (data integrity).
	dbh2, release2, _ := reg.Get(context.Background(), "v")
	defer release2()
	var n int
	if err := dbh2.Handle.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil || n != 0 {
		t.Fatalf("after logical compact: n=%d err=%v (want 0)", n, err)
	}

	// A non-vault backend rejects logical reclaim.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/maintenance", `{"database":"f","op":"reclaimable"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("logical reclaim on file backend: got %d, want 400", rec.Code)
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sec, _ := secret.New(nil)
	be, err := backend.For(config.Database{Name: "app", Backend: "file", Path: "app.db", Mode: "rwc"}, sec, dir)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	h, reg, _ := newAdmin(t, []string{"root"}, false, map[string]backend.Backend{"app": be}, sec, dir)

	// Seed a known state and capture its image with a straight SQLite serialize
	// (what /export or /backup would hand a client).
	dbh, release, _ := reg.Get(context.Background(), "app")
	if _, err := dbh.Handle.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t(v) VALUES('one'),('two');"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	image, err := sqlite.Serialize(context.Background(), dbh.Handle.DB)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// Diverge from the captured state.
	if _, err := dbh.Handle.Exec("INSERT INTO t(v) VALUES('three'); DELETE FROM t WHERE v='one';"); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	release() // idle, so restore can reserve

	// Restore the captured image.
	req := httptest.NewRequest(http.MethodPost, "/_admin/restore?database=app", bytes.NewReader(image))
	req = req.WithContext(authz.NewContext(req.Context(), &authz.Principal{Name: "root", Method: "test"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body)
	}

	// The database now reflects the restored (pre-divergence) state exactly.
	dbh2, release2, err := reg.Get(context.Background(), "app")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer release2()
	rows, err := dbh2.Handle.Query("SELECT v FROM t ORDER BY id")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		got = append(got, v)
	}
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("restored state = %v, want [one two]", got)
	}
}

func TestRestoreGuards(t *testing.T) {
	dir := t.TempDir()
	sec, _ := secret.New(nil)
	fbe, _ := backend.For(config.Database{Name: "app", Backend: "file", Path: "app.db", Mode: "rwc"}, sec, dir)
	mbe, _ := backend.For(config.Database{Name: "mem", Backend: "memory", Mode: "rwc"}, sec, dir)
	h, _, _ := newAdmin(t, []string{"root"}, false, map[string]backend.Backend{"app": fbe, "mem": mbe}, sec, dir)

	post := func(name, target string, body []byte) int {
		req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		if name != "" {
			req = req.WithContext(authz.NewContext(req.Context(), &authz.Principal{Name: name, Method: "test"}))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	valid := []byte(sqliteMagicTest())

	// Non-admin is refused.
	if code := post("stranger", "/_admin/restore?database=app", valid); code != http.StatusForbidden {
		t.Fatalf("non-admin restore: %d, want 403", code)
	}
	// A garbage (non-SQLite) image is rejected before any swap.
	if code := post("root", "/_admin/restore?database=app", []byte("not a database")); code != http.StatusBadRequest {
		t.Fatalf("garbage image: %d, want 400", code)
	}
	// A memory backend is not restorable.
	if code := post("root", "/_admin/restore?database=mem", valid); code != http.StatusBadRequest {
		t.Fatalf("memory restore: %d, want 400", code)
	}
	// A missing ?database= is a 400.
	if code := post("root", "/_admin/restore", valid); code != http.StatusBadRequest {
		t.Fatalf("no database param: %d, want 400", code)
	}
}

// sqliteMagicTest builds a minimal valid SQLite image for the guard tests.
func sqliteMagicTest() string {
	db, _ := sqlite.Open(sqlite.Config{Path: ":memory:"})
	_, _ = db.Exec("CREATE TABLE x(a)")
	img, _ := sqlite.Serialize(context.Background(), db.DB)
	_ = db.Close()
	return string(img)
}

func TestSnapshot(t *testing.T) {
	dir := t.TempDir()
	sec, _ := secret.New(nil)
	be, _ := backend.For(config.Database{Name: "s", Backend: "file", Path: "s.db", Mode: "rwc"}, sec, dir)
	h, reg, _ := newAdmin(t, []string{"root"}, false, map[string]backend.Backend{"s": be}, sec, dir)

	dbh, release, _ := reg.Get(context.Background(), "s")
	_, _ = dbh.Handle.Exec("CREATE TABLE t(x); INSERT INTO t VALUES(42);")
	release()

	dest := filepath.Join(dir, "snap.db")
	rec := as(t, h, "root", http.MethodPost, "/_admin/maintenance", `{"database":"s","op":"snapshot","dest":"`+dest+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("snapshot: got %d (%s)", rec.Code, rec.Body)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("snapshot file missing: %v", err)
	}
	// A dest escaping data_dir is rejected.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/maintenance", `{"database":"s","op":"snapshot","dest":"/etc/quicsql_pwn.db"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("escaping dest: got %d, want 400", rec.Code)
	}
	// Re-snapshotting onto the existing dest is refused (O_EXCL, no clobber).
	if rec := as(t, h, "root", http.MethodPost, "/_admin/maintenance", `{"database":"s","op":"snapshot","dest":"`+dest+`"}`); rec.Code != http.StatusConflict {
		t.Fatalf("clobber dest: got %d, want 409", rec.Code)
	}
}

func TestIntrospectionSessionsAndKill(t *testing.T) {
	sec, _ := secret.New(nil)
	be, _ := backend.For(config.Database{Name: "app", Backend: "memory-shared"}, sec, "")
	reg := registry.New(map[string]backend.Backend{"app": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	store, err := session.NewStore(time.Minute, time.Minute, 16)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	pol := authz.NewPolicy(false)
	h := admin.New(reg, pol, nil, store, sec, nil, "", []string{"root"}, time.Now(), nil)

	// Open a live session on "app" and clear its in-flight flag so it is killable.
	dbh, release, err := reg.Get(context.Background(), "app")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	s, err := store.Open(context.Background(), dbh, release, "user", false, false)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	store.Baton(s) // clears busy

	// /info requires server-admin.
	if rec := as(t, h, "nobody", http.MethodGet, "/_admin/info", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("info non-admin: got %d, want 403", rec.Code)
	}
	info := as(t, h, "root", http.MethodGet, "/_admin/info", "")
	if info.Code != http.StatusOK || !strings.Contains(info.Body.String(), `"active_sessions":1`) {
		t.Fatalf("info: %d %s", info.Code, info.Body)
	}

	// /sessions lists the live session.
	rec := as(t, h, "root", http.MethodGet, "/_admin/sessions", "")
	var resp struct {
		Sessions []struct {
			ID       string `json:"id"`
			Database string `json:"database"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode sessions: %v (%s)", err, rec.Body)
	}
	if len(resp.Sessions) != 1 || resp.Sessions[0].Database != "app" {
		t.Fatalf("want 1 session on app, got %s", rec.Body)
	}
	id := resp.Sessions[0].ID

	// /kill closes it.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/kill", `{"session":"`+id+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("kill: got %d (%s)", rec.Code, rec.Body)
	}
	// It is gone.
	rec = as(t, h, "root", http.MethodGet, "/_admin/sessions", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Sessions) != 0 {
		t.Fatalf("session should be gone after kill: %s", rec.Body)
	}
	// Killing an unknown session is 404.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/kill", `{"session":"AAAAAAAAAAAAAAAAAAAAAA"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("kill unknown: got %d, want 404", rec.Code)
	}
}

func TestKillBusySessionRefused(t *testing.T) {
	sec, _ := secret.New(nil)
	be, _ := backend.For(config.Database{Name: "app", Backend: "memory-shared"}, sec, "")
	reg := registry.New(map[string]backend.Backend{"app": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	store, _ := session.NewStore(time.Minute, time.Minute, 16)
	h := admin.New(reg, authz.NewPolicy(false), nil, store, sec, nil, "", []string{"root"}, time.Now(), nil)

	dbh, release, _ := reg.Get(context.Background(), "app")
	s, _ := store.Open(context.Background(), dbh, release, "user", false, false) // busy=true (not cleared)
	list := store.List(nil)
	if len(list) != 1 {
		t.Fatalf("want 1 session, got %d", len(list))
	}
	// A busy session is refused (409) — bounded by the statement timeout instead.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/kill", `{"session":"`+list[0].ID+`"}`); rec.Code != http.StatusConflict {
		t.Fatalf("kill busy: got %d, want 409 (%s)", rec.Code, rec.Body)
	}
	store.Close(s) // cleanup
}

func TestControlPlaneRequiresNamedAdmin(t *testing.T) {
	// The control plane does NOT collapse to "everyone" in open mode (unlike the
	// data plane): /_admin always requires a configured, named server-admin, so an
	// unnamed caller is refused even with no admins configured.
	h, reg, _ := newAdmin(t, nil, true, nil, nil, "")
	if rec := as(t, h, "", http.MethodPost, "/_admin/create", `{"database":{"name":"o","backend":"memory-shared"}}`); rec.Code != http.StatusForbidden {
		t.Fatalf("open-mode create without a named admin: got %d, want 403 (%s)", rec.Code, rec.Body)
	}
	if reg.Backend("o") != nil {
		t.Fatal("create should not have registered anything")
	}
}

func TestCreateRejectsEscapingPath(t *testing.T) {
	h, _, _ := newAdmin(t, []string{"root"}, false, nil, nil, t.TempDir())
	// An absolute path outside data_dir is rejected.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/create", `{"database":{"name":"esc","backend":"file","path":"/etc/quicsql_pwn.db"}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("absolute path escape: got %d, want 400 (%s)", rec.Code, rec.Body)
	}
	// A `..` traversal is rejected.
	if rec := as(t, h, "root", http.MethodPost, "/_admin/create", `{"database":{"name":"esc","backend":"vault","path":"../../secrets.vault"}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("dotdot escape: got %d, want 400 (%s)", rec.Code, rec.Body)
	}
}
