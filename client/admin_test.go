package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"quicsql.net/client"
	"quicsql.net/config"
)

// TestBackupRestoreRoundTrip clones a database in two calls: BackupTo captures a
// streaming image, and AdminRestore swaps it back after the live data diverges.
func TestBackupRestoreRoundTrip(t *testing.T) {
	addr := startAdminServer(t)
	ctx := context.Background()
	root := client.H1(addr, client.WithBearer("root-token"))
	defer root.Close()
	app := client.H1(addr, client.WithBearer("app-token"))
	defer app.Close()

	if _, err := app.Exec(ctx, "data", "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := app.Exec(ctx, "data", "INSERT INTO t(v) VALUES('one'),('two')"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var buf bytes.Buffer
	n, err := root.BackupTo(ctx, "data", &buf)
	if err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	if n < 512 || string(buf.Bytes()[:16]) != "SQLite format 3\x00" {
		t.Fatalf("backup is not a SQLite image (%d bytes)", n)
	}
	image := append([]byte(nil), buf.Bytes()...)

	// Diverge from the captured state.
	if _, err := app.Exec(ctx, "data", "INSERT INTO t(v) VALUES('three')"); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	if _, err := app.Exec(ctx, "data", "DELETE FROM t WHERE v = 'one'"); err != nil {
		t.Fatalf("mutate: %v", err)
	}

	if err := root.AdminRestore(ctx, "data", bytes.NewReader(image)); err != nil {
		t.Fatalf("AdminRestore: %v", err)
	}

	res, err := app.Query(ctx, "data", "SELECT v FROM t ORDER BY id")
	if err != nil {
		t.Fatalf("verify query: %v", err)
	}
	var got []string
	for _, row := range res.Rows {
		got = append(got, row[0].(string))
	}
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("restored state = %v, want [one two]", got)
	}
}

// startAdminServer stands up a server with the control plane enabled: bearer
// principal "root" is a server-admin, "app" is a plain user with data-plane
// access only.
func startAdminServer(t *testing.T) (addr string) {
	t.Helper()
	addr = freeTCP(t)
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	cfg := &config.Config{
		Server: config.Server{
			DataDir:   t.TempDir(),
			MetaStore: config.MetaStore{Backend: "file", Path: "meta.db"},
		},
		Databases: []config.Database{{
			Name: "data", Backend: "file", Path: filepath.Join(t.TempDir(), "data.db"),
			Grants: []config.Grant{
				{Principal: "root", Level: "admin"},
				{Principal: "app", Level: "read-write"},
			},
		}},
		Listeners: []config.Listener{
			{Name: "h1", Transport: "h1", Address: addr, Auth: []string{"bearer"}},
		},
		Auth: config.Auth{Principals: []config.Principal{
			{Name: "root", Methods: []map[string]any{{"bearer": map[string]any{"token_hash": sum("root-token")}}}},
			{Name: "app", Methods: []map[string]any{{"bearer": map[string]any{"token_hash": sum("app-token")}}}},
		}},
		ControlPlane: config.ControlPlane{Enabled: true, Admins: []string{"root"}},
	}
	runServer(t, cfg)
	return addr
}

// TestAdminAPI drives the typed control-plane surface end to end: health,
// listing, info, create/detach, sessions, and the non-admin refusal.
func TestAdminAPI(t *testing.T) {
	addr := startAdminServer(t)
	ctx := context.Background()

	root := client.H1(addr, client.WithBearer("root-token"))
	defer root.Close()

	if err := root.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}

	dbs, err := root.AdminDatabases(ctx)
	if err != nil {
		t.Fatalf("AdminDatabases: %v", err)
	}
	if len(dbs) != 1 || dbs[0].Name != "data" {
		t.Fatalf("AdminDatabases = %+v, want [data]", dbs)
	}

	info, err := root.AdminInfo(ctx)
	if err != nil {
		t.Fatalf("AdminInfo: %v", err)
	}
	if info.Databases != 1 {
		t.Fatalf("AdminInfo.Databases = %d, want 1", info.Databases)
	}

	sessions, err := root.AdminSessions(ctx)
	if err != nil {
		t.Fatalf("AdminSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("AdminSessions = %+v, want none", sessions)
	}

	// create a database at runtime, see it listed, then detach it
	err = root.AdminCreate(ctx, map[string]any{
		"database": map[string]any{"name": "scratch", "backend": "memory-shared"},
		"grants":   []map[string]any{{"principal": "app", "level": "read-write"}},
	})
	if err != nil {
		t.Fatalf("AdminCreate: %v", err)
	}
	if dbs, err = root.AdminDatabases(ctx); err != nil || len(dbs) != 2 {
		t.Fatalf("after create: %+v, %v; want 2 databases", dbs, err)
	}
	if err := root.AdminDetach(ctx, "scratch"); err != nil {
		t.Fatalf("AdminDetach: %v", err)
	}
	if dbs, err = root.AdminDatabases(ctx); err != nil || len(dbs) != 1 {
		t.Fatalf("after detach: %+v, %v; want 1 database", dbs, err)
	}

	// a data-plane principal is not a server-admin: info must be refused,
	// and its database listing is empty (no admin grants)
	app := client.H1(addr, client.WithBearer("app-token"))
	defer app.Close()
	if _, err := app.AdminInfo(ctx); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("AdminInfo as app = %v, want 403", err)
	}
	if dbs, err := app.AdminDatabases(ctx); err != nil || len(dbs) != 0 {
		t.Fatalf("AdminDatabases as app = %+v, %v; want empty", dbs, err)
	}
}
