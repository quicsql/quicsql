package client_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"quicsql.net/client"
	"quicsql.net/config"
)

// startAttachServer stands up a server whose data DB has MaxOpen=1 (so a pinned
// session and a later autocommit request share the SAME pooled connection — the
// case the ATTACH cleanup must handle). "root" is a server-admin, "app" is a plain
// read-write user. allowAttach toggles auth.sql_policy.allow_attach.
func startAttachServer(t *testing.T, allowAttach bool) string {
	t.Helper()
	addr := freeTCP(t)
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	cfg := &config.Config{
		Server: config.Server{DataDir: t.TempDir(), MetaStore: config.MetaStore{Backend: "file", Path: "meta.db"}},
		Databases: []config.Database{{
			Name: "data", Backend: "file", Path: filepath.Join(t.TempDir(), "data.db"),
			Pool: config.Pool{MaxOpen: 1}, // force conn reuse so the no-leak check is deterministic
			Grants: []config.Grant{
				{Principal: "root", Level: "admin"},
				{Principal: "app", Level: "read-write"},
			},
		}},
		Listeners: []config.Listener{{Name: "h1", Transport: "h1", Address: addr, Auth: []string{"bearer"}}},
		Auth: config.Auth{
			Principals: []config.Principal{
				{Name: "root", Methods: []map[string]any{{"bearer": map[string]any{"token_hash": sum("root-token")}}}},
				{Name: "app", Methods: []map[string]any{{"bearer": map[string]any{"token_hash": sum("app-token")}}}},
			},
			SQLPolicy: config.SQLPolicy{AllowAttach: allowAttach},
		},
		ControlPlane: config.ControlPlane{Enabled: true, Admins: []string{"root"}},
	}
	runServer(t, cfg)
	return addr
}

// TestAttachDevOnly covers the whole gate: a server-admin session may ATTACH (and
// the attachment does NOT leak to the pool afterward), while the autocommit path and
// a non-server-admin session are denied even with the switch on.
func TestAttachDevOnly(t *testing.T) {
	skipUnderRace(t)
	addr := startAttachServer(t, true)
	ctx := context.Background()
	root := client.H1(addr, client.WithBearer("root-token"))
	defer root.Close()
	app := client.H1(addr, client.WithBearer("app-token"))
	defer app.Close()

	// (d) server-admin session: ATTACH works and the attached DB is usable.
	st := root.OpenStream("data")
	if _, err := st.Exec(ctx, "ATTACH ':memory:' AS aux", nil); err != nil {
		t.Fatalf("server-admin ATTACH should succeed: %v", err)
	}
	if _, err := st.Exec(ctx, "CREATE TABLE aux.t(x)", nil); err != nil {
		t.Fatalf("create in attached db: %v", err)
	}
	if _, err := st.Exec(ctx, "INSERT INTO aux.t VALUES(1)", nil); err != nil {
		t.Fatalf("insert into attached db: %v", err)
	}
	if err := st.Close(ctx); err != nil {
		t.Fatalf("close session: %v", err)
	}

	// (no leak) the single pooled connection is reused here; the ATTACH must have
	// been cleaned up on session close, so aux is gone.
	if _, err := root.Query(ctx, "data", "SELECT * FROM aux.t"); err == nil {
		t.Fatal("attached db leaked onto the pooled connection after the session closed")
	}

	// (c) a non-server-admin (read-write) session is denied even with the switch on.
	st2 := app.OpenStream("data")
	if _, err := st2.Exec(ctx, "ATTACH ':memory:' AS aux", nil); err == nil {
		t.Fatal("non-server-admin ATTACH should be denied")
	}
	_ = st2.Close(ctx)

	// (b) the autocommit/native path is denied even for the server-admin.
	if _, err := root.Query(ctx, "data", "ATTACH ':memory:' AS aux"); err == nil {
		t.Fatal("ATTACH on the autocommit path should be denied")
	}
}

// TestAttachDeniedByDefault: with the switch off, even a server-admin session is denied.
func TestAttachDeniedByDefault(t *testing.T) {
	skipUnderRace(t)
	addr := startAttachServer(t, false)
	ctx := context.Background()
	root := client.H1(addr, client.WithBearer("root-token"))
	defer root.Close()

	st := root.OpenStream("data")
	if _, err := st.Exec(ctx, "ATTACH ':memory:' AS aux", nil); err == nil {
		t.Fatal("ATTACH should be denied when allow_attach is off")
	}
	_ = st.Close(ctx)
}
