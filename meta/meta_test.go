package meta_test

import (
	"path/filepath"
	"testing"

	"gosqlite.org/server/config"
	"gosqlite.org/server/meta"
	"gosqlite.org/server/secret"
)

func openStore(t *testing.T) *meta.Store {
	t.Helper()
	sec, _ := secret.New(nil)
	st, err := meta.Open(config.MetaStore{Backend: "file", Path: "meta.db"}, sec, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestDatabasesRoundTrip(t *testing.T) {
	st := openStore(t)
	want := config.Database{
		Name: "sales", Backend: "vault", Path: "sales.vault", Mode: "rwc",
		Grants: []config.Grant{{Principal: "app", Level: "read-write"}},
		Vault:  &config.VaultConfig{Key: "f:sales", Compression: "best"},
	}
	if err := st.Put(want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Idempotent replace.
	if err := st.Put(want); err != nil {
		t.Fatalf("Put replace: %v", err)
	}
	got, err := st.Databases()
	if err != nil {
		t.Fatalf("Databases: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 database, got %d", len(got))
	}
	g := got[0]
	if g.Name != want.Name || g.Backend != want.Backend || g.Vault == nil || g.Vault.Key != "f:sales" {
		t.Fatalf("round-trip mismatch: %+v", g)
	}
	if len(g.Grants) != 1 || g.Grants[0].Principal != "app" {
		t.Fatalf("grants not preserved: %+v", g.Grants)
	}

	if err := st.Delete("sales"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, _ = st.Databases()
	if len(got) != 0 {
		t.Fatalf("Delete left %d databases", len(got))
	}
	// Deleting an absent name is a no-op.
	if err := st.Delete("nope"); err != nil {
		t.Fatalf("Delete absent: %v", err)
	}
}

func TestAuditIsBestEffort(t *testing.T) {
	st := openStore(t)
	// Should not panic or error out the caller.
	st.Audit("root", "create", "sales", "vault")
	st.Audit("root", "detach", "sales", "")
}

func TestPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	sec, _ := secret.New(nil)
	cfg := config.MetaStore{Backend: "file", Path: filepath.Join(dir, "m.db")}
	st, err := meta.Open(cfg, sec, "", nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Put(config.Database{Name: "x", Backend: "memory-shared"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = st.Close()

	st2, err := meta.Open(cfg, sec, "", nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	got, _ := st2.Databases()
	if len(got) != 1 || got[0].Name != "x" {
		t.Fatalf("not persisted across reopen: %+v", got)
	}
}
