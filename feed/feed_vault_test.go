package feed

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/secret"
)

// vaultResolver writes a 32-byte raw key file and returns a resolver that reads
// it via the "f:" source — mirroring the backend package's own vault tests.
func vaultResolver(t *testing.T, dir string) secret.Resolver {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vault.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	sec, err := secret.New([]config.SecretSource{{Name: "f", Type: "file", Dir: dir}})
	if err != nil {
		t.Fatal(err)
	}
	return sec
}

// Attribution for a VAULT backend goes through a custom VFS, so the path a
// connection reports (Conn.Filename) is not obviously the same string the
// backend advertises (Pather.Path). This is the case the unit test with a plain
// sqlite.Open can't cover — verify events actually fire end-to-end.
func TestVaultFeedAttribution(t *testing.T) {
	dir := t.TempDir()
	sec := vaultResolver(t, dir)
	dbcfg := config.Database{
		Name: "vaultdb", Backend: "vault", Path: "v.vault", Mode: "rwc",
		Vault: &config.VaultConfig{Cipher: "adiantum", Key: "f:vault.key"},
	}
	be, err := backend.For(dbcfg, sec, dir)
	if err != nil {
		t.Fatal(err)
	}
	pather, ok := be.(backend.Pather)
	if !ok {
		t.Fatal("vault backend should implement Pather")
	}

	b := New(64, 8, nil)
	b.Install()
	b.Register("vaultdb", pather.Path())

	db, err := be.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sub, _, _, ok, _, _ := b.Subscribe("vaultdb", 0)
	if !ok {
		t.Fatal("vault db should be observable")
	}
	defer sub.Close()

	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO t(v) VALUES ('x')`); err != nil {
		t.Fatal(err)
	}
	got := collect(t, sub, 1) // the whole point: a vault write is NOT silently unobserved
	if got[0].Op != "insert" || got[0].Table != "t" || got[0].Rowid != 1 {
		t.Fatalf("vault event = %+v", got[0])
	}
}

// A symlinked data_dir (macOS's /var → /private/var is the canonical trap) must
// still attribute writes: registration path and the connection's reported path
// have to canonicalize identically.
func TestSymlinkedPathAttribution(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	b := New(64, 8, nil)
	b.Install()
	// Register via the SYMLINK path; the connection will open the real path.
	b.Register("linked", filepath.Join(link, "s.db"))

	db, err := sqliteOpen(filepath.Join(real, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sub, _, _, ok, _, _ := b.Subscribe("linked", 0)
	if !ok {
		t.Fatal("linked db should be observable")
	}
	defer sub.Close()

	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO t DEFAULT VALUES`); err != nil {
		t.Fatal(err)
	}
	got := collect(t, sub, 1)
	if got[0].Op != "insert" {
		t.Fatalf("symlink event = %+v", got[0])
	}
}
