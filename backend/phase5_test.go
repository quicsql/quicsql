package backend_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"gosqlite.org"
	"gosqlite.org/server/backend"
	"gosqlite.org/server/config"
	"gosqlite.org/server/secret"
)

// --- helpers ---

// genSSHKey returns a fresh ed25519 keypair as an OpenSSH private-key PEM and its
// authorized_keys public line — the shapes the secret resolver infers.
func genSSHKey(t *testing.T) (priv, pub []byte) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(sk, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(blk), ssh.MarshalAuthorizedKey(sshPub)
}

// secretDir writes name→bytes files and returns a file-backed resolver over them.
func secretDir(t *testing.T, files map[string][]byte) secret.Resolver {
	t.Helper()
	dir := t.TempDir()
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sec, err := secret.New([]config.SecretSource{{Name: "f", Type: "file", Dir: dir}})
	if err != nil {
		t.Fatal(err)
	}
	return sec
}

func openBackend(t *testing.T, db config.Database, sec secret.Resolver, dataDir string) *sqlite.DB {
	t.Helper()
	be, err := backend.For(db, sec, dataDir)
	if err != nil {
		t.Fatalf("backend.For(%s): %v", db.Name, err)
	}
	h, err := be.Open(context.Background())
	if err != nil {
		t.Fatalf("Open(%s): %v", db.Name, err)
	}
	return h
}

// --- in-memory / registered-VFS backends ---

func TestSharedInMemoryVisibleAcrossConnections(t *testing.T) {
	sec, _ := secret.New(nil)
	for _, kind := range []string{"memory-shared", "mvcc", "memdb"} {
		t.Run(kind, func(t *testing.T) {
			db := openBackend(t, config.Database{Name: "cache", Backend: kind, Pool: config.Pool{MaxOpen: 4}}, sec, "")
			defer db.Close()
			ctx := context.Background()
			// Two connections held at once are distinct underlying conns; a write on
			// one must be visible on the other (the shared-in-memory guarantee).
			c1, err := db.Conn(ctx)
			if err != nil {
				t.Fatalf("conn1: %v", err)
			}
			defer c1.Close()
			c2, err := db.Conn(ctx)
			if err != nil {
				t.Fatalf("conn2: %v", err)
			}
			defer c2.Close()
			if _, err := c1.ExecContext(ctx, "CREATE TABLE t(x)"); err != nil {
				t.Fatalf("create: %v", err)
			}
			if _, err := c1.ExecContext(ctx, "INSERT INTO t VALUES(1)"); err != nil {
				t.Fatalf("insert: %v", err)
			}
			var n int
			if err := c2.QueryRowContext(ctx, "SELECT count(*) FROM t").Scan(&n); err != nil {
				t.Fatalf("read on second conn: %v", err)
			}
			if n != 1 {
				t.Fatalf("%s not shared across connections: count=%d", kind, n)
			}
		})
	}
}

// --- vault: raw key ---

func TestVaultRawKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sec := secretDir(t, map[string][]byte{"vault.key": key})
	dbcfg := config.Database{
		Name: "sales", Backend: "vault", Path: "sales.vault", Mode: "rwc",
		Vault: &config.VaultConfig{Cipher: "adiantum", Compression: "best", Key: "f:vault.key"},
	}

	db := openBackend(t, dbcfg, sec, dir)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "CREATE TABLE t(x)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO t VALUES(7)"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen with the same key: the row survives (encrypted at rest, decrypted on open).
	db2 := openBackend(t, dbcfg, sec, dir)
	defer db2.Close()
	var x int
	if err := db2.QueryRowContext(ctx, "SELECT x FROM t").Scan(&x); err != nil {
		t.Fatalf("reopen read: %v", err)
	}
	if x != 7 {
		t.Fatalf("row not preserved: x=%d", x)
	}

	// A wrong key fails to open (For resolves the key; Open rejects it).
	badSec := secretDir(t, map[string][]byte{"vault.key": make([]byte, 32)})
	beBad, err := backend.For(dbcfg, badSec, dir)
	if err != nil {
		t.Fatalf("For with wrong key should defer the failure to Open: %v", err)
	}
	if h, err := beBad.Open(ctx); err == nil {
		_ = h.Close()
		t.Fatal("opening a vault with the wrong key should fail")
	}
}

// --- vault: multi-recipient ---

func TestVaultMultiRecipient(t *testing.T) {
	dir := t.TempDir()
	aPriv, aPub := genSSHKey(t)
	bPriv, bPub := genSSHKey(t)
	cPriv, _ := genSSHKey(t) // a stranger, not a recipient
	sec := secretDir(t, map[string][]byte{
		"a.key": aPriv, "a.pub": aPub,
		"b.key": bPriv, "b.pub": bPub,
		"c.key": cPriv,
	})
	base := func(v *config.VaultConfig) config.Database {
		return config.Database{Name: "m", Backend: "vault", Path: "m.vault", Mode: "rwc", Vault: v}
	}
	ctx := context.Background()

	// Create wrapped to recipients A and B.
	create := openBackend(t, base(&config.VaultConfig{
		Create: &config.VaultCreate{Recipients: []string{"f:a.pub", "f:b.pub"}},
	}), sec, dir)
	if _, err := create.ExecContext(ctx, "CREATE TABLE t(x); INSERT INTO t VALUES(42);"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := create.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Identity A opens it and reads the row.
	dbA := openBackend(t, base(&config.VaultConfig{Identities: []string{"f:a.key"}}), sec, dir)
	var x int
	if err := dbA.QueryRowContext(ctx, "SELECT x FROM t").Scan(&x); err != nil || x != 42 {
		t.Fatalf("identity A open/read: x=%d err=%v", x, err)
	}
	_ = dbA.Close()

	// Identity B (also a recipient) opens it too.
	dbB := openBackend(t, base(&config.VaultConfig{Identities: []string{"f:b.key"}}), sec, dir)
	if err := dbB.QueryRowContext(ctx, "SELECT x FROM t").Scan(&x); err != nil || x != 42 {
		t.Fatalf("identity B open/read: x=%d err=%v", x, err)
	}
	_ = dbB.Close()

	// The stranger C is refused (no keyslot unwraps for its identity). The vault's
	// ErrNoIdentity surfaces through sqlite.Open as a cannot-open error, so assert
	// on the refusal rather than the exact wrapped sentinel.
	beC, err := backend.For(base(&config.VaultConfig{Identities: []string{"f:c.key"}}), sec, dir)
	if err != nil {
		t.Fatalf("For(C): %v", err)
	}
	if h, err := beC.Open(ctx); err == nil {
		_ = h.Close()
		t.Fatal("a non-recipient identity must not open the vault")
	}
}

// --- vault: read-only recipient write-blocked (writer/master tier) ---

func TestVaultReadOnlyRecipientWriteBlocked(t *testing.T) {
	dir := t.TempDir()
	readerPriv, readerPub := genSSHKey(t)
	writerPriv, writerPub := genSSHKey(t)
	adminPriv, adminPub := genSSHKey(t)
	sec := secretDir(t, map[string][]byte{
		"reader.key": readerPriv, "reader.pub": readerPub,
		"writer.key": writerPriv, "writer.pub": writerPub,
		"admin.key": adminPriv, "admin.pub": adminPub,
	})
	db := func(v *config.VaultConfig) config.Database {
		return config.Database{Name: "w", Backend: "vault", Path: "w.vault", Mode: "rwc", Vault: v}
	}
	ctx := context.Background()

	// Provision an authenticated-writer container: reader is a read-only member,
	// writer is the authorized signer, admin is the master that signs the keyslot.
	create := openBackend(t, db(&config.VaultConfig{
		WriteAs: "f:writer.key",
		Create: &config.VaultCreate{
			Recipients: []string{"f:reader.pub"},
			Masters:    []string{"f:admin.pub"},
			SignWith:   "f:admin.key",
			Writers:    []string{"f:writer.pub"},
		},
	}), sec, dir)
	if _, err := create.ExecContext(ctx, "CREATE TABLE t(x); INSERT INTO t VALUES(1);"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := create.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reader opens WITHOUT write_as → reads fine, but a write is refused at the VFS.
	reader := openBackend(t, db(&config.VaultConfig{
		Identities: []string{"f:reader.key"}, Masters: []string{"f:admin.pub"},
	}), sec, dir)
	var n int
	if err := reader.QueryRowContext(ctx, "SELECT count(*) FROM t").Scan(&n); err != nil || n != 1 {
		t.Fatalf("reader read: n=%d err=%v", n, err)
	}
	if _, err := reader.ExecContext(ctx, "INSERT INTO t VALUES(2)"); err == nil {
		t.Fatal("a read-only recipient must not be able to write")
	}
	_ = reader.Close()

	// Confirm the reader's write did not persist, and the writer CAN write.
	writer := openBackend(t, db(&config.VaultConfig{
		Identities: []string{"f:writer.key"}, Masters: []string{"f:admin.pub"}, WriteAs: "f:writer.key",
	}), sec, dir)
	defer writer.Close()
	if err := writer.QueryRowContext(ctx, "SELECT count(*) FROM t").Scan(&n); err != nil || n != 1 {
		t.Fatalf("read-only write leaked or read failed: n=%d err=%v", n, err)
	}
	if _, err := writer.ExecContext(ctx, "INSERT INTO t VALUES(3)"); err != nil {
		t.Fatalf("writer identity should be able to write: %v", err)
	}
}
