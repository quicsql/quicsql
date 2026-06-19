package registry_test

import (
	"context"
	"path/filepath"
	"testing"

	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/engine"
	"quicsql.net/registry"
	"quicsql.net/secret"
)

// TestPhase0_MultiplexAcrossBackends is the Phase 0 exit criterion: open plain,
// shared-in-memory, and vault databases through the registry and run
// statements / a batched transaction / a query against each — the transport-free
// core of the multiplexer.
func TestPhase0_MultiplexAcrossBackends(t *testing.T) {
	dir := t.TempDir()
	sec, err := secret.New(nil)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}

	dbs := []config.Database{
		{Name: "plain", Backend: "file", Path: filepath.Join(dir, "plain.db"),
			Pragmas: map[string]any{"journal_mode": "WAL"}},
		{Name: "cache", Backend: "memory-shared"},
		{Name: "vault", Backend: "vault", Path: filepath.Join(dir, "data.vault"),
			Vault: &config.VaultConfig{Compression: "best"}}, // plain-but-compressed container
	}

	backends := map[string]backend.Backend{}
	for _, d := range dbs {
		be, err := backend.For(d, sec, dir)
		if err != nil {
			t.Fatalf("backend.For(%s): %v", d.Name, err)
		}
		backends[d.Name] = be
	}

	reg := registry.New(backends, nil)
	t.Cleanup(func() { _ = reg.Close() })
	eng := engine.New(0, 0)
	ctx := context.Background()

	for _, name := range []string{"plain", "cache", "vault"} {
		db, release, err := reg.Get(ctx, name)
		if err != nil {
			t.Fatalf("Get(%s): %v", name, err)
		}

		if _, err := eng.Exec(ctx, db.Handle, engine.Statement{SQL: "CREATE TABLE t(x INTEGER)"}); err != nil {
			t.Fatalf("%s create: %v", name, err)
		}
		if _, err := eng.Batch(ctx, db.Handle.DB, []engine.Statement{
			{SQL: "INSERT INTO t(x) VALUES(?)", Args: []engine.Value{engine.Int(1)}},
			{SQL: "INSERT INTO t(x) VALUES(?)", Args: []engine.Value{engine.Int(2)}},
		}); err != nil {
			t.Fatalf("%s batch: %v", name, err)
		}

		res, err := eng.Query(ctx, db.Handle, engine.Statement{SQL: "SELECT count(*) FROM t"})
		if err != nil {
			t.Fatalf("%s query: %v", name, err)
		}
		if len(res.Rows) != 1 || res.Rows[0][0].Int != 2 {
			t.Fatalf("%s: want count 2, got %+v", name, res.Rows)
		}
		release()
	}
}

// TestPhase0_ReserveBlocksOpen checks the offline-op reservation path used by
// the control plane for Rekey/Rewrap/Compact.
func TestPhase0_ReserveBlocksOpen(t *testing.T) {
	dir := t.TempDir()
	sec, _ := secret.New(nil)
	be, err := backend.For(config.Database{Name: "d", Backend: "file", Path: filepath.Join(dir, "d.db")}, sec, dir)
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{"d": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	ctx := context.Background()

	release, err := reg.Reserve("d")
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if _, _, err := reg.Get(ctx, "d"); err != registry.ErrReserved {
		t.Fatalf("Get while reserved: want ErrReserved, got %v", err)
	}
	release()
	if _, rel, err := reg.Get(ctx, "d"); err != nil {
		t.Fatalf("Get after release: %v", err)
	} else {
		rel()
	}
}
