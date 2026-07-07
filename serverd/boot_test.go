package serverd

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"quicsql.net/config"
	"quicsql.net/meta"
	"quicsql.net/secret"
)

// TestBootWarmsOnlySeeds regresses the boot-time open sweep: Warm must open the
// config-declared seeds (fail-fast) but leave meta-restored runtime-created
// databases — e.g. a fleet of per-account databases — closed until first use.
func TestBootWarmsOnlySeeds(t *testing.T) {
	dir := t.TempDir()
	sec, err := secret.New(nil)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}

	// Pre-seed the meta store with a runtime-created database, as a prior run's
	// control plane / enroll-time provisioning would have.
	ms := config.MetaStore{Backend: "file", Path: "_meta.db"}
	store, err := meta.Open(ms, sec, dir, nil)
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	if err := store.Put(config.Database{Name: "u_restored", Backend: "file", Path: "u_restored.db", Mode: "rwc"}); err != nil {
		t.Fatalf("meta.Put: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("meta.Close: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	cfg := &config.Config{
		Server:       config.Server{DataDir: dir, MetaStore: ms},
		ControlPlane: config.ControlPlane{Enabled: true},
		Databases:    []config.Database{{Name: "seed", Backend: "memory-shared"}},
		Listeners:    []config.Listener{{Name: "h1", Transport: "h1", Address: addr}},
	}
	srv, err := Run(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("serverd.Run: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })

	seen := map[string]bool{}
	for _, info := range srv.registry.List() {
		seen[info.Name] = true
		switch info.Name {
		case "seed":
			if !info.Open {
				t.Error("config seed not open after boot (Warm must fail-fast on seeds)")
			}
		case "u_restored":
			if info.Open {
				t.Error("meta-restored database open after boot (must open lazily on first use)")
			}
		}
	}
	for _, name := range []string{"seed", "u_restored"} {
		if !seen[name] {
			t.Errorf("database %q not registered after boot", name)
		}
	}
}
