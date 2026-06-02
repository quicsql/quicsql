package registry_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gosqlite.org"
	"gosqlite.org/server/backend"
	"gosqlite.org/server/config"
	"gosqlite.org/server/engine"
	"gosqlite.org/server/registry"
	"gosqlite.org/server/secret"
)

// fakeBackend opens a real in-memory handle, optionally failing the first failN
// opens, and counts opens — enough to exercise the single-owner and retry paths.
type fakeBackend struct {
	failN int32
	opens atomic.Int32
}

func (b *fakeBackend) Open(ctx context.Context) (*sqlite.DB, error) {
	if n := b.opens.Add(1); n <= b.failN {
		return nil, fmt.Errorf("fake open fail #%d", n)
	}
	return sqlite.OpenInMemory()
}
func (b *fakeBackend) Kind() string   { return "memory" }
func (b *fakeBackend) ReadOnly() bool { return false }

// TestConcurrentColdGetSingleOwner is the regression for the Get/Reserve data
// race + exclusivity blocker: many concurrent Gets on a cold entry must open the
// backend exactly once and leave refs at zero. Run under -race.
func TestConcurrentColdGetSingleOwner(t *testing.T) {
	be := &fakeBackend{}
	reg := registry.New(map[string]backend.Backend{"d": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			db, release, err := reg.Get(ctx, "d")
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			_ = db
			release()
		})
	}
	wg.Wait()

	if got := be.opens.Load(); got != 1 {
		t.Fatalf("single-owner violated: opened %d times, want 1", got)
	}
	if info := reg.List(); len(info) != 1 || info[0].Refs != 0 {
		t.Fatalf("refs did not return to zero: %+v", info)
	}
}

// TestRetryAfterFailedOpen is the regression for a failed cold open poisoning
// the entry forever: the entry must be dropped so a later Get retries.
func TestRetryAfterFailedOpen(t *testing.T) {
	be := &fakeBackend{failN: 1}
	reg := registry.New(map[string]backend.Backend{"d": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	ctx := context.Background()

	if _, _, err := reg.Get(ctx, "d"); err == nil {
		t.Fatal("first Get: want open failure, got nil")
	}
	db, release, err := reg.Get(ctx, "d")
	if err != nil {
		t.Fatalf("second Get should retry and succeed, got %v", err)
	}
	release()
	_ = db
	if got := be.opens.Load(); got != 2 {
		t.Fatalf("want 2 open attempts (fail then retry), got %d", got)
	}
}

// TestWarm regresses the eager fail-fast contract: Warm errors if any seed
// can't open, and succeeds when all open.
func TestWarm(t *testing.T) {
	bad := registry.New(map[string]backend.Backend{"good": &fakeBackend{}, "bad": &fakeBackend{failN: 100}}, nil)
	t.Cleanup(func() { _ = bad.Close() })
	if err := bad.Warm(context.Background()); err == nil {
		t.Fatal("Warm: want error for a failing seed, got nil")
	}

	ok := registry.New(map[string]backend.Backend{"a": &fakeBackend{}, "b": &fakeBackend{}}, nil)
	t.Cleanup(func() { _ = ok.Close() })
	if err := ok.Warm(context.Background()); err != nil {
		t.Fatalf("Warm: %v", err)
	}
}

// TestReserveGuards covers the offline-op reservation guards.
func TestReserveGuards(t *testing.T) {
	be := &fakeBackend{}
	reg := registry.New(map[string]backend.Backend{"d": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	ctx := context.Background()

	if _, err := reg.Reserve("nope"); err == nil {
		t.Fatal("Reserve unknown db: want error, got nil")
	}

	_, release, err := reg.Get(ctx, "d")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := reg.Reserve("d"); err != registry.ErrBusy {
		t.Fatalf("Reserve while in use: want ErrBusy, got %v", err)
	}
	release()

	rel, err := reg.Reserve("d")
	if err != nil {
		t.Fatalf("Reserve after release: %v", err)
	}
	if _, _, err := reg.Get(ctx, "d"); err != registry.ErrReserved {
		t.Fatalf("Get while reserved: want ErrReserved, got %v", err)
	}
	rel()
}

// TestTimeRoundTrip is the regression for DATETIME corruption: a time value must
// not come back with time.Time's " +0000 UTC" suffix.
func TestTimeRoundTrip(t *testing.T) {
	sec, _ := secret.New(nil)
	be, err := backend.For(config.Database{Name: "d", Backend: "memory-shared"}, sec, "")
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{"d": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	eng := engine.New(0, 0)
	ctx := context.Background()

	db, release, err := reg.Get(ctx, "d")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer release()

	if _, err := eng.Exec(ctx, db.Handle, engine.Statement{SQL: "CREATE TABLE t(ts DATETIME)"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := eng.Exec(ctx, db.Handle, engine.Statement{
		SQL:  "INSERT INTO t(ts) VALUES(?)",
		Args: []engine.Value{engine.Text("2024-01-02T03:04:05Z")},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	res, err := eng.Query(ctx, db.Handle, engine.Statement{SQL: "SELECT ts FROM t"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	got := res.Rows[0][0]
	if got.Kind != engine.KindText || strings.Contains(got.Text, "+0000 UTC") {
		t.Fatalf("time round-trip corrupted: %+v", got)
	}
}
