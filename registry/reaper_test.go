package registry_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"quicsql.net/backend"
	"quicsql.net/registry"
)

// TestReapIdleAndCloseHook covers M8 (idle-handle eviction) and M9 (the close
// hook): an idle handle is reaped only past its TTL, the close hook fires for it,
// and a later Get reopens the (still-registered) database.
func TestReapIdleAndCloseHook(t *testing.T) {
	be := &fakeBackend{}
	reg := registry.New(map[string]backend.Backend{"d": be}, nil)
	defer reg.Close()

	var closed atomic.Int32
	reg.SetCloseHook(func(*registry.DB) { closed.Add(1) })

	// Open then release → an idle handle at refs 0.
	_, rel, err := reg.Get(context.Background(), "d")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	rel()

	// A long TTL leaves the freshly-used handle open.
	if n := reg.ReapIdle(time.Hour); n != 0 {
		t.Fatalf("ReapIdle(1h) reaped %d, want 0", n)
	}
	// Once it has been idle past a short TTL, it is reaped and the hook fires.
	time.Sleep(3 * time.Millisecond)
	if n := reg.ReapIdle(time.Millisecond); n != 1 {
		t.Fatalf("ReapIdle reaped %d, want 1", n)
	}
	if got := closed.Load(); got != 1 {
		t.Fatalf("close hook fired %d times, want 1", got)
	}

	// The backend is still registered, so a fresh Get reopens the handle.
	_, rel2, err := reg.Get(context.Background(), "d")
	if err != nil {
		t.Fatalf("reopen Get: %v", err)
	}
	rel2()
}
