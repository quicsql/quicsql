package limits

import (
	"testing"
	"time"
)

func TestRateLimitPerPrincipal(t *testing.T) {
	l := New(5, 0) // 5 rps, burst 5, no concurrency cap
	// Freeze the clock so no tokens refill during the test.
	base := time.Unix(1000, 0)
	l.now = func() time.Time { return base }

	// The burst (5) is admitted; the 6th is rejected as "rate".
	for i := range 5 {
		if rel, ok, _ := l.Allow("app", "db"); !ok {
			t.Fatalf("request %d should be admitted", i)
		} else {
			rel()
		}
	}
	if _, ok, reason := l.Allow("app", "db"); ok || reason != "rate" {
		t.Fatalf("6th request: ok=%v reason=%q, want rejected/rate", ok, reason)
	}
	// A different principal has its own bucket.
	if _, ok, _ := l.Allow("other", "db"); !ok {
		t.Fatal("a different principal must have its own bucket")
	}
	// After a second of refill, tokens are available again.
	l.now = func() time.Time { return base.Add(time.Second) }
	if _, ok, _ := l.Allow("app", "db"); !ok {
		t.Fatal("tokens should refill after a second")
	}
}

func TestConcurrencyCapPerDB(t *testing.T) {
	l := New(0, 2) // no rate limit, max 2 concurrent per db
	r1, ok, _ := l.Allow("a", "db")
	if !ok {
		t.Fatal("first concurrent request rejected")
	}
	r2, ok, _ := l.Allow("b", "db")
	if !ok {
		t.Fatal("second concurrent request rejected")
	}
	if _, ok, reason := l.Allow("c", "db"); ok || reason != "busy" {
		t.Fatalf("third concurrent request: ok=%v reason=%q, want rejected/busy", ok, reason)
	}
	if got := l.InFlight("db"); got != 2 {
		t.Fatalf("in-flight = %d, want 2", got)
	}
	// A different database is independent.
	if _, ok, _ := l.Allow("c", "other"); !ok {
		t.Fatal("a different database must have its own concurrency budget")
	}
	// Releasing frees a slot.
	r1()
	if got := l.InFlight("db"); got != 1 {
		t.Fatalf("after release, in-flight = %d, want 1", got)
	}
	if _, ok, _ := l.Allow("c", "db"); !ok {
		t.Fatal("a freed slot should admit a new request")
	}
	r2()
}

func TestUnlimitedByDefault(t *testing.T) {
	l := New(0, 0)
	for i := range 1000 {
		if rel, ok, _ := l.Allow("x", "db"); !ok {
			t.Fatalf("unlimited limiter rejected request %d", i)
		} else {
			rel()
		}
	}
}
