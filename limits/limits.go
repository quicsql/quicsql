// Package limits enforces the runtime safety rails that bound one client's or one
// database's share of the server: a per-principal request rate limit (token
// bucket) and a per-database concurrency cap (so one hot database can't starve
// the others). The result caps and statement/transaction timeouts live in the
// engine and session store; this package is the admission control in front of
// them.
package limits

import (
	"sync"
	"time"
)

// Limiter admits or rejects a request before it reaches the engine. The zero
// value (via New with non-positive limits) admits everything, so limits are
// opt-in.
type Limiter struct {
	rps      float64 // per-principal token-bucket refill rate (0 = unlimited)
	burst    float64 // bucket capacity
	perDBMax int     // max concurrent in-flight requests per database (0 = unlimited)
	mu       sync.Mutex
	buckets  map[string]*bucket // principal → token bucket
	inflight map[string]int     // database → in-flight count
	now      func() time.Time   // injectable clock for tests
}

// bucket is a token bucket for one principal.
type bucket struct {
	tokens float64
	last   time.Time
}

// New builds a Limiter. perPrincipalRPS<=0 disables rate limiting;
// maxConcurrentPerDB<=0 disables the concurrency cap.
func New(perPrincipalRPS float64, maxConcurrentPerDB int) *Limiter {
	burst := perPrincipalRPS // allow a one-second burst
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rps:      perPrincipalRPS,
		burst:    burst,
		perDBMax: maxConcurrentPerDB,
		buckets:  map[string]*bucket{},
		inflight: map[string]int{},
		now:      time.Now,
	}
}

// Allow reserves capacity for one request by principal against db. On success it
// returns a release func that MUST be called when the request finishes (it frees
// the per-db concurrency slot); ok=false means the request is rejected — reason
// is "rate" (per-principal rate exceeded) or "busy" (per-db concurrency cap
// reached), so the caller can map it to 429 vs 503.
func (l *Limiter) Allow(principal, db string) (release func(), ok bool, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.takeToken(principal) {
		return nil, false, "rate"
	}
	if l.perDBMax > 0 && l.inflight[db] >= l.perDBMax {
		// The token was already consumed; a rejected request still costs a token,
		// which is the standard token-bucket behavior (backpressure both ways).
		return nil, false, "busy"
	}
	l.inflight[db]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if l.inflight[db] > 0 {
				l.inflight[db]--
			}
			l.mu.Unlock()
		})
	}, true, ""
}

// takeToken refills and debits principal's bucket; caller holds l.mu. With rate
// limiting disabled it always succeeds.
func (l *Limiter) takeToken(principal string) bool {
	if l.rps <= 0 {
		return true
	}
	now := l.now()
	b := l.buckets[principal]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[principal] = b
	}
	// Refill proportionally to elapsed time, capped at burst.
	b.tokens += now.Sub(b.last).Seconds() * l.rps
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// InFlight reports the current in-flight request count for db (for introspection
// / tests).
func (l *Limiter) InFlight(db string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inflight[db]
}
