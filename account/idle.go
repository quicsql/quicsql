package account

import (
	"context"
	"strings"
	"time"
)

// Touch records that an account just authenticated (idle-GC last-seen). Registered
// as the authenticator's seen-hook, so it runs on the auth hot path — a cheap
// in-memory write. Only account principals (u_…) are buffered; the hook also fires
// for static operators, whose Touch would be a no-op against the accounts table.
func (s *Service) Touch(name string) {
	if s.cfg.IdleTTL <= 0 || !strings.HasPrefix(name, accountPrefix) {
		return
	}
	now := time.Now().Unix()
	s.seenMu.Lock()
	s.seen[name] = now
	s.seenMu.Unlock()
}

// flushSeen persists buffered last-seen times to the meta store, re-buffering on a
// write error so a transient failure doesn't lose activity.
func (s *Service) flushSeen() {
	s.seenMu.Lock()
	if len(s.seen) == 0 {
		s.seenMu.Unlock()
		return
	}
	batch := s.seen
	s.seen = make(map[string]int64, len(batch))
	s.seenMu.Unlock()
	if err := s.store.TouchAccounts(batch); err != nil {
		s.log.Error("quicsql/account: flush last-seen", "err", err)
		s.seenMu.Lock()
		for name, at := range batch {
			if cur, ok := s.seen[name]; !ok || at > cur {
				s.seen[name] = at
			}
		}
		s.seenMu.Unlock()
	}
}

// reap flushes last-seen, then deletes every account idle since before now-IdleTTL
// (via Delete, so provision.on_revoke governs its database). Returns how many were
// removed. Exposed for tests via an explicit now.
func (s *Service) reap(now int64) int {
	if s.cfg.IdleTTL <= 0 {
		return 0
	}
	s.flushSeen()
	s.store.GCSessions(now * int64(time.Second)) // drop expired session rows (unix nanos)
	idle, err := s.store.IdleAccounts(now - int64(s.cfg.IdleTTL.Seconds()))
	if err != nil {
		s.log.Error("quicsql/account: idle scan", "err", err)
		return 0
	}
	n := 0
	for _, name := range idle {
		switch ok, derr := s.Delete(name); {
		case derr != nil:
			s.log.Error("quicsql/account: idle GC delete", "account", name, "err", derr)
		case ok:
			s.store.Audit(name, "account.idle_gc", "", "")
			n++
		}
	}
	return n
}

// StartIdleReaper runs idle GC until ctx is cancelled, flushing last-seen once more
// on shutdown. A no-op when IdleTTL is 0. The tick derives from IdleTTL (bounded by
// [floor, 1h]) so a multi-day TTL doesn't flush to the encrypted store constantly.
func (s *Service) StartIdleReaper(ctx context.Context, floor time.Duration) {
	if s.cfg.IdleTTL <= 0 {
		return
	}
	interval := min(max(s.cfg.IdleTTL/20, floor), time.Hour)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				s.flushSeen()
				return
			case <-t.C:
				s.reap(time.Now().Unix())
			}
		}
	}()
}
