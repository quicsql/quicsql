package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"quicsql.net/authz"
	"quicsql.net/feed"
)

// keepaliveInterval paces SSE comment pings so idle streams survive proxies
// and NAT timeouts.
const keepaliveInterval = 25 * time.Second

// handleChanges serves GET /<db>/changes — the committed-change feed as
// Server-Sent Events. Read capability required; resume with ?since=<seq> (or
// the standard Last-Event-ID header); optional ?tables=a,b filters. The stream
// opens with `event: ready` (current sequence) or `event: reset` (the requested
// horizon is gone — refetch, then follow), then emits `event: change` entries.
// A silently closed stream means the server dropped a lagging subscriber or is
// shutting down: reconnect with the last seen id.
func (h *Handler) handleChanges(w http.ResponseWriter, r *http.Request, db string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	if h.feed == nil {
		writeErr(w, http.StatusNotFound, "change feed not enabled")
		return
	}
	if _, ok := h.authorize(w, r, db); !ok {
		return
	}
	// Admission: consume a per-principal rate token on connect so reconnect storms
	// are throttled like any other request, but release the per-db concurrency slot
	// immediately — a long-lived stream must not hold one for its whole life (that
	// would exhaust the per-db cap in a handful of subscribers). The subscriber
	// count is bounded separately by max_subscribers below.
	if h.limiter != nil {
		release, ok, reason := h.limiter.Allow(authz.FromContext(r.Context()).Name, db)
		if !ok {
			if reason == "rate" {
				writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
			} else {
				writeErr(w, http.StatusServiceUnavailable, "database busy: too many concurrent requests")
			}
			return
		}
		release()
	}
	if !h.feed.Observed(db) {
		writeErr(w, http.StatusNotFound, "change feed unavailable for this database (no stable path)")
		return
	}
	var since uint64
	if s := r.URL.Query().Get("since"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "since must be an unsigned integer")
			return
		}
		since = v
	} else if s := r.Header.Get("Last-Event-ID"); s != "" {
		if v, err := strconv.ParseUint(s, 10, 64); err == nil {
			since = v
		}
	}
	var tables map[string]bool
	if t := r.URL.Query().Get("tables"); t != "" {
		tables = map[string]bool{}
		for name := range strings.SplitSeq(t, ",") {
			if name = strings.TrimSpace(name); name != "" {
				tables[name] = true
			}
		}
	}

	sub, replay, reset, ok, full := h.feed.Subscribe(db, since)
	if !ok {
		writeErr(w, http.StatusNotFound, "change feed unavailable")
		return
	}
	if full {
		writeErr(w, http.StatusServiceUnavailable, "too many change-feed subscribers")
		return
	}
	defer sub.Close()

	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Accel-Buffering", "no") // tell buffering proxies to pass events through
	rc := http.NewResponseController(w)
	// The transport's connection write timeout would sever a long-lived stream;
	// deadlines are re-armed per write instead.
	_ = rc.SetWriteDeadline(time.Time{})
	w.WriteHeader(http.StatusOK)

	emit := func(format string, args ...any) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return false
		}
		_ = rc.SetWriteDeadline(time.Time{})
		return rc.Flush() == nil
	}
	change := func(e feed.Event) bool {
		// A reset marker (a transaction whose detail overflowed) is never table-
		// filtered — it means "refetch", which every subscriber must honor.
		if e.Reset {
			return emit("id: %d\nevent: reset\ndata: {\"seq\":%d}\n\n", e.Seq, e.Seq)
		}
		if tables != nil && !tables[e.Table] {
			return true
		}
		data, err := json.Marshal(e)
		if err != nil {
			return false
		}
		return emit("id: %d\nevent: change\ndata: %s\n\n", e.Seq, data)
	}

	head := "ready"
	if reset {
		head = "reset"
	}
	if !emit("event: %s\ndata: {\"seq\":%d}\n\n", head, h.feed.Seq(db)) {
		return
	}
	for _, e := range replay {
		if !change(e) {
			return
		}
	}

	keepalive := time.NewTicker(keepaliveInterval)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, live := <-sub.C:
			if !live {
				return // dropped (lagging) or database detached — client reconnects
			}
			if !change(e) {
				return
			}
		case <-keepalive.C:
			if !emit(": ping\n\n") {
				return
			}
		}
	}
}
