package admin

import (
	"net/http"
	"runtime"
	"time"

	"quicsql.net/session"
)

// handleInfo reports server-level state (uptime, goroutines, memory, database and
// session counts). Server-admin only — it exposes process internals.
func (h *Handler) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	if !h.isServerAdmin(r) {
		writeErr(w, http.StatusForbidden, "server-admin capability required")
		return
	}
	dbs := h.reg.List()
	open := 0
	for _, d := range dbs {
		if d.Open {
			open++
		}
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	sessions := 0
	if h.sessions != nil {
		sessions = h.sessions.Count()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"uptime_seconds":  int64(time.Since(h.started).Seconds()),
		"goroutines":      runtime.NumGoroutine(),
		"heap_bytes":      mem.HeapAlloc,
		"databases":       len(dbs),
		"open_databases":  open,
		"active_sessions": sessions,
	})
}

// handleSessions lists live interactive-transaction sessions, filtered to the
// databases the caller may administer (server-admin sees all).
func (h *Handler) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	if h.sessions == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": []any{}})
		return
	}
	out := make([]map[string]any, 0)
	for _, s := range h.sessions.List(h.adminFilter(r)) {
		out = append(out, map[string]any{
			"id": s.ID, "database": s.DBName, "principal": s.Principal,
			"read_only": s.ReadOnly, "in_flight": s.Busy,
			"age_seconds": int64(s.Age.Seconds()), "idle_seconds": int64(s.IdleFor.Seconds()),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// handleKill force-closes a session by id (server-admin only). A session with a
// request in flight is refused (409) — it is bounded by the statement timeout.
func (h *Handler) handleKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if !h.isServerAdmin(r) {
		h.auditDeny(r, "kill", "", "not server-admin")
		writeErr(w, http.StatusForbidden, "server-admin capability required")
		return
	}
	if h.sessions == nil {
		writeErr(w, http.StatusNotImplemented, "sessions not enabled")
		return
	}
	var req struct {
		Session string `json:"session"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	switch h.sessions.Kill(req.Session) {
	case session.KillNotFound:
		writeErr(w, http.StatusNotFound, "no such session")
	case session.KillBusy:
		writeErr(w, http.StatusConflict, "session has a request in flight; it will end at the statement timeout")
	default:
		h.audit(r, "kill", "", req.Session)
		writeJSON(w, http.StatusOK, map[string]any{"status": "killed", "session": req.Session})
	}
}
