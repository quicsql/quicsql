// Package admin is the control plane: the /_admin HTTP surface for runtime
// database lifecycle (create / detach / list) and vault maintenance (offline
// compact, online reclaim, snapshot). Every route requires an admin capability —
// a server-admin principal, or (for a single database's maintenance) an `admin`
// grant on that database — and every mutating action is audit-logged to the meta
// store. It shares the same auth middleware and transports as the data plane; it
// is a distinct http.Handler mounted under /_admin by the main handler.
package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"gosqlite.org/server/authz"
	"gosqlite.org/server/backend"
	"gosqlite.org/server/config"
	"gosqlite.org/server/internal/httpjson"
	"gosqlite.org/server/meta"
	"gosqlite.org/server/registry"
	"gosqlite.org/server/secret"
	"gosqlite.org/server/session"
)

// Handler serves /_admin/*. It is nil-safe to construct without a meta store
// (Store may be nil for a stateless deployment): create/detach then don't
// persist across restart, and audit records are dropped.
type Handler struct {
	reg      *registry.Registry
	pol      *authz.Policy
	store    *meta.Store
	sessions *session.Store // live sessions, for introspection + KILL (may be nil)
	sec      secret.Resolver
	dataDir  string
	admins   map[string]bool // server-admin principal names
	started  time.Time
	log      *slog.Logger
}

// New builds the admin handler. admins are the server-admin principal names from
// control_plane.admins; sessions (may be nil) backs the sessions/kill endpoints;
// started is used for the uptime report.
func New(reg *registry.Registry, pol *authz.Policy, store *meta.Store, sessions *session.Store, sec secret.Resolver, dataDir string, admins []string, started time.Time, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	set := make(map[string]bool, len(admins))
	for _, a := range admins {
		set[a] = true
	}
	return &Handler{reg: reg, pol: pol, store: store, sessions: sessions, sec: sec, dataDir: dataDir, admins: set, started: started, log: log}
}

// ServeHTTP routes the /_admin/* endpoints. The prefix is already matched by the
// parent handler; here we dispatch the sub-path.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimPrefix(r.URL.Path, "/_admin")
	switch sub {
	case "/databases", "/stats":
		h.handleDatabases(w, r)
	case "/create":
		h.handleCreate(w, r)
	case "/detach":
		h.handleDetach(w, r)
	case "/maintenance":
		h.handleMaintenance(w, r)
	case "/info":
		h.handleInfo(w, r)
	case "/sessions":
		h.handleSessions(w, r)
	case "/kill":
		h.handleKill(w, r)
	default:
		writeErr(w, http.StatusNotFound, "unknown admin endpoint")
	}
}

// isServerAdmin reports whether the request's principal is a configured
// server-admin. Unlike the data plane, the control plane does NOT collapse to
// "everyone" in open mode — its capabilities (create/detach, arbitrary path
// creation, decrypted snapshots) are too dangerous to hand to an unauthenticated
// caller. The control plane requires at least one configured admin (enforced at
// config load), so a named, authenticated admin is always required here.
func (h *Handler) isServerAdmin(r *http.Request) bool {
	return h.admins[authz.FromContext(r.Context()).Name]
}

// adminFilter returns the per-database "may administer" predicate for a request:
// a server-admin administers every database; otherwise a holder of an `admin`
// grant administers that database. It is the single source for the authz-filtered
// list (databases/stats/sessions) and the per-op check (canAdminDB).
func (h *Handler) adminFilter(r *http.Request) func(db string) bool {
	admin := h.isServerAdmin(r)
	p := authz.FromContext(r.Context())
	return func(db string) bool { return admin || h.pol.Level(p, db).CanAdmin() }
}

// canAdminDB reports whether the principal may run maintenance on db.
func (h *Handler) canAdminDB(r *http.Request, db string) bool {
	return h.adminFilter(r)(db)
}

func (h *Handler) principal(r *http.Request) string {
	return authz.FromContext(r.Context()).Name
}

// usesPath reports whether a backend opens an on-disk file addressed by db.Path
// (so its path must be containment-checked). In-memory backends ignore Path.
func usesPath(backend string) bool { return backend == "file" || backend == "vault" }

// contained resolves p against the server's data_dir and returns the cleaned
// absolute path if it stays within data_dir; ok=false for an escape (absolute
// path outside, or `..`) or when data_dir is unset. It is the single guard for
// every control-plane path a caller supplies (create's db.Path, snapshot's dest).
func (h *Handler) contained(p string) (string, bool) {
	if h.dataDir == "" || p == "" {
		return "", false
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(h.dataDir, abs)
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(h.dataDir, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return abs, true
}

// handleDatabases lists the databases the caller may administer.
func (h *Handler) handleDatabases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	allow := h.adminFilter(r)
	out := make([]map[string]any, 0)
	for _, info := range h.reg.List() {
		if !allow(info.Name) {
			continue
		}
		out = append(out, map[string]any{
			"name": info.Name, "kind": info.Kind, "open": info.Open, "refs": info.Refs,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"databases": out})
}

// createRequest provisions a new database at runtime. The spec is a config
// Database (same shape as a YAML seed); grants, if any, are applied to the policy.
type createRequest struct {
	Database config.Database `json:"database"`
	Grants   []config.Grant  `json:"grants"`
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if !h.isServerAdmin(r) {
		writeErr(w, http.StatusForbidden, "server-admin capability required")
		return
	}
	var req createRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	db := req.Database
	if !config.ValidDBName(db.Name) {
		writeErr(w, http.StatusBadRequest, "invalid or reserved database name")
		return
	}
	if !config.KnownBackends[db.Backend] {
		writeErr(w, http.StatusBadRequest, "unknown backend")
		return
	}
	// A control-plane-created on-disk database must live under data_dir: its path
	// must be relative and not escape (no absolute path, no `..`). This stops a
	// caller from making the server open/create a SQLite file at an arbitrary
	// filesystem location.
	if usesPath(db.Backend) && db.Path != "" {
		if _, ok := h.contained(db.Path); !ok {
			writeErr(w, http.StatusBadRequest, "database path must be relative and within data_dir")
			return
		}
	}
	be, err := backend.For(db, h.sec, h.dataDir)
	if err != nil {
		h.log.Error("quicsql/admin: build backend", "db", db.Name, "err", err)
		writeErr(w, http.StatusBadRequest, "cannot build backend for database")
		return
	}
	if err := h.reg.Add(db.Name, be); err != nil {
		if errors.Is(err, registry.ErrExists) {
			writeErr(w, http.StatusConflict, "database already exists")
			return
		}
		writeErr(w, http.StatusInternalServerError, "cannot register database")
		return
	}
	// Verify it actually opens before we persist / grant, so a bad spec is rejected
	// now rather than on a client's first request; drop it again on failure.
	if _, release, err := h.reg.Get(r.Context(), db.Name); err != nil {
		_ = h.reg.Remove(db.Name)
		h.log.Error("quicsql/admin: open new database", "db", db.Name, "err", err)
		writeErr(w, http.StatusBadRequest, "database could not be opened")
		return
	} else {
		release()
	}
	// Persist BEFORE granting, and roll the registry back on a persist failure, so
	// the live state never diverges from what survives a restart (a "created"
	// response always means durably created).
	if h.store != nil {
		db.Grants = req.Grants
		if err := h.store.Put(db); err != nil {
			_ = h.reg.Remove(db.Name)
			h.log.Error("quicsql/admin: persist database", "db", db.Name, "err", err)
			writeErr(w, http.StatusInternalServerError, "database could not be persisted")
			return
		}
	}
	for _, g := range req.Grants {
		if lvl, ok := authz.ParseLevel(g.Level); ok {
			h.pol.Grant(db.Name, g.Principal, lvl)
		}
	}
	if h.store != nil {
		h.store.Audit(h.principal(r), "create", db.Name, db.Backend)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "created", "database": db.Name})
}

func (h *Handler) handleDetach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if !h.isServerAdmin(r) {
		writeErr(w, http.StatusForbidden, "server-admin capability required")
		return
	}
	var req struct {
		Database string `json:"database"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	switch err := h.reg.Remove(req.Database); {
	case errors.Is(err, registry.ErrUnknownDB):
		writeErr(w, http.StatusNotFound, "unknown database")
		return
	case errors.Is(err, registry.ErrBusy):
		writeErr(w, http.StatusConflict, "database busy (has active users); retry when idle")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "cannot detach database")
		return
	}
	if h.store != nil {
		_ = h.store.Delete(req.Database)
		h.store.Audit(h.principal(r), "detach", req.Database, "")
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "detached", "database": req.Database})
}

// --- error/JSON helpers (same envelope shape as the data plane) ---

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) { httpjson.Write(w, status, v) }

func writeErr(w http.ResponseWriter, status int, msg string) { httpjson.Error(w, status, msg) }
