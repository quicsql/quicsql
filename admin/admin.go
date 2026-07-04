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
	"strings"
	"time"

	"quicsql.net/authz"
	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/internal/httpjson"
	"quicsql.net/meta"
	"quicsql.net/obs"
	"quicsql.net/registry"
	"quicsql.net/secret"
	"quicsql.net/session"
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
	metrics  obs.Metrics // to forget a detached database's series (may be nil)
	dataDir  string
	admins   map[string]bool // server-admin principal names
	started  time.Time
	log      *slog.Logger
}

// New builds the admin handler. admins are the server-admin principal names from
// control_plane.admins; sessions (may be nil) backs the sessions/kill endpoints;
// metrics (may be nil) has a detached database's series forgotten; started is used
// for the uptime report.
func New(reg *registry.Registry, pol *authz.Policy, store *meta.Store, sessions *session.Store, sec secret.Resolver, metrics obs.Metrics, dataDir string, admins []string, started time.Time, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	set := make(map[string]bool, len(admins))
	for _, a := range admins {
		set[a] = true
	}
	return &Handler{reg: reg, pol: pol, store: store, sessions: sessions, sec: sec, metrics: metrics, dataDir: dataDir, admins: set, started: started, log: log}
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
//
// Note: a wildcard `*: admin` grant makes CanAdmin true for the anonymous
// principal too, so per-database maintenance (compact/reclaim/trim/snapshot) on
// that database can reach an unauthenticated caller. This is the documented
// wildcard-matches-everyone semantic; its blast radius is bounded — server-admin
// operations (create/detach) never collapse to anonymous, and snapshot writes only
// within data_dir. Don't grant `*: admin` on a database you don't want anyone to
// be able to compact/snapshot.
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

// contained resolves p against the server's data_dir and returns the cleaned
// absolute path if it stays within data_dir; ok=false for an escape (absolute
// path outside, or `..`) or when data_dir is unset. It is the guard for every
// control-plane path a caller supplies (create's db.Path, snapshot's dest), and
// shares config.WithinDir with the startup meta-store reconcile so the two can't
// diverge.
func (h *Handler) contained(p string) (string, bool) {
	return config.WithinDir(h.dataDir, p)
}

// handleDatabases serves both /_admin/databases and /_admin/stats (the same
// view): the databases the caller may administer, each with its live per-database
// stats — kind, whether a handle is currently open, and its reference count.
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
		h.auditDeny(r, "create", "", "not server-admin")
		writeErr(w, http.StatusForbidden, "server-admin capability required")
		return
	}
	var req createRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	db := req.Database
	// The SAME per-database validator YAML seeds pass — name, backend, mode, tx_lock,
	// pragmas_preset, vault vocabulary — so a runtime create can't slip an invalid
	// spec (e.g. a typo'd mode the backend would coerce to read-write-create) past the
	// checks a seed is held to. Path containment is the extra control-plane-only gate.
	if err := config.ValidateDatabase(db); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// A control-plane-created on-disk database must live under data_dir: its path
	// must be relative and not escape (no absolute path, no `..`). This stops a
	// caller from making the server open/create a SQLite file at an arbitrary
	// filesystem location.
	if config.UsesPath(db.Backend) && db.Path != "" {
		if _, ok := h.contained(db.Path); !ok {
			h.auditFail(r, "create", db.Name, "path escapes data_dir: "+db.Path)
			writeErr(w, http.StatusBadRequest, "database path must be relative and within data_dir")
			return
		}
	}
	be, err := backend.For(db, h.sec, h.dataDir)
	if err != nil {
		h.log.Error("quicsql/admin: build backend", "db", db.Name, "err", err)
		h.auditFail(r, "create", db.Name, "build backend")
		writeErr(w, http.StatusBadRequest, "cannot build backend for database")
		return
	}
	if err := h.reg.Add(db.Name, be); err != nil {
		if errors.Is(err, registry.ErrExists) {
			h.auditFail(r, "create", db.Name, "already exists")
			writeErr(w, http.StatusConflict, "database already exists")
			return
		}
		h.auditFail(r, "create", db.Name, "register failed")
		writeErr(w, http.StatusInternalServerError, "cannot register database")
		return
	}
	// Verify it actually opens before we persist / grant, so a bad spec is rejected
	// now rather than on a client's first request; drop it again on failure.
	if _, release, err := h.reg.Get(r.Context(), db.Name); err != nil {
		_ = h.reg.Remove(db.Name)
		h.log.Error("quicsql/admin: open new database", "db", db.Name, "err", err)
		h.auditFail(r, "create", db.Name, "open failed")
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
			h.auditFail(r, "create", db.Name, "persist failed")
			writeErr(w, http.StatusInternalServerError, "database could not be persisted")
			return
		}
	}
	// Revoke first so this create's grant set is authoritative rather than
	// max-merged with any stale grants left under this name.
	h.pol.Revoke(db.Name)
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
		h.auditDeny(r, "detach", "", "not server-admin")
		writeErr(w, http.StatusForbidden, "server-admin capability required")
		return
	}
	var req struct {
		Database string `json:"database"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	switch err := h.reg.Remove(req.Database); {
	case errors.Is(err, registry.ErrUnknownDB):
		h.auditFail(r, "detach", req.Database, "unknown database")
		writeErr(w, http.StatusNotFound, "unknown database")
		return
	case errors.Is(err, registry.ErrBusy):
		h.auditFail(r, "detach", req.Database, "database busy")
		writeErr(w, http.StatusConflict, "database busy (has active users); retry when idle")
		return
	case err != nil:
		h.auditFail(r, "detach", req.Database, "remove failed")
		writeErr(w, http.StatusInternalServerError, "cannot detach database")
		return
	}
	// Drop the database's grants so a later database that reuses this name does
	// not inherit stale privileges (Policy.Grant keeps the max level, so without
	// this a re-created name would silently retain the old grants).
	h.pol.Revoke(req.Database)
	// Forget its metrics series so scrapes don't accrue detached databases.
	if h.metrics != nil {
		h.metrics.Forget(req.Database)
	}
	if h.store != nil {
		_ = h.store.Delete(req.Database)
		h.store.Audit(h.principal(r), "detach", req.Database, "")
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "detached", "database": req.Database})
}

// --- error/JSON helpers (same envelope shape as the data plane) ---

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) { httpjson.Write(w, status, v) }

func writeErr(w http.ResponseWriter, status int, msg string) { httpjson.Error(w, status, msg) }
