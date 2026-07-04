package admin

import (
	"errors"
	"net/http"
	"os"

	"gosqlite.org"
	"quicsql.net/backend"
	"quicsql.net/registry"
)

// maintenanceRequest selects a maintenance op on one database.
//
//	op: "compact"        — OFFLINE: drain + reserve the handle, densely rewrite (vault only)
//	    "compact_online" — ONLINE:  return freed blocks to the OS on the live handle (vault only)
//	    "trim"           — ONLINE:  release the trailing free run (vault only)
//	    "snapshot"       — copy the database to `dest` via VACUUM INTO (any backend)
type maintenanceRequest struct {
	Database string `json:"database"`
	Op       string `json:"op"`
	MaxBytes int64  `json:"max_bytes"` // online reclaim cap; <=0 = unbounded
	Dest     string `json:"dest"`      // snapshot destination path
}

func (h *Handler) handleMaintenance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	var req maintenanceRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.canAdminDB(r, req.Database) {
		h.auditDeny(r, "maintenance", req.Database, "not admin for database")
		writeErr(w, http.StatusForbidden, "admin capability required for this database")
		return
	}
	if h.reg.Backend(req.Database) == nil {
		writeErr(w, http.StatusNotFound, "unknown database")
		return
	}
	switch req.Op {
	case "compact":
		h.offlineCompact(w, r, req)
	case "compact_online", "trim":
		h.onlineReclaim(w, r, req)
	case "snapshot":
		h.snapshot(w, r, req)
	default:
		writeErr(w, http.StatusBadRequest, "unknown maintenance op")
	}
}

// offlineCompact reserves the path (draining the idle handle; ErrBusy if it has
// active users) and rewrites the container densely. The reservation blocks new
// opens for the op's duration; the handle re-opens lazily afterward.
func (h *Handler) offlineCompact(w http.ResponseWriter, r *http.Request, req maintenanceRequest) {
	be := h.reg.Backend(req.Database)
	compacter, ok := be.(backend.OfflineCompacter)
	if !ok {
		writeErr(w, http.StatusBadRequest, "offline compact is only supported for vault databases")
		return
	}
	release, err := h.reg.Reserve(req.Database)
	if err != nil {
		if errors.Is(err, registry.ErrBusy) {
			writeErr(w, http.StatusConflict, "database busy (has active users); retry when idle")
			return
		}
		writeErr(w, http.StatusInternalServerError, "cannot reserve database")
		return
	}
	defer release()
	if err := compacter.CompactOffline(); err != nil {
		h.log.Error("quicsql/admin: offline compact", "db", req.Database, "err", err)
		writeErr(w, http.StatusInternalServerError, "compact failed")
		return
	}
	h.audit(r, "compact", req.Database, "offline")
	writeJSON(w, http.StatusOK, map[string]any{"status": "compacted", "database": req.Database})
}

// onlineReclaim runs an online reclaim against the LIVE handle: it pins a
// registry ref (keeping the container open in this process) and calls the op.
func (h *Handler) onlineReclaim(w http.ResponseWriter, r *http.Request, req maintenanceRequest) {
	be := h.reg.Backend(req.Database)
	reclaimer, ok := be.(backend.OnlineReclaimer)
	if !ok {
		writeErr(w, http.StatusBadRequest, "online reclaim is only supported for vault databases")
		return
	}
	_, releaseRef, err := h.reg.Get(r.Context(), req.Database) // keep the container open
	if err != nil {
		h.writeGetErr(w, req.Database, err)
		return
	}
	defer releaseRef()

	var reclaimed int64
	if req.Op == "trim" {
		reclaimed, err = reclaimer.Trim(req.MaxBytes)
	} else {
		reclaimed, err = reclaimer.CompactOnline(req.MaxBytes)
	}
	if err != nil {
		h.log.Error("quicsql/admin: online reclaim", "db", req.Database, "op", req.Op, "err", err)
		writeErr(w, http.StatusInternalServerError, "reclaim failed")
		return
	}
	h.audit(r, req.Op, req.Database, "online")
	writeJSON(w, http.StatusOK, map[string]any{"status": "reclaimed", "database": req.Database, "bytes_reclaimed": reclaimed})
}

// snapshot writes a consistent point-in-time image of the live database to
// req.Dest. It uses sqlite.Serialize (the C serialize API) rather than
// `VACUUM INTO`, since the latter internally ATTACHes the destination and the
// server's security authorizer denies ATTACH.
//
// Security: for a vault the image is the plain (decrypted) logical database, so
// dest is constrained to within data_dir (server-owned, not caller-controlled)
// and created with O_EXCL — no absolute-path escape, no `..`, no clobbering an
// existing file or following a symlink onto one. This keeps snapshot from being
// an arbitrary-file-write or a decrypted-vault-exfiltration primitive.
//
// NOTE: sqlite.Serialize buffers the whole logical database in memory before the
// write, so snapshot is a bounded-size admin op, not a streaming backup.
func (h *Handler) snapshot(w http.ResponseWriter, r *http.Request, req maintenanceRequest) {
	dest, ok := h.contained(req.Dest)
	if !ok {
		writeErr(w, http.StatusBadRequest, "snapshot dest must be a path within data_dir")
		return
	}
	dbh, releaseRef, err := h.reg.Get(r.Context(), req.Database)
	if err != nil {
		h.writeGetErr(w, req.Database, err)
		return
	}
	defer releaseRef()
	data, err := sqlite.Serialize(r.Context(), dbh.Handle.DB)
	if err != nil {
		h.log.Error("quicsql/admin: serialize snapshot", "db", req.Database, "err", err)
		writeErr(w, http.StatusInternalServerError, "snapshot failed")
		return
	}
	// O_EXCL: refuse to overwrite or follow a symlink onto an existing file.
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		writeErr(w, http.StatusConflict, "snapshot dest already exists or cannot be created")
		return
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		h.log.Error("quicsql/admin: write snapshot", "db", req.Database, "err", err)
		writeErr(w, http.StatusInternalServerError, "snapshot write failed")
		return
	}
	if err := f.Close(); err != nil {
		h.log.Error("quicsql/admin: close snapshot", "db", req.Database, "err", err)
		writeErr(w, http.StatusInternalServerError, "snapshot write failed")
		return
	}
	h.audit(r, "snapshot", req.Database, dest)
	writeJSON(w, http.StatusOK, map[string]any{"status": "snapshot", "database": req.Database, "dest": dest, "bytes": len(data)})
}

// writeGetErr maps a registry Get failure to a status, matching the data plane's
// httpapi.writeGetError (a reserved/busy database is a transient 503, not a 409;
// the 409 Conflict is reserved for the Reserve/Remove paths where the caller's
// own op conflicts with active users).
func (h *Handler) writeGetErr(w http.ResponseWriter, db string, err error) {
	switch {
	case errors.Is(err, registry.ErrUnknownDB):
		writeErr(w, http.StatusNotFound, "unknown database")
	case errors.Is(err, registry.ErrReserved), errors.Is(err, registry.ErrBusy):
		writeErr(w, http.StatusServiceUnavailable, "database temporarily unavailable")
	default:
		h.log.Error("quicsql/admin: open database", "db", db, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

func (h *Handler) audit(r *http.Request, action, db, detail string) {
	h.store.Audit(h.principal(r), action, db, detail)
}

// auditDeny records a rejected control-plane attempt (forbidden) so the trail
// captures who tried what — not only what succeeded. Suffixing the action with
// ".denied" keeps denials greppable and distinct from completed actions.
func (h *Handler) auditDeny(r *http.Request, action, db, reason string) {
	h.store.Audit(h.principal(r), action+".denied", db, reason)
}

// auditFail records a control-plane attempt that passed authorization but was
// rejected downstream (bad input, a path escape, an open/persist error). Suffixed
// ".failed" so it is distinct from both completed actions and ".denied" refusals.
func (h *Handler) auditFail(r *http.Request, action, db, reason string) {
	h.store.Audit(h.principal(r), action+".failed", db, reason)
}
