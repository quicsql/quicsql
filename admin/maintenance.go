package admin

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"gosqlite.org"
	"quicsql.net/backend"
	"quicsql.net/registry"
)

// maintenanceRequest selects a maintenance op on one database.
//
//	op: "compact"         — OFFLINE: drain + reserve the handle, densely rewrite (vault only)
//	    "compact_online"  — ONLINE:  return freed blocks to the OS on the live handle (vault only)
//	    "compact_logical" — ONLINE:  rewrite the live container to its logical footprint (vault only)
//	    "trim"            — ONLINE:  release the trailing free run (vault only)
//	    "reclaimable"     — ONLINE:  report how much a logical compaction would free (vault only)
//	    "checkpoint"      — ONLINE:  WAL checkpoint on the live handle (any WAL database)
//	    "snapshot"        — copy the (decrypted, for a vault) database image to `dest` (any backend)
//	    "snapshot_encrypted" — OFFLINE: re-sealed encrypted copy of a vault to `dest` (vault only)
//	    "members"          — OFFLINE: enumerate a recipient-mode vault's keyslot membership
//	    "rewrap"           — OFFLINE: re-wrap the data key to the configured membership (O(1))
//	    "rekey"            — OFFLINE: re-encrypt under a fresh key + configured membership (O(size))
type maintenanceRequest struct {
	Database string `json:"database"`
	Op       string `json:"op"`
	MaxBytes int64  `json:"max_bytes"` // online reclaim cap; <=0 = unbounded
	Dest     string `json:"dest"`      // snapshot destination path
	Mode     string `json:"mode"`      // checkpoint mode: passive|full|restart|truncate
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
		h.auditFail(r, req.Op, req.Database, "unknown database")
		writeErr(w, http.StatusNotFound, "unknown database")
		return
	}
	switch req.Op {
	case "compact":
		h.offlineCompact(w, r, req)
	case "compact_online", "trim":
		h.onlineReclaim(w, r, req)
	case "compact_logical", "reclaimable":
		h.logicalReclaim(w, r, req)
	case "checkpoint":
		h.checkpoint(w, r, req)
	case "snapshot":
		h.snapshot(w, r, req)
	case "snapshot_encrypted":
		h.snapshotEncrypted(w, r, req)
	case "members", "rewrap", "rekey":
		h.vaultKeyMgmt(w, r, req)
	default:
		h.auditFail(r, req.Op, req.Database, "unknown maintenance op")
		writeErr(w, http.StatusBadRequest, "unknown maintenance op")
	}
}

// reserve drains and reserves the idle handle for an OFFLINE op, mapping the
// registry result to a response (ErrBusy→409, anything else→500) and auditing the
// failure. On success it returns the release func (defer it) and ok=true; on
// failure it has already written the response, so the caller returns immediately.
func (h *Handler) reserve(w http.ResponseWriter, r *http.Request, op, db string) (release func(), ok bool) {
	release, err := h.reg.Reserve(db)
	if err != nil {
		if errors.Is(err, registry.ErrBusy) {
			h.auditFail(r, op, db, "database busy")
			writeErr(w, http.StatusConflict, "database busy (has active users); retry when idle")
			return nil, false
		}
		h.auditFail(r, op, db, "reserve failed")
		writeErr(w, http.StatusInternalServerError, "cannot reserve database")
		return nil, false
	}
	return release, true
}

// pin opens (or reuses) the LIVE handle and holds a ref so the container stays
// open for the duration of the op, mapping a Get failure via writeGetErr and
// auditing it. On success it returns the handle + release func (defer it) +
// ok=true; on failure it has already written the response, so the caller returns.
func (h *Handler) pin(w http.ResponseWriter, r *http.Request, op, db string) (dbh *registry.DB, release func(), ok bool) {
	dbh, release, err := h.reg.Get(r.Context(), db)
	if err != nil {
		h.auditFail(r, op, db, "open failed")
		h.writeGetErr(w, db, err)
		return nil, nil, false
	}
	return dbh, release, true
}

// logicalReclaim runs the O(live-data) reclaim against the LIVE handle, or (for
// "reclaimable") just reports how much it would free — both read/write the open
// container, so a registry ref is pinned to keep it open.
func (h *Handler) logicalReclaim(w http.ResponseWriter, r *http.Request, req maintenanceRequest) {
	be := h.reg.Backend(req.Database)
	reclaimer, ok := be.(backend.LogicalReclaimer)
	if !ok {
		h.auditFail(r, req.Op, req.Database, "backend does not support logical reclaim")
		writeErr(w, http.StatusBadRequest, "logical reclaim is only supported for vault databases")
		return
	}
	_, releaseRef, ok := h.pin(w, r, req.Op, req.Database)
	if !ok {
		return
	}
	defer releaseRef()

	if req.Op == "reclaimable" {
		n, err := reclaimer.ReclaimableBytes()
		if err != nil {
			h.log.Error("admin: reclaimable probe", "db", req.Database, "err", err)
			h.auditFail(r, req.Op, req.Database, "probe failed")
			writeErr(w, http.StatusInternalServerError, "reclaimable probe failed")
			return
		}
		// A read-only probe is not audited as a mutation.
		writeJSON(w, http.StatusOK, map[string]any{"database": req.Database, "reclaimable_bytes": n})
		return
	}
	n, err := reclaimer.CompactLogicalOnline()
	if err != nil {
		h.log.Error("admin: logical compact", "db", req.Database, "err", err)
		h.auditFail(r, req.Op, req.Database, "reclaim failed")
		writeErr(w, http.StatusInternalServerError, "logical reclaim failed")
		return
	}
	h.audit(r, req.Op, req.Database, "online")
	writeJSON(w, http.StatusOK, map[string]any{"status": "reclaimed", "database": req.Database, "bytes_reclaimed": n})
}

// checkpointModes maps the request vocabulary to sqlite checkpoint modes.
var checkpointModes = map[string]sqlite.CheckpointMode{
	"":         sqlite.CheckpointPassive, // default: never blocks
	"passive":  sqlite.CheckpointPassive,
	"full":     sqlite.CheckpointFull,
	"restart":  sqlite.CheckpointRestart,
	"truncate": sqlite.CheckpointTruncate,
}

// checkpoint runs a WAL checkpoint on the live handle, bounding WAL growth
// without a restart. Any WAL-mode database qualifies; a non-WAL database returns
// the engine's error. Modes: passive (default, never blocks), full, restart,
// truncate (zeroes the WAL file).
func (h *Handler) checkpoint(w http.ResponseWriter, r *http.Request, req maintenanceRequest) {
	mode, ok := checkpointModes[req.Mode]
	if !ok {
		h.auditFail(r, "checkpoint", req.Database, "bad mode: "+req.Mode)
		writeErr(w, http.StatusBadRequest, "checkpoint mode must be passive|full|restart|truncate")
		return
	}
	dbh, releaseRef, ok := h.pin(w, r, "checkpoint", req.Database)
	if !ok {
		return
	}
	defer releaseRef()
	conn, err := dbh.Handle.Conn(r.Context())
	if err != nil {
		h.auditFail(r, "checkpoint", req.Database, "conn failed")
		writeErr(w, http.StatusInternalServerError, "cannot acquire a connection")
		return
	}
	defer conn.Close()

	var logFrames, checkpointed int
	rawErr := conn.Raw(func(dc any) error {
		c, ok := dc.(*sqlite.Conn)
		if !ok {
			return fmt.Errorf("connection is not *sqlite.Conn (%T)", dc)
		}
		logFrames, checkpointed, err = c.WALCheckpoint("", mode)
		return err
	})
	if rawErr != nil {
		h.log.Error("admin: checkpoint", "db", req.Database, "err", rawErr)
		h.auditFail(r, "checkpoint", req.Database, "checkpoint failed")
		writeErr(w, http.StatusInternalServerError, "checkpoint failed (is the database in WAL mode?)")
		return
	}
	modeName := req.Mode
	if modeName == "" {
		modeName = "passive"
	}
	h.audit(r, "checkpoint", req.Database, modeName)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "checkpointed", "database": req.Database,
		"mode": modeName, "wal_frames": logFrames, "checkpointed_frames": checkpointed,
	})
}

// offlineCompact reserves the path (draining the idle handle; ErrBusy if it has
// active users) and rewrites the container densely. The reservation blocks new
// opens for the op's duration; the handle re-opens lazily afterward.
func (h *Handler) offlineCompact(w http.ResponseWriter, r *http.Request, req maintenanceRequest) {
	be := h.reg.Backend(req.Database)
	compacter, ok := be.(backend.OfflineCompacter)
	if !ok {
		h.auditFail(r, "compact", req.Database, "backend does not support offline compact")
		writeErr(w, http.StatusBadRequest, "offline compact is only supported for vault databases")
		return
	}
	release, ok := h.reserve(w, r, "compact", req.Database)
	if !ok {
		return
	}
	defer release()
	if err := compacter.CompactOffline(); err != nil {
		h.log.Error("admin: offline compact", "db", req.Database, "err", err)
		h.auditFail(r, "compact", req.Database, "compact failed")
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
		h.auditFail(r, req.Op, req.Database, "backend does not support online reclaim")
		writeErr(w, http.StatusBadRequest, "online reclaim is only supported for vault databases")
		return
	}
	_, releaseRef, ok := h.pin(w, r, req.Op, req.Database) // keep the container open
	if !ok {
		return
	}
	defer releaseRef()

	var reclaimed int64
	var err error
	if req.Op == "trim" {
		reclaimed, err = reclaimer.Trim(req.MaxBytes)
	} else {
		reclaimed, err = reclaimer.CompactOnline(req.MaxBytes)
	}
	if err != nil {
		h.log.Error("admin: online reclaim", "db", req.Database, "op", req.Op, "err", err)
		h.auditFail(r, req.Op, req.Database, "reclaim failed")
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
		h.auditFail(r, "snapshot", req.Database, "dest escapes data_dir: "+req.Dest)
		writeErr(w, http.StatusBadRequest, "snapshot dest must be a path within data_dir")
		return
	}
	dbh, releaseRef, ok := h.pin(w, r, "snapshot", req.Database)
	if !ok {
		return
	}
	defer releaseRef()
	data, err := sqlite.Serialize(r.Context(), dbh.Handle.DB)
	if err != nil {
		h.log.Error("admin: serialize snapshot", "db", req.Database, "err", err)
		h.auditFail(r, "snapshot", req.Database, "serialize failed")
		writeErr(w, http.StatusInternalServerError, "snapshot failed")
		return
	}
	// O_EXCL: refuse to overwrite or follow a symlink onto an existing file.
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		h.auditFail(r, "snapshot", req.Database, "dest exists or cannot be created: "+dest)
		writeErr(w, http.StatusConflict, "snapshot dest already exists or cannot be created")
		return
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		h.log.Error("admin: write snapshot", "db", req.Database, "err", err)
		h.auditFail(r, "snapshot", req.Database, "write failed")
		writeErr(w, http.StatusInternalServerError, "snapshot write failed")
		return
	}
	if err := f.Close(); err != nil {
		h.log.Error("admin: close snapshot", "db", req.Database, "err", err)
		h.auditFail(r, "snapshot", req.Database, "write failed")
		writeErr(w, http.StatusInternalServerError, "snapshot write failed")
		return
	}
	h.audit(r, "snapshot", req.Database, dest)
	writeJSON(w, http.StatusOK, map[string]any{"status": "snapshot", "database": req.Database, "dest": dest, "bytes": len(data)})
}

// snapshotEncrypted writes a re-sealed, standalone backup of a vault container to
// req.Dest — the ENCRYPTED analogue of "snapshot". Where "snapshot" Serializes the
// decrypted logical image (plaintext on disk), this keeps an encrypted vault
// encrypted, so a backup never exposes plaintext. Vault backends only.
//
// The database is RESERVED first (its idle handle drained + closed, WAL
// checkpointed): vault.Snapshot reads the container file directly and requires it
// not be open, and the reservation also gives a consistent point-in-time read.
// dest is constrained to within data_dir and must not already exist.
func (h *Handler) snapshotEncrypted(w http.ResponseWriter, r *http.Request, req maintenanceRequest) {
	dest, ok := h.contained(req.Dest)
	if !ok {
		h.auditFail(r, "snapshot_encrypted", req.Database, "dest escapes data_dir: "+req.Dest)
		writeErr(w, http.StatusBadRequest, "snapshot dest must be a path within data_dir")
		return
	}
	snap, ok := h.reg.Backend(req.Database).(backend.EncryptedSnapshotter)
	if !ok {
		h.auditFail(r, "snapshot_encrypted", req.Database, "backend is not a vault")
		writeErr(w, http.StatusBadRequest, "encrypted snapshot is only supported for vault databases")
		return
	}
	// Claim dest atomically with O_EXCL (as snapshot does) rather than a TOCTOU
	// os.Stat: refuse to overwrite or follow a symlink onto an existing file, with
	// no window between the check and the write. vault.Snapshot renames its temp
	// sibling over this empty placeholder, so the claim only reserves the name; the
	// deferred cleanup removes it again unless the snapshot commits.
	cf, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		h.auditFail(r, "snapshot_encrypted", req.Database, "dest exists or cannot be created: "+dest)
		writeErr(w, http.StatusConflict, "snapshot dest already exists or cannot be created")
		return
	}
	_ = cf.Close()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(dest) // reserved placeholder or partial artifact — don't leave it behind
		}
	}()
	// vault.Snapshot needs the container closed; reserve to drain the handle.
	release, ok := h.reserve(w, r, "snapshot_encrypted", req.Database)
	if !ok {
		return
	}
	defer release()
	if err := snap.SnapshotEncrypted(dest); err != nil {
		h.log.Error("admin: encrypted snapshot", "db", req.Database, "err", err)
		h.auditFail(r, "snapshot_encrypted", req.Database, "snapshot failed: "+err.Error())
		writeErr(w, http.StatusInternalServerError, "encrypted snapshot failed (a recipient-mode vault cannot be re-sealed in-band)")
		return
	}
	committed = true
	var size int64
	if info, statErr := os.Stat(dest); statErr == nil {
		size = info.Size()
	}
	h.audit(r, "snapshot_encrypted", req.Database, dest)
	writeJSON(w, http.StatusOK, map[string]any{"status": "snapshot_encrypted", "database": req.Database, "dest": dest, "bytes": size})
}

// vaultKeyMgmt runs a vault keyslot lifecycle op (members / rewrap / rekey). All
// three require the container CLOSED, so the database is reserved (409 if it has
// active users) and its handle reopens lazily afterward. The target membership for
// rewrap/rekey is the vault's configured create: block — edit it in YAML, then
// reconcile the on-disk container with rewrap (cheap) or rekey (rewrites data,
// true revocation). rewrap/rekey seal the new keyslot before committing, so an
// unauthorized caller fails cleanly without touching the data.
func (h *Handler) vaultKeyMgmt(w http.ResponseWriter, r *http.Request, req maintenanceRequest) {
	// The membership-changing ops re-seal (rewrap) or re-encrypt every page (rekey)
	// — too heavy to reach via a per-database `*: admin` wildcard (which the
	// anonymous principal matches). Require a server-admin; read-only `members`
	// stays gated by the ordinary per-database admin check above.
	if (req.Op == "rewrap" || req.Op == "rekey") && !h.isServerAdmin(r) {
		h.auditDeny(r, req.Op, req.Database, "not server-admin")
		writeErr(w, http.StatusForbidden, "rewrap/rekey require server-admin capability")
		return
	}
	km, ok := h.reg.Backend(req.Database).(backend.VaultKeyManager)
	if !ok {
		h.auditFail(r, req.Op, req.Database, "backend is not a recipient-mode vault")
		writeErr(w, http.StatusBadRequest, "vault key management is only supported for recipient-mode vaults")
		return
	}
	release, ok := h.reserve(w, r, req.Op, req.Database)
	if !ok {
		return
	}
	defer release()

	switch req.Op {
	case "members":
		members, err := km.VaultMembers()
		if err != nil {
			h.auditFail(r, "members", req.Database, "enumerate failed: "+err.Error())
			writeErr(w, http.StatusBadRequest, "cannot enumerate vault membership: "+err.Error())
			return
		}
		// A read-only enumeration is not audited as a mutation.
		writeJSON(w, http.StatusOK, map[string]any{"database": req.Database, "members": members})
	case "rewrap":
		if err := km.Rewrap(); err != nil {
			h.log.Error("admin: vault rewrap", "db", req.Database, "err", err)
			h.auditFail(r, "rewrap", req.Database, "rewrap failed: "+err.Error())
			writeErr(w, http.StatusBadRequest, "rewrap failed: "+err.Error())
			return
		}
		h.audit(r, "rewrap", req.Database, "membership re-wrapped")
		writeJSON(w, http.StatusOK, map[string]any{"status": "rewrapped", "database": req.Database})
	case "rekey":
		if err := km.Rekey(); err != nil {
			h.log.Error("admin: vault rekey", "db", req.Database, "err", err)
			h.auditFail(r, "rekey", req.Database, "rekey failed: "+err.Error())
			writeErr(w, http.StatusBadRequest, "rekey failed: "+err.Error())
			return
		}
		h.audit(r, "rekey", req.Database, "re-encrypted under a fresh key")
		writeJSON(w, http.StatusOK, map[string]any{"status": "rekeyed", "database": req.Database})
	}
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
		h.log.Error("admin: open database", "db", db, "err", err)
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
