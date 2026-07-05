package admin

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	sqlite "gosqlite.org"
	"quicsql.net/backend"
)

// sqliteMagic is the 16-byte header every SQLite database file begins with.
const sqliteMagic = "SQLite format 3\x00"

// defaultMaxRestoreBytes bounds an uploaded restore image when no explicit
// limits.max_restore_bytes is set. It is streamed to disk, so this guards disk
// (not RAM); raise the limit (or set it <0 for no cap) to restore a larger image
// in place, or move the file into place out of band.
const defaultMaxRestoreBytes = 4 << 30

// handleRestore replaces a file database's contents with an uploaded SQLite image
// — the inverse of /export and /backup. `POST /_admin/restore?database=X` with
// the image as the raw request body.
//
// Server-admin only (it discards the current contents), and file backends only
// for now: a vault stores its data encrypted, so restoring into one needs an
// import path, not a file swap. The swap is made safe by validating the image
// (magic header + it opens + `PRAGMA integrity_check`) BEFORE anything is
// touched; then the database is reserved (refused with 409 if it has active
// users), which closes the idle handle and checkpoints its WAL; the stale
// -wal/-shm sidecars are removed and the validated image is moved into place with
// an atomic rename; the handle reopens lazily on the next request. Back the
// database up first (`GET /<db>/backup`) — the previous contents are discarded.
func (h *Handler) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	db := r.URL.Query().Get("database")
	if db == "" {
		writeErr(w, http.StatusBadRequest, "restore requires a ?database= query parameter")
		return
	}
	if !h.isServerAdmin(r) {
		h.auditDeny(r, "restore", db, "not server-admin")
		writeErr(w, http.StatusForbidden, "server-admin capability required")
		return
	}
	be := h.reg.Backend(db)
	if be == nil {
		h.auditFail(r, "restore", db, "unknown database")
		writeErr(w, http.StatusNotFound, "unknown database")
		return
	}
	pather, ok := be.(backend.Pather)
	if !ok || be.Kind() != "file" {
		h.auditFail(r, "restore", db, "backend not restorable: "+be.Kind())
		writeErr(w, http.StatusBadRequest, "restore is only supported for file databases")
		return
	}
	target := pather.Path()

	// Stream the upload to a temp file IN THE TARGET'S DIRECTORY (same filesystem,
	// so the later rename is atomic), bounded, then validate before touching the
	// live database.
	tmp, err := os.CreateTemp(filepath.Dir(target), ".restore-*.tmp")
	if err != nil {
		h.log.Error("quicsql/admin: restore temp", "db", db, "err", err)
		writeErr(w, http.StatusInternalServerError, "restore: cannot create temp file")
		return
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
			removeSidecars(tmpPath)
		}
	}()

	limit := h.maxRestore
	if limit == 0 {
		limit = defaultMaxRestoreBytes
	}
	src := r.Body
	if limit > 0 {
		src = io.NopCloser(io.LimitReader(r.Body, limit+1)) // +1 so an at-limit read still trips the check
	}
	n, err := io.Copy(tmp, src)
	_ = tmp.Close()
	if err != nil {
		h.auditFail(r, "restore", db, "upload failed")
		writeErr(w, http.StatusBadRequest, "restore: upload failed")
		return
	}
	if limit > 0 && n > limit {
		h.auditFail(r, "restore", db, "image too large")
		writeErr(w, http.StatusRequestEntityTooLarge, "restore image exceeds the size cap")
		return
	}
	if err := validateSQLiteImage(tmpPath); err != nil {
		h.auditFail(r, "restore", db, "invalid image: "+err.Error())
		writeErr(w, http.StatusBadRequest, "restore: uploaded file is not a valid SQLite database")
		return
	}
	// Validation may have created its own -wal/-shm beside the temp; drop them so
	// only the bare image file is renamed into place.
	removeSidecars(tmpPath)

	// Reserve: close the idle handle (checkpointing its WAL) and block new opens.
	release, ok := h.reserve(w, r, "restore", db)
	if !ok {
		return
	}
	defer release()

	// The handle is closed and its WAL checkpointed, so the target's sidecars are
	// stale — remove them before the swap so the reopened handle can't read a WAL
	// belonging to the old database.
	removeSidecars(target)
	if err := os.Rename(tmpPath, target); err != nil {
		h.log.Error("quicsql/admin: restore rename", "db", db, "err", err)
		h.auditFail(r, "restore", db, "swap failed")
		writeErr(w, http.StatusInternalServerError, "restore: could not replace the database file")
		return
	}
	cleanup = false // renamed into place; nothing to clean
	h.audit(r, "restore", db, "bytes="+strconv.FormatInt(n, 10))
	writeJSON(w, http.StatusOK, map[string]any{"status": "restored", "database": db, "bytes": n})
}

func removeSidecars(path string) {
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
}

// validateSQLiteImage checks that path is a SQLite database that opens and passes
// a quick integrity check, so a corrupt or non-SQLite upload is rejected BEFORE
// it can replace the live file.
func validateSQLiteImage(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	hdr := make([]byte, 16)
	_, rerr := io.ReadFull(f, hdr)
	_ = f.Close()
	if rerr != nil || string(hdr) != sqliteMagic {
		return errors.New("not a SQLite database file")
	}
	db, err := sqlite.Open(sqlite.Config{Path: path, Mode: sqlite.ModeReadOnly})
	if err != nil {
		return err
	}
	defer db.Close()
	var res string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return errors.New("integrity check: " + res)
	}
	return nil
}
