package httpapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	sqlite "gosqlite.org"
)

// handleBackup serves GET /<db>/backup: a streaming online backup of the whole
// database as a standalone SQLite file. Unlike /export (which materializes the
// whole image in RAM via Serialize), this uses the SQLite online-backup API to
// page-copy the LIVE database into a temp file with bounded memory, then streams
// that file — so it has no RAM ceiling and doesn't block writers (the backup API
// restarts any page the source rewrites mid-copy). It needs read access; a
// read-capable principal can already read every row, so a backup grants nothing
// more. Like /export, a vault database backs up to its decrypted logical image.
func (h *Handler) handleBackup(w http.ResponseWriter, r *http.Request, db string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	if _, ok := h.authorize(w, r, db); !ok {
		return
	}
	done, ok := h.meter(w, r, db)
	if !ok {
		return
	}
	defer done()

	// Bound concurrent backups (each opens a temp DB and copies) with the same
	// global semaphore as export, so a fleet of them can't exhaust fds/disk churn.
	select {
	case h.exportSem <- struct{}{}:
		defer func() { <-h.exportSem }()
	case <-r.Context().Done():
		writeErr(w, http.StatusServiceUnavailable, "too many concurrent backups")
		return
	}

	src, release, err := h.reg.Get(r.Context(), db)
	if err != nil {
		h.writeGetError(w, db, err)
		return
	}
	defer release()

	tmp, err := os.CreateTemp("", "backup-*.sqlite")
	if err != nil {
		h.log.Error("backup temp file", "db", db, "err", err)
		writeErr(w, http.StatusInternalServerError, "backup: cannot create temp file")
		return
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	if err := backupTo(r.Context(), src.Handle, tmpPath); err != nil {
		h.log.Error("backup", "db", db, "err", err)
		writeErr(w, http.StatusInternalServerError, "backup failed")
		return
	}

	f, err := os.Open(tmpPath)
	if err != nil {
		h.log.Error("backup read", "db", db, "err", err)
		writeErr(w, http.StatusInternalServerError, "backup: cannot read image")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+db+`.sqlite"`)
	if fi, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// backupTo online-copies src into a fresh SQLite database at destPath using the
// backup API on raw connections (bounded memory, page-batched, cancelable).
func backupTo(ctx context.Context, src *sqlite.DB, destPath string) error {
	dest, err := sqlite.Open(sqlite.Config{Path: destPath})
	if err != nil {
		return fmt.Errorf("open dest: %w", err)
	}
	defer dest.Close()
	srcConn, err := src.Conn(ctx)
	if err != nil {
		return err
	}
	defer srcConn.Close()
	destConn, err := dest.Conn(ctx)
	if err != nil {
		return err
	}
	defer destConn.Close()

	// Nested Raw: both raw *sqlite.Conn must be live for the backup handle.
	return srcConn.Raw(func(sdc any) error {
		sc, ok := sdc.(*sqlite.Conn)
		if !ok {
			return fmt.Errorf("source connection is not *sqlite.Conn (%T)", sdc)
		}
		return destConn.Raw(func(ddc any) error {
			dc, ok := ddc.(*sqlite.Conn)
			if !ok {
				return fmt.Errorf("dest connection is not *sqlite.Conn (%T)", ddc)
			}
			bk, err := dc.Backup("main", sc, "main")
			if err != nil {
				return err
			}
			for {
				if err := ctx.Err(); err != nil {
					_ = bk.Finish()
					return err
				}
				more, err := bk.Step(1000) // copy up to 1000 pages per step
				if err != nil {
					_ = bk.Finish()
					return err
				}
				if !more {
					return bk.Finish() // finalize on success; surface a finalize error
				}
			}
		})
	})
}
