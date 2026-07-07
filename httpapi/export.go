package httpapi

import (
	"net/http"

	sqlite "gosqlite.org"
)

// handleExport serves GET /<db>/export: it returns the whole database as a SQLite
// serialization — the same byte image a backup would contain — for backup or
// migration from a remote client. The image is materialized in memory (via
// sqlite.Serialize) before it is written, so this is not suited to databases too
// large to hold in RAM. It requires read access; a read-capable
// principal can already read every row via SQL, so a bulk export grants nothing
// more. The client cannot influence how the database is stored: export always
// yields the logical SQLite image (a vault database is serialized decrypted,
// exactly as its read-capable principals already see it).
func (h *Handler) handleExport(w http.ResponseWriter, r *http.Request, db string) {
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

	// Bound concurrent in-RAM exports globally (each materializes the whole image),
	// on top of the per-db meter, so a fleet of exports across databases can't OOM.
	select {
	case h.exportSem <- struct{}{}:
		defer func() { <-h.exportSem }()
	case <-r.Context().Done():
		writeErr(w, http.StatusServiceUnavailable, "too many concurrent exports")
		return
	}

	dbh, release, err := h.reg.Get(r.Context(), db)
	if err != nil {
		h.writeGetError(w, db, err)
		return
	}
	defer release()

	// Refuse a database too large to hold in RAM (Serialize materializes the whole
	// image before writing). page_count*page_size is the on-disk image size.
	if h.maxExport > 0 {
		var size int64
		// Fail closed if the size can't be determined: a probe error must not fall
		// through to an unbounded Serialize (which materializes the whole image in RAM).
		if err := dbh.Handle.QueryRowContext(r.Context(),
			"SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").Scan(&size); err != nil {
			h.log.Error("export size probe", "db", db, "err", err)
			writeErr(w, http.StatusInternalServerError, "export: could not determine database size")
			return
		}
		if size > h.maxExport {
			writeErr(w, http.StatusRequestEntityTooLarge, "database too large to export")
			return
		}
	}

	data, err := sqlite.Serialize(r.Context(), dbh.Handle.DB)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "export failed")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+db+`.sqlite"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
