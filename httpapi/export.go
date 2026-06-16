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

	dbh, release, err := h.reg.Get(r.Context(), db)
	if err != nil {
		h.writeGetError(w, db, err)
		return
	}
	defer release()

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
