package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	sqlite "gosqlite.org"
)

// handleChangesetApply serves POST /<db>/changeset/apply: it applies a SQLite
// changeset — the raw request body, as produced by a session_changeset capture —
// to db on a fresh connection. It requires write access. This is the receiving
// half of changeset replication: capture on one database (or server), apply here.
//
// Two query options tune the apply (the body is the raw changeset, so options
// ride the URL): `on_conflict=abort|omit|replace` picks the conflict policy
// (default `abort` — any conflict rolls the whole apply back), and `tables=a,b`
// restricts the apply to those tables.
func (h *Handler) handleChangesetApply(w http.ResponseWriter, r *http.Request, db string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	lvl, ok := h.authorize(w, r, db)
	if !ok {
		return
	}
	if !lvl.CanWrite() {
		writeDenied(w)
		return
	}
	done, ok := h.meter(w, r, db)
	if !ok {
		return
	}
	defer done()

	boundBodyRead(w)
	cs, err := h.readBody(r)
	if err != nil {
		writeReadBodyErr(w, err)
		return
	}
	if len(cs) == 0 {
		writeErr(w, http.StatusBadRequest, "empty changeset")
		return
	}

	opts, perr := changesetApplyOptions(r)
	if perr != nil {
		writeErr(w, http.StatusBadRequest, perr.Error())
		return
	}
	if _, err := h.onConn(r, db, func(c *sqlite.Conn) (any, error) { return nil, c.ApplyChangeset(cs, opts...) }); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "apply changeset: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// changesetApplyOptions builds the gosqlite ApplyOptions from the request query:
//
//	on_conflict = abort (default) | omit | replace
//	tables      = comma-separated allowlist (apply only these tables)
//
// "abort" installs no handler, so any conflict rolls the whole apply back — the
// safe default. "omit" skips each conflicting change and applies the rest.
// "replace" overwrites the target row on a value/PK conflict (SQLite only permits
// REPLACE for those two conflict types) and omits the others.
func changesetApplyOptions(r *http.Request) ([]sqlite.ApplyOption, error) {
	var opts []sqlite.ApplyOption
	switch pol := r.URL.Query().Get("on_conflict"); pol {
	case "", "abort":
		// no handler ⇒ abort on the first conflict
	case "omit":
		opts = append(opts, sqlite.WithConflictHandler(func(sqlite.ConflictType) sqlite.ConflictAction {
			return sqlite.ChangesetOmit
		}))
	case "replace":
		opts = append(opts, sqlite.WithConflictHandler(func(t sqlite.ConflictType) sqlite.ConflictAction {
			switch t {
			case sqlite.ConflictData, sqlite.ConflictConflict:
				return sqlite.ChangesetReplace
			default:
				return sqlite.ChangesetOmit // REPLACE is illegal for these types
			}
		}))
	default:
		return nil, fmt.Errorf("on_conflict must be abort|omit|replace, got %q", pol)
	}
	if raw := r.URL.Query().Get("tables"); raw != "" {
		allow := map[string]bool{}
		for name := range strings.SplitSeq(raw, ",") {
			if name = strings.TrimSpace(name); name != "" {
				allow[name] = true
			}
		}
		opts = append(opts, sqlite.WithTableFilter(func(table string) bool { return allow[table] }))
	}
	return opts, nil
}

// handleChangesetInvert serves POST /<db>/changeset/invert: it returns the
// inverse of the changeset in the request body (undo). It is a pure transform —
// read access suffices, since it modifies nothing.
func (h *Handler) handleChangesetInvert(w http.ResponseWriter, r *http.Request, db string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
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
	boundBodyRead(w)
	cs, err := h.readBody(r)
	if err != nil {
		writeReadBodyErr(w, err) // 413 for an over-cap body, 400 otherwise
		return
	}
	if len(cs) == 0 {
		writeErr(w, http.StatusBadRequest, "empty changeset")
		return
	}
	out, err := h.onConn(r, db, func(c *sqlite.Conn) (any, error) { return c.InvertChangeset(cs) })
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "invert changeset: "+err.Error())
		return
	}
	writeBytes(w, out.([]byte))
}

// handleChangesetConcat serves POST /<db>/changeset/concat with a JSON body
// {"a":<base64>,"b":<base64>} and returns the concatenation (a then b) as raw
// bytes. Read access suffices.
func (h *Handler) handleChangesetConcat(w http.ResponseWriter, r *http.Request, db string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
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
	boundBodyRead(w)
	body, err := h.readBody(r)
	if err != nil {
		writeReadBodyErr(w, err)
		return
	}
	var req struct{ A, B string }
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	a, err1 := base64.StdEncoding.DecodeString(req.A)
	b, err2 := base64.StdEncoding.DecodeString(req.B)
	if err1 != nil || err2 != nil {
		writeErr(w, http.StatusBadRequest, "invalid base64 changeset")
		return
	}
	out, err := h.onConn(r, db, func(c *sqlite.Conn) (any, error) { return c.ConcatChangesets(a, b) })
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "concat changesets: "+err.Error())
		return
	}
	writeBytes(w, out.([]byte))
}

// onConn runs fn against the underlying *sqlite.Conn of a fresh pooled connection
// for db, releasing the registry ref afterward.
func (h *Handler) onConn(r *http.Request, db string, fn func(*sqlite.Conn) (any, error)) (any, error) {
	dbh, release, err := h.reg.Get(r.Context(), db)
	if err != nil {
		return nil, err
	}
	defer release()
	conn, err := dbh.Handle.Conn(r.Context())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var out any
	rawErr := conn.Raw(func(dc any) error {
		c, ok := dc.(*sqlite.Conn)
		if !ok {
			return fmt.Errorf("connection is not *sqlite.Conn (%T)", dc)
		}
		out, err = fn(c)
		return err
	})
	if rawErr != nil {
		return nil, rawErr
	}
	return out, nil
}

// writeBytes writes raw octet-stream bytes with a 200 status.
func writeBytes(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
