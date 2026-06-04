package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"gosqlite.org/server/engine"
	"gosqlite.org/server/registry"
)

// queryRequest is the native-JSON request body: either a single `sql` (+ `args`)
// or a `statements` batch, never both.
type queryRequest struct {
	SQL        string            `json:"sql"`
	Args       []json.RawMessage `json:"args"`
	Statements []statementJSON   `json:"statements"`
}

type statementJSON struct {
	SQL  string            `json:"sql"`
	Args []json.RawMessage `json:"args"`
}

type apiError struct {
	Message      string `json:"message"`
	Code         int    `json:"code,omitempty"`
	ExtendedCode int    `json:"extended_code,omitempty"`
}

// errorEnvelope is the single JSON error shape for every error response.
type errorEnvelope struct {
	Error       apiError `json:"error"`
	FailedIndex *int     `json:"failed_index,omitempty"`
}

// resultJSON is one statement's result. Integers are emitted as JSON numbers
// (exact on the wire; a JS client that parses with JSON.parse loses precision
// above 2^53 — send/read such columns as text if that matters). Blobs are
// boxed as {"base64": "..."} so they are unambiguous vs. text.
type resultJSON struct {
	Columns      []string `json:"columns"`
	Rows         [][]any  `json:"rows"`
	RowsAffected int64    `json:"rows_affected"`
	LastInsertID int64    `json:"last_insert_id"`
	Truncated    bool     `json:"truncated,omitempty"`
}

func (h *Handler) handleQuery(w http.ResponseWriter, r *http.Request, db string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	ctx, cancel := h.withTimeout(r.Context())
	defer cancel()
	body, err := h.readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req queryRequest
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if dec.More() {
		writeErr(w, http.StatusBadRequest, "unexpected trailing content after JSON body")
		return
	}
	switch {
	case req.SQL == "" && len(req.Statements) == 0:
		writeErr(w, http.StatusBadRequest, "request must set 'sql' or 'statements'")
		return
	case req.SQL != "" && len(req.Statements) > 0:
		writeErr(w, http.StatusBadRequest, "set either 'sql' or 'statements', not both")
		return
	}

	dbh, release, err := h.reg.Get(ctx, db)
	if err != nil {
		h.writeGetError(w, db, err)
		return
	}
	defer release()

	if len(req.Statements) > 0 {
		h.runBatch(ctx, w, dbh, req.Statements)
		return
	}

	args, err := decodeArgs(req.Args)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := h.eng.Run(ctx, dbh.Handle, engine.Statement{SQL: req.SQL, Args: args})
	if err != nil {
		h.writeRunError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toResultJSON(res))
}

// runBatch executes the statements in one explicit transaction (reads return
// rows, writes return affected); all-or-nothing. A SQL error rolls the whole
// batch back and returns an error envelope carrying the failing index.
func (h *Handler) runBatch(ctx context.Context, w http.ResponseWriter, dbh *registry.DB, stmts []statementJSON) {
	es := make([]engine.Statement, len(stmts))
	for i, s := range stmts {
		if s.SQL == "" {
			writeErr(w, http.StatusBadRequest, "batch statement missing 'sql'")
			return
		}
		args, err := decodeArgs(s.Args)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		es[i] = engine.Statement{SQL: s.SQL, Args: args}
	}
	results, err := h.eng.Batch(ctx, dbh.Handle.DB, es)
	if err != nil {
		switch {
		case errors.Is(err, engine.ErrDenied):
			writeErr(w, http.StatusForbidden, err.Error())
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			writeErr(w, http.StatusGatewayTimeout, "statement timed out")
		default:
			env := errorEnvelope{Error: toAPIError(err)}
			var be *engine.BatchError
			if errors.As(err, &be) {
				env.FailedIndex = &be.Index
			}
			writeJSON(w, http.StatusOK, env)
		}
		return
	}
	out := make([]resultJSON, len(results))
	for i, res := range results {
		out[i] = toResultJSON(res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

func toResultJSON(r *engine.Result) resultJSON {
	cols := make([]string, len(r.Columns))
	for i, c := range r.Columns {
		cols[i] = c.Name
	}
	rows := make([][]any, len(r.Rows))
	for i, row := range r.Rows {
		cells := make([]any, len(row))
		for j, v := range row {
			cells[j] = encodeValue(v)
		}
		rows[i] = cells
	}
	// rows is non-nil (make), so it marshals as [] not null even when empty.
	return resultJSON{
		Columns:      cols,
		Rows:         rows,
		RowsAffected: r.RowsAffected,
		LastInsertID: r.LastInsertID,
		Truncated:    r.Truncated,
	}
}

// toAPIError surfaces SQLite error detail (message + codes are safe — they echo
// the client's own SQL) but reduces any other error to a generic message so a
// filesystem path or driver internal never leaks to the client.
func toAPIError(err error) apiError {
	var e *engine.Error
	if errors.As(err, &e) {
		return apiError{Message: e.Msg, Code: e.Code, ExtendedCode: e.Extended}
	}
	return apiError{Message: "internal error"}
}
