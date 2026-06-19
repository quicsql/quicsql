package httpapi

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"gosqlite.org"
	"quicsql.net/authz"
	"quicsql.net/engine"
	"quicsql.net/session"
)

// handlePipeline serves Hrana's POST /v2|v3/pipeline: it resolves the stream's
// session (creating one on a null baton, resuming on a signed baton), runs each
// stream request on the session's pinned connection, and returns the rotated
// baton so the client can continue the stream.
func (h *Handler) handlePipeline(w http.ResponseWriter, r *http.Request, dbName string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if h.sessions == nil {
		writeErr(w, http.StatusNotImplemented, "sessions not enabled")
		return
	}
	level, ok := h.authorize(w, r, dbName)
	if !ok {
		return
	}
	done, ok := h.meter(w, r, dbName)
	if !ok {
		return
	}
	defer done()
	ctx := r.Context() // per-statement timeouts are applied in execStmt / sequence
	boundBodyRead(w)
	body, err := h.readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return
	}
	var req pipelineReq
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	sess, err := h.stream(ctx, dbName, req.Baton, level)
	if err != nil {
		h.writeStreamError(w, dbName, err)
		return
	}

	closed := false
	results := make([]streamResult, 0, len(req.Requests))
	for _, sr := range req.Requests {
		if closed {
			results = append(results, streamResult{Type: "error", Error: &hError{Message: "stream is closed"}})
			continue
		}
		res, closeStream := h.runStreamRequest(ctx, sess, sr)
		results = append(results, res)
		closed = closed || closeStream
	}

	var baton *string
	if closed {
		h.sessions.Close(sess)
	} else {
		b := h.sessions.Baton(sess)
		baton = &b
	}
	writeJSON(w, http.StatusOK, pipelineResp{Baton: baton, Results: results})
}

// writeStreamError maps a stream-resolution failure (stream) to its status.
// The pipeline and cursor endpoints share it so the two report identically.
func (h *Handler) writeStreamError(w http.ResponseWriter, dbName string, err error) {
	switch {
	case errors.Is(err, session.ErrBadBaton):
		writeErr(w, http.StatusBadRequest, "invalid or expired baton")
	case errors.Is(err, session.ErrPrincipalMismatch):
		writeErr(w, http.StatusForbidden, "baton belongs to a different principal")
	case errors.Is(err, session.ErrTooMany):
		writeErr(w, http.StatusServiceUnavailable, "too many open sessions")
	default:
		h.writeGetError(w, dbName, err)
	}
}

// stream resolves the session for a pipeline request: resume an existing one
// (validating the baton, the bound database, and the resuming principal), or
// open a new one bound to the caller's principal and capability.
func (h *Handler) stream(ctx context.Context, dbName string, baton *string, level authz.Level) (*session.Session, error) {
	principal := authz.FromContext(ctx)
	if baton != nil && *baton != "" {
		// Resume checks the database + principal binding before consuming the
		// baton, so a wrong-principal request can't invalidate the owner's baton.
		return h.sessions.Resume(*baton, dbName, principal.Name)
	}
	dbh, release, err := h.reg.Get(ctx, dbName)
	if err != nil {
		return nil, err
	}
	// The session owns the registry ref for the stream's life (Open drops it,
	// after the pinned conn, on Close/reap). A principal that cannot write gets a
	// read-only pinned connection.
	s, err := h.sessions.Open(ctx, dbh, release, principal.Name, !level.CanWrite())
	if err != nil {
		release()
		return nil, err
	}
	return s, nil
}

func (h *Handler) runStreamRequest(ctx context.Context, sess *session.Session, sr streamRequest) (streamResult, bool) {
	switch sr.Type {
	case "execute":
		if sr.Stmt == nil {
			return errStream("execute requires a stmt"), false
		}
		res, err := h.execStmt(ctx, sess, *sr.Stmt)
		if err != nil {
			return streamResult{Type: "error", Error: hErrorFrom(err)}, false
		}
		return okStream(executeResp{Type: "execute", Result: res}), false

	case "batch":
		if sr.Batch == nil {
			return errStream("batch requires a batch"), false
		}
		return okStream(batchResp{Type: "batch", Result: h.execBatch(ctx, sess, *sr.Batch)}), false

	case "sequence":
		sqlText, err := resolveSQL(sess, sr.SQL, sr.SQLID)
		if err != nil {
			return errStream(err.Error()), false
		}
		sctx, cancel := h.withTimeout(ctx)
		defer cancel()
		if _, err := sess.Conn().ExecContext(sctx, sqlText); err != nil {
			return streamResult{Type: "error", Error: hErrorFrom(err)}, false
		}
		return okStream(simpleResp{Type: "sequence"}), false

	case "describe":
		sqlText, err := resolveSQL(sess, sr.SQL, sr.SQLID)
		if err != nil {
			return errStream(err.Error()), false
		}
		res, err := describeStmt(sess, sqlText)
		if err != nil {
			return streamResult{Type: "error", Error: hErrorFrom(err)}, false
		}
		return okStream(describeResp{Type: "describe", Result: res}), false

	case "store_sql":
		if sr.SQLID == nil || sr.SQL == nil {
			return errStream("store_sql requires sql_id and sql"), false
		}
		if _, ok := sess.LookupSQL(*sr.SQLID); ok {
			return errStream("sql_id already in use"), false
		}
		sess.StoreSQL(*sr.SQLID, *sr.SQL)
		return okStream(simpleResp{Type: "store_sql"}), false

	case "close_sql":
		if sr.SQLID != nil {
			sess.DropSQL(*sr.SQLID)
		}
		return okStream(simpleResp{Type: "close_sql"}), false

	case "get_autocommit":
		return okStream(getAutocommitResp{Type: "get_autocommit", IsAutocommit: autocommit(sess.Conn())}), false

	case "session_start":
		if err := h.startCapture(sess, sr.Tables); err != nil {
			return streamResult{Type: "error", Error: hErrorFrom(err)}, false
		}
		return okStream(simpleResp{Type: "session_start"}), false

	case "session_changeset":
		cs, err := captureChangeset(sess)
		if err != nil {
			return streamResult{Type: "error", Error: hErrorFrom(err)}, false
		}
		return okStream(changesetResp{Type: "session_changeset", Changeset: base64.StdEncoding.EncodeToString(cs)}), false

	case "close":
		return okStream(simpleResp{Type: "close"}), true

	default:
		return errStream("unknown request type: " + sr.Type), false
	}
}

// startCapture attaches a SQLite SESSION to the stream's pinned connection so
// subsequent writes on the stream are recorded into a changeset. Empty tables
// tracks all tables. It is a quicSQL extension to the Hrana pipeline; the SESSION
// lives on the pinned connection until session_changeset fetches it or the stream
// closes (the session store closes an unfetched capture).
func (h *Handler) startCapture(sess *session.Session, tables []string) error {
	if sess.Capture() != nil {
		return &protocolError{"a capture session is already open on this stream"}
	}
	return sess.Conn().Raw(func(dc any) error {
		c, ok := dc.(*sqlite.Conn)
		if !ok {
			return &protocolError{fmt.Sprintf("connection is not *sqlite.Conn (%T)", dc)}
		}
		cap, err := c.CreateSession("main")
		if err != nil {
			return err
		}
		if len(tables) == 0 {
			if err := cap.Attach(""); err != nil { // "" attaches all tables
				_ = cap.Close()
				return err
			}
		}
		for _, t := range tables {
			if err := cap.Attach(t); err != nil {
				_ = cap.Close()
				return err
			}
		}
		sess.SetCapture(cap)
		return nil
	})
}

// captureChangeset serializes and closes the stream's capture session (single-
// shot: the SESSION is consumed once its changeset is read).
func captureChangeset(sess *session.Session) ([]byte, error) {
	cap := sess.TakeCapture() // take ownership so teardown can't also close it
	if cap == nil {
		return nil, &protocolError{"no capture session open (send session_start first)"}
	}
	cs, err := cap.Changeset()
	_ = cap.Close()
	return cs, err
}

// stmtDescriber is the introspection surface of gosqlite's prepared statement.
// The driver's stmt type is unexported, so its exported methods are reached
// through this assertion on the driver.Stmt that Conn.Prepare returns.
type stmtDescriber interface {
	ColumnCount() int
	ColumnName(i int) string
	ColumnDeclType(i int) string
	BindCount() int
	BindName(i int) string
	Readonly() bool
}

// describeStmt implements Hrana's describe: it PREPARES sqlText on the
// stream's pinned connection — never stepping it, so describing a write
// changes nothing — and reports the statement's real shape: one params entry
// per bound parameter (name null for anonymous `?`, prefixed `:AAA`/`@AAA`/
// `$AAA`/`?NNN` otherwise, per the spec), the result columns with declared
// types where a column resolves to one, and sqlite3_stmt_readonly's exact
// classification. A prepare failure (bad SQL, or the read-only authorizer
// denying a write at compile time) is returned for the caller to surface as an
// in-stream Hrana error, not a transport error.
func describeStmt(sess *session.Session, sqlText string) (*hDescribeResult, error) {
	out := &hDescribeResult{Params: []hDescribeParam{}, Cols: []hCol{}, IsExplain: engine.IsExplain(sqlText)}
	err := sess.Conn().Raw(func(dc any) error {
		c, ok := dc.(*sqlite.Conn)
		if !ok {
			return &protocolError{fmt.Sprintf("connection is not *sqlite.Conn (%T)", dc)}
		}
		ds, err := c.Prepare(sqlText)
		if err != nil {
			return err
		}
		defer func() { _ = ds.Close() }()
		st, ok := ds.(stmtDescriber)
		if !ok {
			return &protocolError{fmt.Sprintf("statement is not introspectable (%T)", ds)}
		}
		for i := range st.ColumnCount() {
			name := st.ColumnName(i)
			col := hCol{Name: &name}
			if dt := st.ColumnDeclType(i); dt != "" {
				col.Decltype = &dt
			}
			out.Cols = append(out.Cols, col)
		}
		for i := 1; i <= st.BindCount(); i++ { // SQLite indexes parameters from 1
			var p hDescribeParam
			if name := st.BindName(i); name != "" {
				p.Name = &name
			}
			out.Params = append(out.Params, p)
		}
		out.IsReadonly = st.Readonly()
		return nil
	})
	if err != nil {
		// Carry the SQLite codes into the shared engine.Error shape so hErrorFrom
		// maps a prepare failure exactly like an execution failure.
		if se, ok := errors.AsType[*sqlite.Error](err); ok {
			return nil, &engine.Error{Code: se.Code(), Extended: se.ExtendedCode(), Msg: se.Error()}
		}
		return nil, err
	}
	return out, nil
}

func (h *Handler) execStmt(ctx context.Context, sess *session.Session, st hStmt) (*hStmtResult, error) {
	sqlText, err := resolveSQL(sess, st.SQL, st.SQLID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := h.withTimeout(ctx)
	defer cancel()
	res, err := h.eng.Run(ctx, sess.Conn(), stmtFromHrana(sqlText, st))
	if err != nil {
		return nil, err
	}
	return toHStmtResult(res, st.WantRows), nil
}

func (h *Handler) execBatch(ctx context.Context, sess *session.Session, b hBatch) *hBatchResult {
	return h.runHranaBatch(ctx, sess, b, nil)
}

// runHranaBatch executes a Hrana batch step by step, evaluating each step's
// condition against the results so far. Every EXECUTED step is also reported to
// emit (when non-nil) — skipped steps are not, matching the cursor entry rules —
// and a false return from emit abandons the rest of the batch (the cursor
// client is gone). The pipeline `batch` request and the cursor endpoint share
// this loop so their condition semantics cannot drift. (runBatch, in native.go,
// is the native path's all-or-nothing transaction batch — a different contract.)
func (h *Handler) runHranaBatch(ctx context.Context, sess *session.Session, b hBatch, emit func(step int, res *hStmtResult, herr *hError) bool) *hBatchResult {
	n := len(b.Steps)
	out := &hBatchResult{StepResults: make([]*hStmtResult, n), StepErrors: make([]*hError, n)}
	ac := autocommit(sess.Conn())
	for i, step := range b.Steps {
		if step.Condition != nil && !evalCond(step.Condition, out.StepResults, out.StepErrors, ac) {
			continue // skipped step: both result and error stay nil
		}
		res, err := h.execStmt(ctx, sess, step.Stmt)
		var herr *hError
		if err != nil {
			herr = hErrorFrom(err)
			out.StepErrors[i] = herr
		} else {
			out.StepResults[i] = res
		}
		if emit != nil && !emit(i, res, herr) {
			return out
		}
		ac = autocommit(sess.Conn()) // BEGIN/COMMIT in a step flips autocommit
	}
	return out
}

// evalCond evaluates a Hrana batch condition against the results so far.
func evalCond(c *hBatchCond, results []*hStmtResult, errs []*hError, ac bool) bool {
	switch c.Type {
	case "ok":
		return c.Step != nil && int(*c.Step) < len(results) && results[*c.Step] != nil
	case "error":
		return c.Step != nil && int(*c.Step) < len(errs) && errs[*c.Step] != nil
	case "not":
		return c.Cond != nil && !evalCond(c.Cond, results, errs, ac)
	case "and":
		for i := range c.Conds {
			if !evalCond(&c.Conds[i], results, errs, ac) {
				return false
			}
		}
		return true
	case "or":
		for i := range c.Conds {
			if evalCond(&c.Conds[i], results, errs, ac) {
				return true
			}
		}
		return false
	case "is_autocommit":
		return ac
	default:
		return false
	}
}

// protocolError is a client-side request error (bad sql_id, missing sql). It is
// surfaced to the client verbatim rather than masked as "internal error".
type protocolError struct{ msg string }

func (e *protocolError) Error() string { return e.msg }

// resolveSQL picks the literal SQL or the session-cached SQL (sql_id).
func resolveSQL(sess *session.Session, sqlText *string, sqlID *int32) (string, error) {
	switch {
	case sqlText != nil:
		return *sqlText, nil
	case sqlID != nil:
		if s, ok := sess.LookupSQL(*sqlID); ok {
			return s, nil
		}
		return "", &protocolError{"unknown sql_id"}
	default:
		return "", &protocolError{"request has neither sql nor sql_id"}
	}
}

func stmtFromHrana(sqlText string, st hStmt) engine.Statement {
	es := engine.Statement{SQL: sqlText}
	switch {
	case len(st.NamedArgs) > 0:
		es.Named = make([]engine.NamedArg, len(st.NamedArgs))
		for i, na := range st.NamedArgs {
			es.Named[i] = engine.NamedArg{Name: na.Name, Value: na.Value.v}
		}
	case len(st.Args) > 0:
		es.Args = make([]engine.Value, len(st.Args))
		for i, a := range st.Args {
			es.Args[i] = a.v
		}
	}
	return es
}

func toHStmtResult(res *engine.Result, wantRows *bool) *hStmtResult {
	out := &hStmtResult{
		Cols:             make([]hCol, len(res.Columns)),
		Rows:             [][]hValue{},
		AffectedRowCount: uint64(res.RowsAffected),
		Truncated:        res.Truncated,
	}
	for i, c := range res.Columns {
		name := c.Name
		out.Cols[i] = hCol{Name: &name}
	}
	if wantRows == nil || *wantRows {
		out.Rows = make([][]hValue, len(res.Rows))
		for i, row := range res.Rows {
			cells := make([]hValue, len(row))
			for j, v := range row {
				cells[j] = hValue{v: v}
			}
			out.Rows[i] = cells
		}
	}
	if res.LastInsertID != 0 {
		s := strconv.FormatInt(res.LastInsertID, 10)
		out.LastInsertRowid = &s
	}
	return out
}

func okStream(resp any) streamResult { return streamResult{Type: "ok", Response: resp} }
func errStream(msg string) streamResult {
	return streamResult{Type: "error", Error: &hError{Message: msg}}
}

// hErrorFrom maps an execution error to a Hrana error: SQLite errors keep their
// message + symbolic code, a policy denial and a client protocol error surface
// their message, and anything else is masked to "internal error" (no
// path/driver leakage). Counterpart of the native path's writeRunError/toAPIError
// (handler.go/native.go) — separate because the wire error shapes differ.
func hErrorFrom(err error) *hError {
	var pe *protocolError
	var e *engine.Error
	switch {
	case errors.As(err, &pe):
		return &hError{Message: pe.msg}
	case errors.Is(err, engine.ErrDenied):
		return &hError{Message: err.Error()}
	case errors.As(err, &e):
		// Send the EXTENDED-code name so a client can tell constraint subtypes
		// (unique / foreign-key / not-null / check) apart — the primary code
		// alone collapses them all to SQLITE_CONSTRAINT.
		code := engine.ExtendedCodeName(e.Extended)
		return &hError{Message: e.Msg, Code: &code}
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return &hError{Message: "statement timed out"}
	default:
		return &hError{Message: "internal error"}
	}
}

// autocommit reports whether the pinned connection is in autocommit mode (no
// open transaction), via the driver's AutoCommit accessor.
func autocommit(sc *sql.Conn) bool {
	ac := true
	_ = sc.Raw(func(dc any) error {
		if c, ok := dc.(*sqlite.Conn); ok {
			ac = c.AutoCommit()
		}
		return nil
	})
	return ac
}
