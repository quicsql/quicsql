package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"quicsql.net/internal/wire"
)

// Stream is a session-pinned sequence of statements over the server's Hrana
// pipeline endpoint (/<db>/v3/pipeline). Every statement on a Stream runs on the
// same server-side connection, held for the Stream's lifetime — which is what a
// database/sql transaction (BEGIN … COMMIT, with SAVEPOINT nesting) requires.
// The stateless Query/Exec on *Client cannot give that guarantee.
//
// A Stream is opened lazily: the first Exec sends a null baton, the server pins a
// connection and returns a baton, and each subsequent Exec threads the rotated
// baton to resume the same connection. Close ends the server-side session. A
// Stream is not safe for concurrent use; drive it from one goroutine (the
// database/sql contract for a connection in a transaction).
type Stream struct {
	c      *Client
	db     string
	baton  *string
	closed bool
}

// OpenStream returns a Stream bound to db. No network call happens until the
// first Exec.
func (c *Client) OpenStream(db string) *Stream { return &Stream{c: c, db: db} }

// Exec runs one statement on the stream's pinned connection and returns its
// result. sql may be any statement, including BEGIN / SAVEPOINT / RELEASE /
// COMMIT / ROLLBACK.
func (s *Stream) Exec(ctx context.Context, sql string, args []any) (*Result, error) {
	if s.closed {
		return nil, fmt.Errorf("quicsql: stream is closed")
	}
	resp, err := s.c.pipeline(ctx, s.db, s.baton, []any{executeRequest(sql, args)})
	if err != nil {
		return nil, err
	}
	s.baton = resp.Baton
	if len(resp.Results) != 1 {
		return nil, fmt.Errorf("quicsql: pipeline returned %d results, want 1", len(resp.Results))
	}
	return resultFromExecute(resp.Results[0])
}

// SessionStart begins capturing a SQLite changeset on the stream's pinned
// connection: every write executed on this stream afterward is recorded. tables
// names the tables to track (empty tracks all). Pair with SessionChangeset. This
// is a quicSQL extension to the Hrana pipeline.
func (s *Stream) SessionStart(ctx context.Context, tables []string) error {
	if s.closed {
		return fmt.Errorf("quicsql: stream is closed")
	}
	req := map[string]any{"type": "session_start"}
	if len(tables) > 0 {
		req["tables"] = tables
	}
	resp, err := s.c.pipeline(ctx, s.db, s.baton, []any{req})
	if err != nil {
		return err
	}
	s.baton = resp.Baton
	if len(resp.Results) == 1 && (resp.Results[0].Type == "error" || resp.Results[0].Error != nil) {
		return hranaError(resp.Results[0].Error)
	}
	return nil
}

// SessionChangeset serializes and returns the changeset captured since
// SessionStart (consuming the capture; a second call needs a fresh SessionStart).
func (s *Stream) SessionChangeset(ctx context.Context) ([]byte, error) {
	if s.closed {
		return nil, fmt.Errorf("quicsql: stream is closed")
	}
	resp, err := s.c.pipeline(ctx, s.db, s.baton, []any{map[string]any{"type": "session_changeset"}})
	if err != nil {
		return nil, err
	}
	s.baton = resp.Baton
	if len(resp.Results) != 1 {
		return nil, fmt.Errorf("quicsql: pipeline returned %d results, want 1", len(resp.Results))
	}
	r := resp.Results[0]
	if r.Type == "error" || r.Error != nil {
		return nil, hranaError(r.Error)
	}
	var out struct {
		Changeset string `json:"changeset"`
	}
	if err := json.Unmarshal(r.Response, &out); err != nil {
		return nil, fmt.Errorf("quicsql: decode changeset: %w", err)
	}
	return base64.StdEncoding.DecodeString(out.Changeset)
}

// Close ends the server-side session (a Hrana "close" request), returning the
// pinned connection to the server's pool. It is safe to call more than once and
// on a never-used stream (no baton yet → no-op).
func (s *Stream) Close(ctx context.Context) error {
	if s.closed || s.baton == nil {
		s.closed = true
		return nil
	}
	s.closed = true
	_, err := s.c.pipeline(ctx, s.db, s.baton, []any{map[string]any{"type": "close"}})
	return err
}

// Statement is one SQL statement plus its bound arguments, for [Client.Batch].
type Statement struct {
	SQL  string
	Args []any
}

// Batch runs several statements in ONE HTTP request — a single authentication and
// a single network round trip — instead of one request per statement. The
// statements run in order on one server-side connection, each autocommitting.
//
// It returns one Result per statement (in order). The batch is NOT atomic: a
// failing statement does not roll back the ones before it, and Batch returns the
// first statement's error (wrapped with its index) without the later results. For
// all-or-nothing semantics, make the first and last statements BEGIN and COMMIT,
// or use [Client.OpenStream] for an interactive transaction.
//
// This is the fix for "I have N statements to run": it saves N-1 round trips for
// every auth method, and with the keyring method it also collapses N challenge
// fetches into (at most) one. Batch uses the Hrana pipeline endpoint, so the
// server must have sessions enabled (it is, in every standard deployment).
func (c *Client) Batch(ctx context.Context, db string, stmts []Statement) ([]*Result, error) {
	if len(stmts) == 0 {
		return nil, nil
	}
	// N execute requests + a trailing close, so the server opens the session,
	// runs every statement on its pinned connection, and tears it down within
	// this one request — no lingering server-side session.
	requests := make([]any, 0, len(stmts)+1)
	for _, s := range stmts {
		requests = append(requests, executeRequest(s.SQL, s.Args))
	}
	requests = append(requests, map[string]any{"type": "close"})

	resp, err := c.pipeline(ctx, db, nil, requests)
	if err != nil {
		return nil, err
	}
	if len(resp.Results) < len(stmts) {
		return nil, fmt.Errorf("quicsql: batch returned %d results, want at least %d", len(resp.Results), len(stmts))
	}
	out := make([]*Result, 0, len(stmts))
	for i := range stmts {
		r, err := resultFromExecute(resp.Results[i])
		if err != nil {
			return nil, fmt.Errorf("quicsql: batch statement %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// --- pipeline transport ---

type hpResp struct {
	Baton   *string    `json:"baton"`
	Results []hpResult `json:"results"`
}

type hpResult struct {
	Type     string          `json:"type"`
	Response json.RawMessage `json:"response"`
	Error    *hpError        `json:"error"`
}

type hpError struct {
	Message string  `json:"message"`
	Code    *string `json:"code"`
}

type hpExecuteResp struct {
	Result *hpStmtResult `json:"result"`
}

type hpStmtResult struct {
	Cols []struct {
		Name *string `json:"name"`
	} `json:"cols"`
	Rows             [][]json.RawMessage `json:"rows"`
	AffectedRowCount int64               `json:"affected_row_count"`
	LastInsertRowid  *string             `json:"last_insert_rowid"`
	Truncated        bool                `json:"truncated"`
}

// pipeline posts a Hrana pipeline request (baton + requests) to db and decodes
// the envelope. It threads auth exactly like the native endpoint.
func (c *Client) pipeline(ctx context.Context, db string, baton *string, requests []any) (*hpResp, error) {
	reqBody, err := json.Marshal(map[string]any{"baton": baton, "requests": requests})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/"+db+"/v3/pipeline", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.authenticate(ctx, req); err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := c.readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quicsql: %s: %s", resp.Status, firstMessage(body))
	}
	var out hpResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("quicsql: decode pipeline response: %w", err)
	}
	return &out, nil
}

// executeRequest builds a Hrana {"type":"execute","stmt":{…}} request, encoding
// args in Hrana's tagged value form.
func executeRequest(sql string, args []any) map[string]any {
	stmt := map[string]any{"sql": sql, "want_rows": true}
	if len(args) > 0 {
		hargs := make([]any, len(args))
		for i, a := range args {
			hargs[i] = encodeHValue(a)
		}
		stmt["args"] = hargs
	}
	return map[string]any{"type": "execute", "stmt": stmt}
}

// resultFromExecute maps one stream result (ok/execute or error) to a *Result.
func resultFromExecute(r hpResult) (*Result, error) {
	if r.Type == "error" || r.Error != nil {
		return nil, hranaError(r.Error)
	}
	var exec hpExecuteResp
	if err := json.Unmarshal(r.Response, &exec); err != nil {
		return nil, fmt.Errorf("quicsql: decode execute result: %w", err)
	}
	if exec.Result == nil {
		return &Result{}, nil
	}
	sr := exec.Result
	res := &Result{RowsAffected: sr.AffectedRowCount, Truncated: sr.Truncated}
	if sr.LastInsertRowid != nil {
		res.LastInsertID, _ = strconv.ParseInt(*sr.LastInsertRowid, 10, 64)
	}
	res.Columns = make([]string, len(sr.Cols))
	for i, col := range sr.Cols {
		if col.Name != nil {
			res.Columns[i] = *col.Name
		}
	}
	res.Rows = make([][]any, len(sr.Rows))
	for i, row := range sr.Rows {
		cells := make([]any, len(row))
		for j, cell := range row {
			v, err := decodeHValue(cell)
			if err != nil {
				return nil, fmt.Errorf("quicsql: decode cell: %w", err)
			}
			cells[j] = v
		}
		res.Rows[i] = cells
	}
	return res, nil
}

// hranaError turns a Hrana error into a *Error, recovering the numeric extended
// result code from its symbolic name so constraint/busy classification survives
// the wire (the server sends the extended-code name; see engine.ExtendedCodeName).
func hranaError(e *hpError) error {
	if e == nil {
		return fmt.Errorf("quicsql: unknown stream error")
	}
	ext := extendedFromName(e.Code)
	return &Error{Message: e.Message, code: ext & 0xff, ext: ext}
}

// extendedFromName recovers the numeric result code (extended subtype when the
// name is a constraint specialization, else the primary code) from the symbolic
// name the server sent, via the single wire table — the inverse of the server's
// wire.ExtendedCodeName, so the two cannot drift.
func extendedFromName(name *string) int {
	if name == nil {
		return 0
	}
	return wire.CodeForName(*name)
}

// --- Hrana tagged value codec ---

// encodeHValue maps a Go argument to Hrana's tagged value form via the shared wire
// codec. It normalizes through wire.FromGo — the SAME normalizer the native path
// uses — so a given argument encodes to the identical stored type on both paths and
// the two cannot drift.
func encodeHValue(a any) wire.HranaValue { return wire.HranaValue{V: wire.FromGo(a)} }

// decodeHValue maps one Hrana tagged value to a Go value via the shared wire codec:
// null→nil, integer→int64, float→float64, text→string, blob→[]byte. All are valid
// driver.Values, so the database/sql driver passes them through unchanged.
func decodeHValue(raw json.RawMessage) (any, error) {
	var hv wire.HranaValue
	if err := hv.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	return hv.V.Go(), nil
}
