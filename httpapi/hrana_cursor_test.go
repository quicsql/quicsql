package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// cursorLine decodes any line of a cursor response: the prelude (baton /
// base_url) or a cursor entry (type-discriminated).
type cursorLine struct {
	Baton   *string `json:"baton"`
	BaseURL *string `json:"base_url"`

	Type string `json:"type"`
	Step *int   `json:"step"`
	Cols []struct {
		Name *string `json:"name"`
	} `json:"cols"`
	Row []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"row"`
	AffectedRowCount *uint64 `json:"affected_row_count"`
	LastInsertRowid  *string `json:"last_insert_rowid"`
	Error            *struct {
		Message string  `json:"message"`
		Code    *string `json:"code"`
	} `json:"error"`
}

// cursor posts a batch to /v3/cursor and decodes the newline-separated JSON
// response into the prelude and its entries.
func cursor(t *testing.T, h http.Handler, db string, baton *string, batch string) (prelude cursorLine, entries []cursorLine) {
	t.Helper()
	bj := "null"
	if baton != nil {
		bj = strconv.Quote(*baton)
	}
	rec := post(t, h, "/"+db+"/v3/cursor", `{"baton":`+bj+`,"batch":`+batch+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cursor status %d: %s", rec.Code, rec.Body)
	}
	// The reference implementation serves the JSON cursor stream as text/plain.
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("cursor content-type: want text/plain, got %q", ct)
	}
	lines := strings.Split(strings.TrimRight(rec.Body.String(), "\n"), "\n")
	if err := json.Unmarshal([]byte(lines[0]), &prelude); err != nil {
		t.Fatalf("decode prelude: %v (%s)", err, lines[0])
	}
	for _, ln := range lines[1:] {
		var e cursorLine
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("decode entry: %v (%s)", err, ln)
		}
		entries = append(entries, e)
	}
	return prelude, entries
}

// entryTypes flattens the entry sequence for order assertions.
func entryTypes(entries []cursorLine) string {
	kinds := make([]string, len(entries))
	for i, e := range entries {
		kinds[i] = e.Type
	}
	return strings.Join(kinds, " ")
}

// TestHranaCursorMultiStepRows is the NDJSON happy path: a prelude carrying a
// baton and a null base_url, then step_begin/row/step_end per executed step, in
// batch order with step indices referring to the steps array.
func TestHranaCursorMultiStepRows(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(x INTEGER)"}}]`)

	prelude, entries := cursor(t, h, "app", nil, `{"steps":[
		{"stmt":{"sql":"INSERT INTO t VALUES(1),(2)"}},
		{"stmt":{"sql":"SELECT x FROM t ORDER BY x","want_rows":true}}]}`)
	if prelude.Baton == nil {
		t.Fatal("prelude should carry a baton for the open stream")
	}
	if prelude.BaseURL != nil {
		t.Fatalf("base_url should be null, got %q", *prelude.BaseURL)
	}
	if got, want := entryTypes(entries), "step_begin step_end step_begin row row step_end"; got != want {
		t.Fatalf("entry sequence: want %q, got %q", want, got)
	}
	if *entries[0].Step != 0 || *entries[2].Step != 1 {
		t.Fatalf("step indices: got %d / %d", *entries[0].Step, *entries[2].Step)
	}
	// The INSERT's step_end reports affected rows and a last_insert_rowid.
	if e := entries[1]; e.AffectedRowCount == nil || *e.AffectedRowCount != 2 || e.LastInsertRowid == nil {
		t.Fatalf("insert step_end: %+v", e)
	}
	// The SELECT's step_begin names the column; rows carry integers as strings.
	if len(entries[2].Cols) != 1 || *entries[2].Cols[0].Name != "x" {
		t.Fatalf("select cols: %+v", entries[2].Cols)
	}
	if entries[3].Row[0].Value != "1" || entries[4].Row[0].Value != "2" {
		t.Fatalf("rows: %+v / %+v", entries[3].Row, entries[4].Row)
	}
}

// TestHranaCursorStepConditions mirrors TestHranaBatchConditions on the cursor
// endpoint: a skipped step (condition false) produces NO entries at all.
func TestHranaCursorStepConditions(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(x INTEGER PRIMARY KEY)"}}]`)
	_, entries := cursor(t, h, "app", nil, `{"steps":[
		{"stmt":{"sql":"INSERT INTO t VALUES(1)"}},
		{"condition":{"type":"ok","step":0},"stmt":{"sql":"INSERT INTO t VALUES(2)"}},
		{"condition":{"type":"error","step":0},"stmt":{"sql":"INSERT INTO t VALUES(3)"}}]}`)
	if got, want := entryTypes(entries), "step_begin step_end step_begin step_end"; got != want {
		t.Fatalf("entry sequence: want %q, got %q", want, got)
	}
	if *entries[0].Step != 0 || *entries[2].Step != 1 {
		t.Fatalf("executed steps: %d / %d", *entries[0].Step, *entries[2].Step)
	}
	// Steps 0 and 1 ran, step 2 was skipped → two rows, same as the pipeline batch.
	if got := firstInt(t, pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT count(*) AS n FROM t","want_rows":true}}]`)); got != "2" {
		t.Fatalf("cursor conditions: want 2 rows, got %s", got)
	}
}

// TestHranaCursorStepError: a failing step yields a step_error entry (carrying
// the SQLite extended-code name), and an error-conditioned later step then
// executes — identical to the pipeline batch semantics.
func TestHranaCursorStepError(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(x INTEGER PRIMARY KEY)"}},{"type":"execute","stmt":{"sql":"INSERT INTO t VALUES(1)"}}]`)
	_, entries := cursor(t, h, "app", nil, `{"steps":[
		{"stmt":{"sql":"INSERT INTO t VALUES(1)"}},
		{"condition":{"type":"error","step":0},"stmt":{"sql":"SELECT count(*) AS n FROM t","want_rows":true}}]}`)
	if got, want := entryTypes(entries), "step_error step_begin row step_end"; got != want {
		t.Fatalf("entry sequence: want %q, got %q", want, got)
	}
	e := entries[0]
	if *e.Step != 0 || e.Error == nil || e.Error.Code == nil || !strings.Contains(*e.Error.Code, "CONSTRAINT") {
		t.Fatalf("step_error entry: %+v", e)
	}
}

// TestHranaCursorBatonContinuity: a cursor request rides the same session store
// as the pipeline, in both directions — it resumes a pipeline-opened stream's
// transaction, and its prelude baton is then resumed by a pipeline request that
// commits and closes.
func TestHranaCursorBatonContinuity(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	b := pipe(t, h, "app", nil, `[
		{"type":"execute","stmt":{"sql":"CREATE TABLE t(x INTEGER)"}},
		{"type":"execute","stmt":{"sql":"BEGIN"}}]`).Baton

	// The is_autocommit condition sees the open transaction on the pinned conn.
	prelude, entries := cursor(t, h, "app", b, `{"steps":[
		{"stmt":{"sql":"INSERT INTO t VALUES(7)"}},
		{"condition":{"type":"not","cond":{"type":"is_autocommit"}},"stmt":{"sql":"INSERT INTO t VALUES(8)"}}]}`)
	if got, want := entryTypes(entries), "step_begin step_end step_begin step_end"; got != want {
		t.Fatalf("entry sequence: want %q, got %q", want, got)
	}
	// Not committed yet: a separate autocommit stream sees the pre-commit snapshot.
	if got := firstInt(t, pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT count(*) AS n FROM t","want_rows":true}}]`)); got != "0" {
		t.Fatalf("before commit: want 0, got %s", got)
	}
	// The pipeline resumes the cursor's prelude baton to commit and close.
	pipe(t, h, "app", prelude.Baton, `[{"type":"execute","stmt":{"sql":"COMMIT"}},{"type":"close"}]`)
	if got := firstInt(t, pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT count(*) AS n FROM t","want_rows":true}}]`)); got != "2" {
		t.Fatalf("after commit: want 2, got %s", got)
	}
}

// TestHranaCursorAuthz: a principal without a grant is denied up front with the
// standard error envelope (no stream), and a read-only principal's write step
// fails in-stream as a step_error without touching the database.
func TestHranaCursorAuthz(t *testing.T) {
	h := newAuthHandler(t)
	if rec := postAs(t, h, "writer", "/app/query", `{"sql":"CREATE TABLE c(x)"}`); rec.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", rec.Code, rec.Body)
	}
	rec := postAs(t, h, "stranger", "/app/v3/cursor", `{"baton":null,"batch":{"steps":[{"stmt":{"sql":"SELECT 1"}}]}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stranger cursor: want 403, got %d (%s)", rec.Code, rec.Body)
	}
	rec = postAs(t, h, "reader", "/app/v3/cursor", `{"baton":null,"batch":{"steps":[{"stmt":{"sql":"INSERT INTO c VALUES(1)"}}]}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reader cursor: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"step_error"`) {
		t.Fatalf("read-only cursor write should be a step_error: %s", rec.Body)
	}
	check := postAs(t, h, "writer", "/app/query", `{"sql":"SELECT count(*) FROM c"}`)
	if !strings.Contains(check.Body.String(), "[[0]]") {
		t.Fatalf("read-only cursor write leaked: %s", check.Body)
	}
}

// TestHranaCursorRequestValidation covers the pre-stream failures (normal error
// envelope + status) and the /v2 route.
func TestHranaCursorRequestValidation(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	if rec := post(t, h, "/app/v3/cursor", `{"baton":"forged.baton","batch":{"steps":[]}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("forged baton: want 400, got %d (%s)", rec.Code, rec.Body)
	}
	if rec := post(t, h, "/app/v3/cursor", `{"baton":null}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing batch: want 400, got %d (%s)", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/app/v3/cursor", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET cursor: want 405, got %d", rec.Code)
	}
	// The v2 route accepts cursors too (a harmless superset of Hrana 2).
	if rec := post(t, h, "/app/v2/cursor", `{"baton":null,"batch":{"steps":[{"stmt":{"sql":"SELECT 1"}}]}}`); rec.Code != http.StatusOK {
		t.Fatalf("v2 cursor: want 200, got %d (%s)", rec.Code, rec.Body)
	}
}
