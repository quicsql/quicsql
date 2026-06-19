package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/engine"
	"quicsql.net/httpapi"
	"quicsql.net/registry"
	"quicsql.net/secret"
	"quicsql.net/session"
)

func walDB(name string) config.Database {
	return config.Database{
		Name: name, Backend: "file", Path: name + ".db",
		Pragmas: map[string]any{"journal_mode": "WAL", "busy_timeout": 2000},
	}
}

func newHranaHandler(t *testing.T, db config.Database) *httpapi.Handler {
	t.Helper()
	sec, _ := secret.New(nil)
	be, err := backend.For(db, sec, t.TempDir())
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{db.Name: be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	store, err := session.NewStore(time.Minute, time.Minute, 16)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(store.CloseAll)
	return httpapi.New(reg, engine.New(0, 0), config.Routing{ByPath: true}, httpapi.WithSessions(store))
}

type hpResp struct {
	Baton   *string `json:"baton"`
	Results []struct {
		Type     string          `json:"type"`
		Response json.RawMessage `json:"response"`
		Error    *struct {
			Message string `json:"message"`
		} `json:"error"`
	} `json:"results"`
}

func pipe(t *testing.T, h http.Handler, db string, baton *string, requests string) hpResp {
	t.Helper()
	bj := "null"
	if baton != nil {
		bj = strconv.Quote(*baton)
	}
	rec := post(t, h, "/"+db+"/v3/pipeline", `{"baton":`+bj+`,"requests":`+requests+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("pipeline status %d: %s", rec.Code, rec.Body)
	}
	var r hpResp
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode pipeline: %v (%s)", err, rec.Body)
	}
	return r
}

// firstInt reads the first cell of the first execute result as a Hrana integer.
func firstInt(t *testing.T, r hpResp) string {
	t.Helper()
	if len(r.Results) == 0 || r.Results[0].Type != "ok" {
		t.Fatalf("no ok result: %+v", r.Results)
	}
	var resp struct {
		Result struct {
			Rows [][]struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"rows"`
		} `json:"result"`
	}
	if err := json.Unmarshal(r.Results[0].Response, &resp); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(resp.Result.Rows) == 0 {
		t.Fatalf("no rows in result: %s", r.Results[0].Response)
	}
	return resp.Result.Rows[0][0].Value
}

func TestHranaExecuteIntegerAsString(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	r := pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT 42 AS n","want_rows":true}}]`)
	if got := firstInt(t, r); got != "42" {
		t.Fatalf("integer value: want \"42\" (string), got %q", got)
	}
	if r.Baton == nil {
		t.Fatal("expected a baton for the new stream")
	}
}

// TestHranaInteractiveTransaction is the core Phase 2 exit: BEGIN…INSERT…COMMIT
// spanning multiple pipeline requests on one baton, with isolation before commit.
func TestHranaInteractiveTransaction(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	r := pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(x INTEGER)"}}]`)
	b := r.Baton

	r = pipe(t, h, "app", b, `[
		{"type":"execute","stmt":{"sql":"BEGIN"}},
		{"type":"execute","stmt":{"sql":"INSERT INTO t VALUES(1)"}},
		{"type":"execute","stmt":{"sql":"INSERT INTO t VALUES(2)"}}]`)
	b = r.Baton

	// A separate autocommit stream sees the pre-commit snapshot (0) under WAL.
	if got := firstInt(t, pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT count(*) AS n FROM t","want_rows":true}}]`)); got != "0" {
		t.Fatalf("before commit: want 0, got %s", got)
	}
	// get_autocommit is false while the tx is open on the pinned stream.
	rac := pipe(t, h, "app", b, `[{"type":"get_autocommit"}]`)
	var ac struct {
		IsAutocommit bool `json:"is_autocommit"`
	}
	_ = json.Unmarshal(rac.Results[0].Response, &ac)
	if ac.IsAutocommit {
		t.Fatal("expected is_autocommit=false inside a transaction")
	}
	b = rac.Baton

	pipe(t, h, "app", b, `[{"type":"execute","stmt":{"sql":"COMMIT"}}]`)

	if got := firstInt(t, pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT count(*) AS n FROM t","want_rows":true}}]`)); got != "2" {
		t.Fatalf("after commit: want 2, got %s", got)
	}
}

func TestHranaCloseRollsBack(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	b := pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(x)"}}]`).Baton
	// Open a tx, insert, then close the stream — the insert must roll back.
	r := pipe(t, h, "app", b, `[
		{"type":"execute","stmt":{"sql":"BEGIN"}},
		{"type":"execute","stmt":{"sql":"INSERT INTO t VALUES(9)"}},
		{"type":"close"}]`)
	if r.Baton != nil {
		t.Fatal("close should return a null baton")
	}
	if got := firstInt(t, pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT count(*) AS n FROM t","want_rows":true}}]`)); got != "0" {
		t.Fatalf("close should roll back the tx: want 0, got %s", got)
	}
}

func TestHranaBatchConditions(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(x INTEGER PRIMARY KEY)"}}]`)
	pipe(t, h, "app", nil, `[{"type":"batch","batch":{"steps":[
		{"stmt":{"sql":"INSERT INTO t VALUES(1)"}},
		{"condition":{"type":"ok","step":0},"stmt":{"sql":"INSERT INTO t VALUES(2)"}},
		{"condition":{"type":"error","step":0},"stmt":{"sql":"INSERT INTO t VALUES(3)"}}]}}]`)
	// step 0 ran, step 1 ran (cond ok/0), step 2 skipped (cond error/0 is false) → count 2.
	if got := firstInt(t, pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT count(*) AS n FROM t","want_rows":true}}]`)); got != "2" {
		t.Fatalf("batch conditions: want 2 rows, got %s", got)
	}
}

func TestHranaNamedArgs(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(x INTEGER)"}}]`)
	pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"INSERT INTO t VALUES(:x)","named_args":[{"name":"x","value":{"type":"integer","value":"77"}}]}}]`)
	if got := firstInt(t, pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT x FROM t","want_rows":true}}]`)); got != "77" {
		t.Fatalf("named args: want 77, got %s", got)
	}
}

// describeResult decodes the first result of a pipeline as a DescribeResult.
func describeResult(t *testing.T, r hpResp) (res struct {
	Params []struct {
		Name *string `json:"name"`
	} `json:"params"`
	Cols []struct {
		Name     *string `json:"name"`
		Decltype *string `json:"decltype"`
	} `json:"cols"`
	IsExplain  bool `json:"is_explain"`
	IsReadonly bool `json:"is_readonly"`
}) {
	t.Helper()
	if len(r.Results) == 0 || r.Results[0].Type != "ok" {
		t.Fatalf("describe did not succeed: %+v", r.Results)
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(r.Results[0].Response, &resp); err != nil {
		t.Fatalf("decode describe response: %v", err)
	}
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("decode describe result: %v", err)
	}
	return res
}

// TestHranaDescribeSelect: describe prepares the statement and reports its real
// shape — column names with declared types, one params entry per SQL parameter
// (null name for a positional `?`, prefixed name otherwise), and the driver's
// exact read-only classification.
func TestHranaDescribeSelect(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(a INTEGER, b TEXT)"}}]`)

	res := describeResult(t, pipe(t, h, "app", nil, `[{"type":"describe","sql":"SELECT a, b FROM t WHERE a > ? AND b = :name"}]`))
	if len(res.Cols) != 2 || *res.Cols[0].Name != "a" || *res.Cols[1].Name != "b" {
		t.Fatalf("describe cols: %+v", res.Cols)
	}
	if *res.Cols[0].Decltype != "INTEGER" || *res.Cols[1].Decltype != "TEXT" {
		t.Fatalf("describe decltypes: %+v", res.Cols)
	}
	if len(res.Params) != 2 {
		t.Fatalf("describe params: want 2, got %+v", res.Params)
	}
	if res.Params[0].Name != nil { // positional ? is nameless
		t.Fatalf("positional param should have a null name: %+v", res.Params[0])
	}
	if res.Params[1].Name == nil || *res.Params[1].Name != ":name" {
		t.Fatalf("named param should keep its prefix: %+v", res.Params[1])
	}
	if !res.IsReadonly || res.IsExplain {
		t.Fatalf("SELECT: want is_readonly=true is_explain=false, got %+v", res)
	}

	// EXPLAIN is flagged.
	res = describeResult(t, pipe(t, h, "app", nil, `[{"type":"describe","sql":"EXPLAIN SELECT a FROM t"}]`))
	if !res.IsExplain {
		t.Fatalf("EXPLAIN: want is_explain=true, got %+v", res)
	}
}

// TestHranaDescribeWriteDoesNotExecute: describing an INSERT reports zero cols,
// the right param count, is_readonly=false — and must NOT run the statement.
func TestHranaDescribeWriteDoesNotExecute(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(a INTEGER)"}}]`)

	res := describeResult(t, pipe(t, h, "app", nil, `[{"type":"describe","sql":"INSERT INTO t(a) VALUES(1)"}]`))
	if len(res.Cols) != 0 || len(res.Params) != 0 || res.IsReadonly {
		t.Fatalf("INSERT describe: want no cols/params and is_readonly=false, got %+v", res)
	}
	if got := firstInt(t, pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT count(*) AS n FROM t","want_rows":true}}]`)); got != "0" {
		t.Fatalf("describe must not execute the statement: count %s", got)
	}
}

// TestHranaDescribeInvalidSQL: a prepare failure is an in-stream Hrana error
// (message + code), not a transport error.
func TestHranaDescribeInvalidSQL(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	r := pipe(t, h, "app", nil, `[{"type":"describe","sql":"SELEC nonsense FROM nowhere"}]`)
	if len(r.Results) == 0 || r.Results[0].Type != "error" || r.Results[0].Error == nil {
		t.Fatalf("invalid SQL describe: want an error result, got %+v", r.Results)
	}
	if r.Results[0].Error.Message == "" {
		t.Fatal("describe error should carry the SQLite message")
	}
}

func TestHranaForgedBatonRejected(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	rec := post(t, h, "/app/v3/pipeline", `{"baton":"forged.baton.value","requests":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("forged baton: want 400, got %d (%s)", rec.Code, rec.Body)
	}
}

func TestHranaAttachDenied(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	r := pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"ATTACH DATABASE '/tmp/x.db' AS y"}}]`)
	if r.Results[0].Type != "error" {
		t.Fatalf("ATTACH via Hrana should error, got %s", r.Results[0].Response)
	}
}

// TestHranaSequenceAttachDenied regresses the ATTACH-via-sequence filesystem
// escape (the authorizer must catch it even though SELECT leads the script).
func TestHranaSequenceAttachDenied(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	r := pipe(t, h, "app", nil, `[{"type":"sequence","sql":"SELECT 1; ATTACH DATABASE '/tmp/seq_evil.db' AS e"}]`)
	if r.Results[0].Type != "error" {
		t.Fatalf("multi-statement ATTACH via sequence must be denied, got %s", r.Results[0].Response)
	}
}

// TestHranaSavepoint exercises nested SAVEPOINT across the interactive stream.
func TestHranaSavepoint(t *testing.T) {
	h := newHranaHandler(t, walDB("app"))
	b := pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(x INTEGER)"}}]`).Baton
	pipe(t, h, "app", b, `[
		{"type":"execute","stmt":{"sql":"BEGIN"}},
		{"type":"execute","stmt":{"sql":"INSERT INTO t VALUES(1)"}},
		{"type":"execute","stmt":{"sql":"SAVEPOINT sp"}},
		{"type":"execute","stmt":{"sql":"INSERT INTO t VALUES(2)"}},
		{"type":"execute","stmt":{"sql":"ROLLBACK TO sp"}},
		{"type":"execute","stmt":{"sql":"COMMIT"}}]`)
	// only the pre-savepoint insert survives.
	if got := firstInt(t, pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"SELECT count(*) AS n FROM t","want_rows":true}}]`)); got != "1" {
		t.Fatalf("savepoint rollback: want 1, got %s", got)
	}
}

// TestHranaWriterContention: a second stream's writer is blocked by the first's
// held write lock and errors within busy_timeout (write-slot contention).
func TestHranaWriterContention(t *testing.T) {
	h := newHranaHandler(t, config.Database{
		Name: "app", Backend: "file", Path: "app.db",
		Pragmas: map[string]any{"journal_mode": "WAL", "busy_timeout": 150},
	})
	pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"CREATE TABLE t(x)"}}]`)
	pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"BEGIN IMMEDIATE"}}]`) // stream A holds the writer
	rb := pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":"BEGIN IMMEDIATE"}}]`)
	if rb.Results[0].Type != "error" {
		t.Fatalf("second writer should be blocked, got %s", rb.Results[0].Response)
	}
}

// TestHranaStatementTimeoutInterrupts: a slow query is cancelled by the
// statement timeout (ctx → sqlite3_interrupt).
func TestHranaStatementTimeoutInterrupts(t *testing.T) {
	sec, _ := secret.New(nil)
	be, err := backend.For(walDB("app"), sec, t.TempDir())
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{"app": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	store, _ := session.NewStore(time.Minute, time.Minute, 16)
	t.Cleanup(store.CloseAll)
	h := httpapi.New(reg, engine.New(0, 0), config.Routing{ByPath: true},
		httpapi.WithSessions(store), httpapi.WithStatementTimeout(100*time.Millisecond))

	slow := `WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 50000000) SELECT count(*) AS n FROM c`
	r := pipe(t, h, "app", nil, `[{"type":"execute","stmt":{"sql":`+strconv.Quote(slow)+`,"want_rows":true}}]`)
	if r.Results[0].Type != "error" {
		t.Fatalf("slow query should be interrupted by the statement timeout, got %s", r.Results[0].Response)
	}
}
