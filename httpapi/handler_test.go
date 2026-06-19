package httpapi_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/engine"
	"quicsql.net/httpapi"
	"quicsql.net/registry"
	"quicsql.net/secret"
)

func newHandler(t *testing.T) *httpapi.Handler {
	t.Helper()
	sec, _ := secret.New(nil)
	be, err := backend.For(config.Database{
		Name:    "app",
		Backend: "file",
		Path:    filepath.Join(t.TempDir(), "app.db"),
		Pragmas: map[string]any{"journal_mode": "WAL"},
	}, sec, "")
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{"app": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	eng := engine.New(0, 0)
	return httpapi.New(reg, eng, config.Routing{ByPath: true, ByHost: true, HostSuffix: ".q.local"})
}

func do(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func post(t *testing.T, h http.Handler, target, body string) *httptest.ResponseRecorder {
	return do(t, h, http.MethodPost, target, body)
}

func mustOK(t *testing.T, h http.Handler, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := post(t, h, target, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s → status %d, body %s", body, rec.Code, rec.Body.String())
	}
	return rec
}

// TestNativeRoundTrip covers the whole value matrix: int, float, text, blob (as
// {"base64":...}), and null, in and out.
func TestNativeRoundTrip(t *testing.T) {
	h := newHandler(t)
	mustOK(t, h, "/app/query", `{"sql":"CREATE TABLE t(i INTEGER, f REAL, s TEXT, b BLOB, n INT)"}`)
	b64 := base64.StdEncoding.EncodeToString([]byte{0, 1, 2})
	mustOK(t, h, "/app/query",
		`{"sql":"INSERT INTO t(i,f,s,b,n) VALUES(?,?,?,?,?)","args":[7,2.5,"hi",{"base64":"`+b64+`"},null]}`)

	rec := mustOK(t, h, "/app/query", `{"sql":"SELECT i,f,s,b,n FROM t"}`)
	var resp struct {
		Columns []string            `json:"columns"`
		Rows    [][]json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body)
	}
	if len(resp.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(resp.Rows))
	}
	want := []string{"7", "2.5", `"hi"`, `{"base64":"` + b64 + `"}`, "null"}
	for i, w := range want {
		if got := string(resp.Rows[0][i]); got != w {
			t.Errorf("cell %d: got %s, want %s", i, got, w)
		}
	}
}

func TestWriteReportsAffected(t *testing.T) {
	h := newHandler(t)
	mustOK(t, h, "/app/query", `{"sql":"CREATE TABLE u(id INTEGER PRIMARY KEY, v TEXT)"}`)
	rec := mustOK(t, h, "/app/query", `{"sql":"INSERT INTO u(v) VALUES(?)","args":["x"]}`)
	var resp struct {
		RowsAffected int64 `json:"rows_affected"`
		LastInsertID int64 `json:"last_insert_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.RowsAffected != 1 || resp.LastInsertID != 1 {
		t.Fatalf("want affected=1 last=1, got %+v", resp)
	}
}

func TestBatchOneTransaction(t *testing.T) {
	h := newHandler(t)
	mustOK(t, h, "/app/query", `{"sql":"CREATE TABLE b(x INTEGER)"}`)
	rec := mustOK(t, h, "/app/query",
		`{"statements":[{"sql":"INSERT INTO b VALUES(1)"},{"sql":"INSERT INTO b VALUES(2)"}]}`)
	var resp struct {
		Results []struct {
			RowsAffected int64 `json:"rows_affected"`
		} `json:"results"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Results) != 2 {
		t.Fatalf("want 2 results, got %+v", resp)
	}
	count := mustOK(t, h, "/app/query", `{"sql":"SELECT count(*) FROM b"}`)
	if !strings.Contains(count.Body.String(), "[[2]]") {
		t.Fatalf("want count 2, got %s", count.Body)
	}
}

func TestBatchRollsBackOnError(t *testing.T) {
	h := newHandler(t)
	mustOK(t, h, "/app/query", `{"sql":"CREATE TABLE w(x INTEGER PRIMARY KEY)"}`)
	rec := mustOK(t, h, "/app/query",
		`{"statements":[{"sql":"INSERT INTO w VALUES(1)"},{"sql":"INSERT INTO w VALUES(1)"}]}`)
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("want error envelope, got %s", rec.Body)
	}
	count := mustOK(t, h, "/app/query", `{"sql":"SELECT count(*) FROM w"}`)
	if !strings.Contains(count.Body.String(), "[[0]]") {
		t.Fatalf("batch not rolled back: %s", count.Body)
	}
}

func TestSQLErrorIsEnvelope(t *testing.T) {
	h := newHandler(t)
	rec := mustOK(t, h, "/app/query", `{"sql":"SELECT * FROM does_not_exist"}`)
	var resp struct {
		Error *struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Message == "" {
		t.Fatalf("want SQL error envelope, got %s", rec.Body)
	}
}

func TestTransportErrors(t *testing.T) {
	h := newHandler(t)
	cases := []struct {
		name, method, target, body string
		want                       int
	}{
		{"unknown db", http.MethodPost, "/nope/query", `{"sql":"SELECT 1"}`, http.StatusNotFound},
		{"malformed json", http.MethodPost, "/app/query", `{not json`, http.StatusBadRequest},
		{"empty request", http.MethodPost, "/app/query", `{}`, http.StatusBadRequest},
		{"both fields", http.MethodPost, "/app/query", `{"sql":"SELECT 1","statements":[{"sql":"SELECT 1"}]}`, http.StatusBadRequest},
		{"method not allowed", http.MethodGet, "/app/query", ``, http.StatusMethodNotAllowed},
		{"reserved path", http.MethodGet, "/_admin/x", ``, http.StatusNotFound},
		{"unknown endpoint", http.MethodPost, "/app/frobnicate", `{}`, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(t, h, c.method, c.target, c.body)
			if rec.Code != c.want {
				t.Fatalf("status %d, want %d (body %s)", rec.Code, c.want, rec.Body)
			}
		})
	}
}

func TestHealth(t *testing.T) {
	h := newHandler(t)
	rec := do(t, h, http.MethodGet, "/_health", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("health: status %d body %s", rec.Code, rec.Body)
	}
}

func TestHostRoutingAndPathWins(t *testing.T) {
	h := newHandler(t)
	// Host routing: <db>.<suffix> with an endpoint-only path.
	mustOK(t, h, "http://app.q.local/query", `{"sql":"CREATE TABLE h(x)"}`)
	mustOK(t, h, "http://app.q.local/query", `{"sql":"INSERT INTO h VALUES(1)"}`)
	// Path wins when both a path db-prefix and a host subdomain are present.
	rec := mustOK(t, h, "http://other.q.local/app/query", `{"sql":"SELECT count(*) FROM h"}`)
	if !strings.Contains(rec.Body.String(), "[[1]]") {
		t.Fatalf("path did not win / host routing failed: %s", rec.Body)
	}
}
