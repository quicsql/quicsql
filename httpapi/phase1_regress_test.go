package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"gosqlite.org/server/backend"
	"gosqlite.org/server/config"
	"gosqlite.org/server/engine"
	"gosqlite.org/server/httpapi"
	"gosqlite.org/server/registry"
	"gosqlite.org/server/secret"
)

// newHandlerDB builds a handler serving a single database of the caller's shape.
func newHandlerDB(t *testing.T, db config.Database) *httpapi.Handler {
	t.Helper()
	sec, _ := secret.New(nil)
	be, err := backend.For(db, sec, t.TempDir())
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{db.Name: be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	return httpapi.New(reg, engine.New(0, 0), config.Routing{ByPath: true, ByHost: true, HostSuffix: ".q.local"})
}

func fileDB(name string) config.Database {
	return config.Database{Name: name, Backend: "file", Path: name + ".db"}
}

// TestVaultOverHTTP closes the exit-criterion gap: a vault-backed database
// exercised through the HTTP endpoint (not just at the registry level).
func TestVaultOverHTTP(t *testing.T) {
	h := newHandlerDB(t, config.Database{
		Name: "vault", Backend: "vault", Path: "data.vault",
		Vault: &config.VaultConfig{Compression: "best"},
	})
	mustOK(t, h, "/vault/query", `{"sql":"CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)"}`)
	mustOK(t, h, "/vault/query", `{"sql":"INSERT INTO t(v) VALUES(?)","args":["stored-in-a-vault"]}`)
	rec := mustOK(t, h, "/vault/query", `{"sql":"SELECT id, v FROM t"}`)
	if !strings.Contains(rec.Body.String(), `"stored-in-a-vault"`) {
		t.Fatalf("vault round-trip over HTTP failed: %s", rec.Body)
	}
}

// TestNonFiniteFloat regresses the silent empty-200 blocker: a non-finite REAL
// must serialize (as a string) rather than abort the response.
func TestNonFiniteFloat(t *testing.T) {
	h := newHandlerDB(t, fileDB("app"))
	rec := mustOK(t, h, "/app/query", `{"sql":"SELECT 1e308*10 AS inf"}`)
	if body := strings.TrimSpace(rec.Body.String()); body == "" || !strings.Contains(body, "Infinity") {
		t.Fatalf("want a non-empty body containing Infinity, got %q", rec.Body.String())
	}
}

// TestCommentAndBOMPrefixedSelect regresses the read/write misclassification:
// a commented or BOM-prefixed SELECT must still return its rows.
func TestCommentAndBOMPrefixedSelect(t *testing.T) {
	h := newHandlerDB(t, fileDB("app"))
	mustOK(t, h, "/app/query", `{"sql":"CREATE TABLE t(x)"}`)
	mustOK(t, h, "/app/query", `{"sql":"INSERT INTO t VALUES(1),(2),(3)"}`)
	bomSelect := "\xef\xbb\xbf" + "SELECT x FROM t" // UTF-8 BOM prefix, written as bytes
	for _, sql := range []string{"/* hint */ SELECT x FROM t", "-- c\nSELECT x FROM t", bomSelect} {
		body, _ := json.Marshal(map[string]string{"sql": sql})
		rec := mustOK(t, h, "/app/query", string(body))
		var resp struct {
			Rows [][]json.RawMessage `json:"rows"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if len(resp.Rows) != 3 {
			t.Errorf("sql %q: want 3 rows, got %d (%s)", sql, len(resp.Rows), rec.Body)
		}
	}
}

// TestAttachDeniedOverHTTP regresses the ATTACH filesystem-escape at the HTTP
// boundary: it must be 403, in single and batch requests.
func TestAttachDeniedOverHTTP(t *testing.T) {
	h := newHandlerDB(t, fileDB("app"))
	rec := post(t, h, "/app/query", `{"sql":"ATTACH DATABASE '/tmp/escaped.db' AS y"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ATTACH: want 403, got %d (%s)", rec.Code, rec.Body)
	}
	rec = post(t, h, "/app/query", `{"statements":[{"sql":"SELECT 1"},{"sql":"DETACH DATABASE y"}]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("batch DETACH: want 403, got %d (%s)", rec.Code, rec.Body)
	}
}

// TestNativeMultiStatementAttachDenied regresses the multi-statement ATTACH
// bypass: a leading SELECT hides the ATTACH from a keyword check, but the
// connection authorizer must still deny it at compile time.
func TestNativeMultiStatementAttachDenied(t *testing.T) {
	h := newHandlerDB(t, fileDB("app"))
	rec := post(t, h, "/app/query", `{"sql":"SELECT 1; ATTACH DATABASE '/tmp/native_evil.db' AS e"}`)
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("multi-statement ATTACH must be denied: %d %s", rec.Code, rec.Body)
	}
}

// TestMemoryPrivateSharesAcrossRequests regresses the private-:memory: footgun:
// with the pool pinned to one conn, writes are visible to later reads.
func TestMemoryPrivateSharesAcrossRequests(t *testing.T) {
	h := newHandlerDB(t, config.Database{Name: "mem", Backend: "memory"})
	mustOK(t, h, "/mem/query", `{"sql":"CREATE TABLE t(x)"}`)
	mustOK(t, h, "/mem/query", `{"sql":"INSERT INTO t VALUES(1)"}`)
	rec := mustOK(t, h, "/mem/query", `{"sql":"SELECT count(*) FROM t"}`)
	if !strings.Contains(rec.Body.String(), "[[1]]") {
		t.Fatalf("private memory not shared across requests (pool not pinned): %s", rec.Body)
	}
}

// TestReturningReturnsRows regresses the RETURNING row-loss.
func TestReturningReturnsRows(t *testing.T) {
	h := newHandlerDB(t, fileDB("app"))
	mustOK(t, h, "/app/query", `{"sql":"CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)"}`)
	rec := mustOK(t, h, "/app/query", `{"sql":"INSERT INTO t(v) VALUES('a'),('b') RETURNING id"}`)
	var resp struct {
		Rows [][]json.RawMessage `json:"rows"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Rows) != 2 {
		t.Fatalf("RETURNING dropped rows: %s", rec.Body)
	}
}

// TestReservedAndInvalidNamesRejected regresses reserved-name-via-host and
// path-segment escapes.
func TestReservedAndInvalidNamesRejected(t *testing.T) {
	h := newHandlerDB(t, fileDB("app"))
	for _, target := range []string{
		"http://_meta.q.local/query", // reserved name via host
		"http://query.q.local/query", // endpoint-token name via host
		"/../secret/query",           // .. path segment
	} {
		rec := post(t, h, target, `{"sql":"SELECT 1"}`)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d (%s)", target, rec.Code, rec.Body)
		}
	}
}

// TestTrailingContentRejected regresses the silent trailing-body drop.
func TestTrailingContentRejected(t *testing.T) {
	h := newHandlerDB(t, fileDB("app"))
	rec := post(t, h, "/app/query", `{"sql":"SELECT 1"} EXTRA`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for trailing content, got %d (%s)", rec.Code, rec.Body)
	}
}

// TestBatchFailedIndex regresses the missing failing-statement index.
func TestBatchFailedIndex(t *testing.T) {
	h := newHandlerDB(t, fileDB("app"))
	mustOK(t, h, "/app/query", `{"sql":"CREATE TABLE w(x INTEGER PRIMARY KEY)"}`)
	rec := mustOK(t, h, "/app/query",
		`{"statements":[{"sql":"INSERT INTO w VALUES(1)"},{"sql":"INSERT INTO w VALUES(1)"}]}`)
	var resp struct {
		Error       *struct{ Message string } `json:"error"`
		FailedIndex *int                      `json:"failed_index"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error == nil || resp.FailedIndex == nil || *resp.FailedIndex != 1 {
		t.Fatalf("want error with failed_index=1, got %s", rec.Body)
	}
}

// TestBatchReadReturnsRows regresses reads-in-batch returning empty.
func TestBatchReadReturnsRows(t *testing.T) {
	h := newHandlerDB(t, fileDB("app"))
	mustOK(t, h, "/app/query", `{"sql":"CREATE TABLE b(x INTEGER)"}`)
	rec := mustOK(t, h, "/app/query",
		`{"statements":[{"sql":"INSERT INTO b VALUES(5)"},{"sql":"SELECT x FROM b"}]}`)
	var resp struct {
		Results []struct {
			Rows         [][]json.RawMessage `json:"rows"`
			RowsAffected int64               `json:"rows_affected"`
		} `json:"results"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Results) != 2 {
		t.Fatalf("want 2 results, got %s", rec.Body)
	}
	if resp.Results[0].RowsAffected != 1 {
		t.Errorf("insert result: %+v", resp.Results[0])
	}
	if len(resp.Results[1].Rows) != 1 || string(resp.Results[1].Rows[0][0]) != "5" {
		t.Errorf("read in batch returned no rows: %s", rec.Body)
	}
}
