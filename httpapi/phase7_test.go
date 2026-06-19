package httpapi_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/engine"
	"quicsql.net/httpapi"
	"quicsql.net/limits"
	"quicsql.net/obs"
	"quicsql.net/registry"
	"quicsql.net/secret"
)

func obsHandler(t *testing.T, opts ...httpapi.Option) *httpapi.Handler {
	t.Helper()
	sec, _ := secret.New(nil)
	be, err := backend.For(config.Database{Name: "app", Backend: "memory-shared"}, sec, "")
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{"app": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	base := []httpapi.Option{}
	base = append(base, opts...)
	return httpapi.New(reg, engine.New(0, 0), config.Routing{ByPath: true}, base...)
}

func TestMetricsEndpoint(t *testing.T) {
	reg := obs.NewRegistry()
	h := obsHandler(t, httpapi.WithMetrics(reg))
	// A couple of data-plane requests are counted.
	mustOK(t, h, "/app/query", `{"sql":"SELECT 1"}`)
	mustOK(t, h, "/app/query", `{"sql":"SELECT 1"}`)

	rec := do(t, h, http.MethodGet, "/_metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/_metrics: status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `quicsql_requests_total{db="app"} 2`) {
		t.Fatalf("request counter missing/wrong: %s", body)
	}
}

func TestMetricsDisabled(t *testing.T) {
	h := obsHandler(t) // no WithMetrics
	if rec := do(t, h, http.MethodGet, "/_metrics", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("/_metrics without metrics: got %d, want 404", rec.Code)
	}
}

func TestRateLimit429(t *testing.T) {
	// A tiny refill rate: the burst of 1 is admitted, the next is 429.
	h := obsHandler(t, httpapi.WithLimiter(limits.New(0.001, 0)))
	if rec := post(t, h, "/app/query", `{"sql":"SELECT 1"}`); rec.Code != http.StatusOK {
		t.Fatalf("first request: got %d (%s)", rec.Code, rec.Body)
	}
	if rec := post(t, h, "/app/query", `{"sql":"SELECT 1"}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429 (%s)", rec.Code, rec.Body)
	}
}

// TestRunawayQueryKilledByTimeout regresses the statement-timeout backstop: an
// unbounded recursive CTE is interrupted by the per-statement deadline rather
// than running forever (the same ctx path a client disconnect drives).
func TestRunawayQueryKilledByTimeout(t *testing.T) {
	h := obsHandler(t, httpapi.WithStatementTimeout(150*time.Millisecond))
	runaway := `{"sql":"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c"}`
	done := make(chan *responseRecorder, 1)
	go func() { done <- rec2(t, h, runaway) }()
	select {
	case rec := <-done:
		// It must NOT be a clean success — either a 504 timeout or an error envelope.
		if rec.Code == http.StatusOK && !strings.Contains(rec.Body, "error") {
			t.Fatalf("runaway query returned a clean result: %d %s", rec.Code, rec.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runaway query was not interrupted within 5s")
	}
}

// responseRecorder + rec2 avoid sharing httptest.ResponseRecorder across the
// goroutine boundary with the *testing.T helpers (which call t.Fatalf).
type responseRecorder struct {
	Code int
	Body string
}

func rec2(t *testing.T, h http.Handler, body string) *responseRecorder {
	rec := post(t, h, "/app/query", body)
	return &responseRecorder{Code: rec.Code, Body: rec.Body.String()}
}
