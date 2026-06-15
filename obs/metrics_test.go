package obs

import (
	"strings"
	"testing"
	"time"
)

func TestRegistryOpenMetrics(t *testing.T) {
	r := NewRegistry()
	r.IncRequests("sales", "app")
	r.IncRequests("sales", "app")
	r.IncRequests("logs", "app")
	r.ObserveLatency("sales", 200*time.Millisecond)
	r.SetGauge("quicsql_active_sessions", func() int64 { return 3 })

	var b strings.Builder
	r.WriteOpenMetrics(&b)
	out := b.String()

	for _, want := range []string{
		`quicsql_requests_total{db="sales"} 2`,
		`quicsql_requests_total{db="logs"} 1`,
		`quicsql_request_duration_seconds_count{db="sales"} 1`,
		"# TYPE quicsql_active_sessions gauge",
		"quicsql_active_sessions 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, out)
		}
	}
}

func TestRegistryIsMetrics(t *testing.T) {
	// The registry satisfies the Metrics interface and the Exposer interface.
	var _ Metrics = NewRegistry()
	var _ Exposer = NewRegistry()
}
