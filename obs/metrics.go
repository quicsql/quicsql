package obs

import (
	"fmt"
	"io"
	"maps"
	"sort"
	"sync"
	"time"
)

// Registry is the in-process metrics sink: request counters and latency sums per
// database, plus named gauges sampled on scrape. It satisfies Metrics and renders
// Prometheus text. It is safe for concurrent use.
//
// A single mutex guards the per-request counter bumps — fine at POC and moderate
// load (the critical section is one map write); shard by database or switch to
// per-database atomic counters if profiling ever shows contention at high QPS.
type Registry struct {
	mu       sync.Mutex
	requests map[string]int64         // db → total requests
	latSum   map[string]time.Duration // db → summed latency
	latCount map[string]int64         // db → observations
	gauges   map[string]func() int64  // name → live sampler
}

// NewRegistry builds an empty metrics registry.
func NewRegistry() *Registry {
	return &Registry{
		requests: map[string]int64{},
		latSum:   map[string]time.Duration{},
		latCount: map[string]int64{},
		gauges:   map[string]func() int64{},
	}
}

// IncRequests counts one request against a database. principal is accepted for
// the Metrics interface but not used as a label (unbounded cardinality).
func (r *Registry) IncRequests(db, _ string) {
	r.mu.Lock()
	r.requests[db]++
	r.mu.Unlock()
}

// ObserveLatency records a request's duration against a database.
func (r *Registry) ObserveLatency(db string, d time.Duration) {
	r.mu.Lock()
	r.latSum[db] += d
	r.latCount[db]++
	r.mu.Unlock()
}

// Forget drops a database's series (request count + latency) so a detached
// database stops appearing in scrapes and its maps don't grow unbounded across
// create/detach churn. Gauges are keyed by metric name, not db, so untouched.
func (r *Registry) Forget(db string) {
	r.mu.Lock()
	delete(r.requests, db)
	delete(r.latSum, db)
	delete(r.latCount, db)
	r.mu.Unlock()
}

// SetGauge registers a live gauge sampled at scrape time (e.g. active sessions,
// open databases). A nil sampler removes the gauge.
func (r *Registry) SetGauge(name string, sample func() int64) {
	r.mu.Lock()
	if sample == nil {
		delete(r.gauges, name)
	} else {
		r.gauges[name] = sample
	}
	r.mu.Unlock()
}

// WritePrometheus renders the registry in the Prometheus text exposition format
// (served as text/plain; version=0.0.4). It is deliberately NOT OpenMetrics (which
// needs application/openmetrics-text and a # EOF trailer). Series are emitted in
// sorted order so the output is stable.
func (r *Registry) WritePrometheus(w io.Writer) {
	r.mu.Lock()
	// Snapshot under the lock; sample gauges after releasing it (a sampler may take
	// its own locks — don't nest under r.mu).
	reqs := maps.Clone(r.requests)
	latSum := maps.Clone(r.latSum)
	latCount := maps.Clone(r.latCount)
	samplers := maps.Clone(r.gauges)
	r.mu.Unlock()

	// Build into a byte slice (fmt.Appendf has no error return) and write once.
	var b []byte
	b = append(b, "# TYPE requests_total counter\n"...)
	for _, db := range sortedKeys(reqs) {
		b = fmt.Appendf(b, "requests_total{db=%q} %d\n", db, reqs[db])
	}
	b = append(b, "# TYPE request_duration_seconds summary\n"...)
	for _, db := range sortedKeys(latCount) {
		b = fmt.Appendf(b, "request_duration_seconds_sum{db=%q} %g\n", db, latSum[db].Seconds())
		b = fmt.Appendf(b, "request_duration_seconds_count{db=%q} %d\n", db, latCount[db])
	}
	names := make([]string, 0, len(samplers))
	for name := range samplers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b = fmt.Appendf(b, "# TYPE %s gauge\n%s %d\n", name, name, samplers[name]())
	}
	_, _ = w.Write(b)
}

func sortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
