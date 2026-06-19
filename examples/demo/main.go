// Command demo is a fully self-contained, runnable quicSQL example: it starts an
// in-process server (via serverd) with several databases across every transport,
// runs real-life operations against each database through the Go client, shows a
// Hrana interactive transaction, and then benchmarks request throughput (RPS /
// RPM) on each protocol.
//
//	go run ./examples/demo            # default 2s benchmark, 16 workers
//	go run ./examples/demo -dur 5s -workers 64
//
// Everything runs on loopback with a temp data directory that is removed on exit;
// no external setup is required.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"quicsql.net/client"
	"quicsql.net/config"
	"quicsql.net/serverd"
)

func main() {
	dur := flag.Duration("dur", 2*time.Second, "benchmark duration per protocol")
	workers := flag.Int("workers", 16, "concurrent workers per protocol")
	verbose := flag.Bool("v", false, "verbose server logs")
	flag.Parse()

	if err := run(*dur, *workers, *verbose); err != nil {
		fmt.Fprintln(os.Stderr, "demo failed:", err)
		os.Exit(1)
	}
}

// addrs holds the picked loopback addresses for each transport.
type addrs struct {
	h1, h2c, h2, h3, sock string
}

func run(dur time.Duration, workers int, verbose bool) error {
	dataDir, err := os.MkdirTemp("", "quicsql-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dataDir)

	keysDir := filepath.Join(dataDir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(keysDir, "orders"), key, 0o600); err != nil {
		return err
	}

	a := addrs{
		h1:   freeTCP(),
		h2c:  freeTCP(),
		h2:   freeTCP(),
		h3:   freeUDP(),
		sock: filepath.Join(dataDir, "quicsql.sock"),
	}

	logLevel := slog.LevelWarn
	if verbose {
		logLevel = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	cfg := buildConfig(dataDir, keysDir, a)
	srv, err := serverd.Run(cfg, log)
	if err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	banner("quicSQL demo — server up", fmt.Sprintf(
		"data_dir=%s\n  HTTP/1.1  http://%s\n  h2c       http://%s\n  HTTP/2    https://%s\n  HTTP/3    https://%s (QUIC/UDP)\n  Unix      %s\n  databases: users (file/WAL), orders (vault: encrypted+compressed), cache (shared in-memory)",
		dataDir, a.h1, a.h2c, a.h2, a.h3, a.sock))

	if err := waitReady(a.h1); err != nil {
		return err
	}

	ctx := context.Background()
	h1 := client.H1(a.h1)
	defer h1.Close()

	if err := usersScenario(ctx, h1); err != nil {
		return err
	}
	if err := ordersScenario(ctx, h1); err != nil {
		return err
	}
	if err := cacheScenario(ctx, a); err != nil {
		return err
	}
	if err := hranaTxScenario(ctx, a.h1); err != nil {
		return err
	}

	return benchmark(ctx, a, dur, workers)
}

func buildConfig(dataDir, keysDir string, a addrs) *config.Config {
	return &config.Config{
		Server:  config.Server{DataDir: dataDir},
		Secrets: []config.SecretSource{{Name: "keys", Type: "file", Dir: keysDir}},
		TLS: map[string]config.TLSProfile{
			"dev": {Mode: "self_signed", Hosts: []string{"localhost", "127.0.0.1"}},
		},
		Listeners: []config.Listener{
			{Name: "h1", Transport: "h1", Address: a.h1},
			{Name: "h2c", Transport: "h2c", Address: a.h2c},
			{Name: "h2", Transport: "h2", Address: a.h2, TLS: "dev"},
			{Name: "h3", Transport: "h3", Address: a.h3, TLS: "dev"},
			{Name: "unix", Transport: "unix", Address: a.sock, SocketMode: "0600"},
		},
		Databases: []config.Database{
			{Name: "users", Backend: "file", Path: "users.db", Mode: "rwc", Pragmas: map[string]any{"journal_mode": "WAL"}},
			{Name: "orders", Backend: "vault", Path: "orders.vault", Mode: "rwc",
				Vault: &config.VaultConfig{Key: "keys:orders", Compression: "default"}},
			{Name: "cache", Backend: "memory-shared"},
		},
		Limits: config.Limits{StatementTimeout: 30 * time.Second, MaxConcurrentPerDB: 512},
	}
}

// --- real-life scenarios ---

func usersScenario(ctx context.Context, c *client.Client) error {
	banner("users (plain file, WAL)", "create → insert → query → update")
	stmts := []string{
		`CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, active INT)`,
	}
	for _, s := range stmts {
		if _, err := c.Exec(ctx, "users", s); err != nil {
			return fmt.Errorf("users schema: %w", err)
		}
	}
	people := []struct {
		name, email string
	}{{"Ada Lovelace", "ada@example.com"}, {"Alan Turing", "alan@example.com"}, {"Grace Hopper", "grace@example.com"}}
	for _, p := range people {
		if _, err := c.Exec(ctx, "users", `INSERT INTO users(name, email, active) VALUES(?,?,1)`, p.name, p.email); err != nil {
			return fmt.Errorf("insert %s: %w", p.name, err)
		}
	}
	res, err := c.Query(ctx, "users", `SELECT id, name, email FROM users ORDER BY id`)
	if err != nil {
		return err
	}
	for _, row := range res.Rows {
		fmt.Printf("    #%v  %-14v %v\n", row[0], row[1], row[2])
	}
	if _, err := c.Exec(ctx, "users", `UPDATE users SET active=0 WHERE email=?`, "alan@example.com"); err != nil {
		return err
	}
	cnt, err := c.Query(ctx, "users", `SELECT count(*) FROM users WHERE active=1`)
	if err != nil {
		return err
	}
	fmt.Printf("    active users after deactivating one: %v\n", cnt.Rows[0][0])
	return nil
}

func ordersScenario(ctx context.Context, c *client.Client) error {
	banner("orders (vault: encrypted + compressed at rest)", "seed catalog → place orders → per-user totals")
	for _, s := range []string{
		`CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price_cents INT)`,
		`CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, product_id INT, qty INT)`,
	} {
		if _, err := c.Exec(ctx, "orders", s); err != nil {
			return fmt.Errorf("orders schema: %w", err)
		}
	}
	products := []struct {
		name  string
		cents int
	}{{"Analytical Engine", 990000}, {"Punch Card (1k)", 500}, {"Bombe Rotor", 12500}}
	for _, p := range products {
		if _, err := c.Exec(ctx, "orders", `INSERT INTO products(name, price_cents) VALUES(?,?)`, p.name, p.cents); err != nil {
			return err
		}
	}
	orders := [][3]int{{1, 1, 1}, {1, 2, 10}, {3, 2, 50}, {3, 3, 2}}
	for _, o := range orders {
		if _, err := c.Exec(ctx, "orders", `INSERT INTO orders(user_id, product_id, qty) VALUES(?,?,?)`, o[0], o[1], o[2]); err != nil {
			return err
		}
	}
	res, err := c.Query(ctx, "orders", `
		SELECT o.user_id, SUM(p.price_cents * o.qty) AS total_cents, COUNT(*) AS lines
		FROM orders o JOIN products p ON p.id = o.product_id
		GROUP BY o.user_id ORDER BY total_cents DESC`)
	if err != nil {
		return err
	}
	for _, row := range res.Rows {
		fmt.Printf("    user #%v: %v line(s), total_cents=%v (persisted encrypted+compressed)\n", row[0], row[2], row[1])
	}
	return nil
}

func cacheScenario(ctx context.Context, a addrs) error {
	banner("cache (shared in-memory)", "one session writes, another reads it — no disk")
	// Two independent clients over two different transports share the same in-memory db.
	writer := client.Unix(a.sock)
	defer writer.Close()
	reader := client.H1(a.h1)
	defer reader.Close()

	if _, err := writer.Exec(ctx, "cache", `CREATE TABLE cache(k TEXT PRIMARY KEY, v TEXT)`); err != nil {
		return fmt.Errorf("cache schema: %w", err)
	}
	if _, err := writer.Exec(ctx, "cache", `INSERT INTO cache VALUES('session','shared across connections')`); err != nil {
		return err
	}
	res, err := reader.Query(ctx, "cache", `SELECT v FROM cache WHERE k='session'`)
	if err != nil {
		return err
	}
	if len(res.Rows) == 1 {
		fmt.Printf("    reader (HTTP/1.1) sees writer's (Unix socket) value: %q\n", res.Rows[0][0])
	} else {
		return fmt.Errorf("shared in-memory not visible across sessions")
	}
	return nil
}

// hranaTxScenario runs a libSQL Hrana pipeline: an interactive transaction
// (BEGIN … INSERT … COMMIT) on a single pinned connection, all-or-nothing.
func hranaTxScenario(ctx context.Context, h1 string) error {
	banner("interactive transaction (libSQL Hrana pipeline)", "BEGIN → INSERT×2 → COMMIT on one pinned connection")
	pipeline := `{"requests":[
		{"type":"execute","stmt":{"sql":"BEGIN"}},
		{"type":"execute","stmt":{"sql":"INSERT INTO users(name,email,active) VALUES('Katherine Johnson','katherine@example.com',1)"}},
		{"type":"execute","stmt":{"sql":"INSERT INTO users(name,email,active) VALUES('Margaret Hamilton','margaret@example.com',1)"}},
		{"type":"execute","stmt":{"sql":"COMMIT"}},
		{"type":"close"}
	]}`
	resp, err := http.Post("http://"+h1+"/users/v3/pipeline", "application/json", strings.NewReader(pipeline))
	if err != nil {
		return fmt.Errorf("hrana pipeline: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hrana pipeline: %s: %s", resp.Status, body)
	}
	c := client.H1(h1)
	defer c.Close()
	total, err := c.Query(ctx, "users", `SELECT count(*) FROM users`)
	if err != nil {
		return err
	}
	fmt.Printf("    committed; users table now has %v rows\n", total.Rows[0][0])
	return nil
}

// --- benchmark ---

type protoClient struct {
	name string
	c    *client.Client
}

func benchmark(ctx context.Context, a addrs, dur time.Duration, workers int) error {
	banner("benchmark", fmt.Sprintf("%s per protocol, %d workers, query: SELECT 1", dur, workers))
	protos := []protoClient{
		{"HTTP/1.1", client.H1(a.h1)},
		{"h2c", client.H2C(a.h2c)},
		{"HTTP/2 (TLS)", client.H2TLS(a.h2, true)},
		{"HTTP/3 (QUIC)", client.H3(a.h3, true)},
		{"Unix socket", client.Unix(a.sock)},
	}
	fmt.Printf("    %-16s %10s %12s %12s %10s %10s\n", "protocol", "requests", "req/s", "req/min", "p50", "p99")
	for _, p := range protos {
		r := benchOne(ctx, p.c, dur, workers)
		p.c.Close()
		if r.err != nil {
			fmt.Printf("    %-16s  ERROR: %v\n", p.name, r.err)
			continue
		}
		fmt.Printf("    %-16s %10d %12.0f %12.0f %10s %10s\n",
			p.name, r.count, r.rps, r.rps*60, r.p50.Round(time.Microsecond), r.p99.Round(time.Microsecond))
	}
	return nil
}

type benchResult struct {
	count    int64
	rps      float64
	p50, p99 time.Duration
	err      error
}

func benchOne(ctx context.Context, c *client.Client, dur time.Duration, workers int) benchResult {
	// Warm up + fail fast if this protocol can't round-trip at all.
	if _, err := c.Query(ctx, "users", "SELECT 1"); err != nil {
		return benchResult{err: err}
	}
	deadline := time.Now().Add(dur)
	var count int64
	var mu sync.Mutex
	var lat []time.Duration
	var wg sync.WaitGroup
	start := time.Now()
	for range workers {
		wg.Go(func() {
			var local []time.Duration
			for time.Now().Before(deadline) {
				t0 := time.Now()
				if _, err := c.Query(ctx, "users", "SELECT 1"); err != nil {
					continue
				}
				local = append(local, time.Since(t0))
				atomic.AddInt64(&count, 1)
			}
			mu.Lock()
			lat = append(lat, local...)
			mu.Unlock()
		})
	}
	wg.Wait()
	elapsed := time.Since(start)
	slices.Sort(lat)
	return benchResult{
		count: count,
		rps:   float64(count) / elapsed.Seconds(),
		p50:   pct(lat, 50),
		p99:   pct(lat, 99),
	}
}

func pct(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := p * len(sorted) / 100
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// --- helpers ---

func banner(title, sub string) {
	fmt.Printf("\n\033[1m▸ %s\033[0m\n  %s\n", title, sub)
}

func freeTCP() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func freeUDP() string {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer c.Close()
	return c.LocalAddr().String()
}

func waitReady(h1 string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + h1 + "/_health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("server did not become ready at %s", h1)
}
