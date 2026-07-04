// Command remote-tour is a pure remote client that walks every quicSQL-reachable
// feature against a charged server, over TLS with mTLS. It self-verifies (non-zero
// exit on any miss), so it doubles as an end-to-end smoke test.
//
//	go run ./examples/remote-tour -addr your.host:7777
//
// It talks to examples/charged-server: same fixed dev credentials, derived on both
// sides from the shared internal/showcase package — nothing is copied at runtime.
// It uses only quicsql.net/client and the database/sql driver (no ORM), so it lives
// in the quicSQL module and works on any checkout. The LiteORM-over-quicSQL tour
// (models, typed search, sessions) lives with LiteORM.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	sqlite "gosqlite.org"
	"quicsql.net/client"
	_ "quicsql.net/client/sqldriver" // registers the "quicsql"/"sqlite" driver for driverSection
	"quicsql.net/examples/internal/showcase"
)

func main() {
	addr := flag.String("addr", "localhost:7777", "charged server h2/TLS address (host:port)")
	h3 := flag.String("h3", "", "h3/QUIC address (default: the -addr host, same port — h3 shares the h2 port)")
	flag.Parse()
	if err := run(*addr, *h3); err != nil {
		fmt.Fprintln(os.Stderr, "remote-tour:", err)
		os.Exit(1)
	}
}

func run(addr, h3addr string) error {
	ctx := context.Background()
	pool := showcase.CAPool()
	cert := showcase.ClientCert()
	if h3addr == "" {
		h3addr = addr // h3 shares the h2 port (TLS/TCP + QUIC/UDP on the same host:port)
	}
	fmt.Printf("\n\033[1mquicSQL remote tour\033[0m — every network-reachable feature, against %s (mTLS over TLS)\n", addr)

	// Main tour client: mTLS over h2/TLS → principal "tourist" (admin).
	mtls := client.H2TLS(addr, false, client.WithRootCA(pool), client.WithClientCert(cert))
	defer mtls.Close()

	ck := &checker{}
	opsSection(ctx, ck, mtls)
	txSection(ctx, ck, mtls)
	engineSection(ctx, ck, mtls)
	changesetSection(ctx, ck, mtls)
	blobSection(ctx, ck, mtls)
	driverSection(ctx, ck, addr)
	exportSection(ctx, ck, mtls)
	authMatrix(ctx, ck, addr, pool, cert)
	transportMatrix(ctx, ck, addr, h3addr, pool, cert)
	controlPlane(ctx, ck, addr, pool, cert)
	observability(ctx, ck, addr, pool, cert)

	fmt.Println()
	return ck.result()
}

// --- native CRUD + parameterized args + a constraint error over the wire ---

func opsSection(ctx context.Context, ck *checker, cl *client.Client) {
	section("native CRUD on the file DB (params + constraint errors over the wire)")
	ck.ok("create table", exec(ctx, cl, "app", `CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE)`))
	ck.ok("clear table", exec(ctx, cl, "app", `DELETE FROM users`))
	ck.ok("parameterized insert", exec(ctx, cl, "app", `INSERT INTO users(name, email) VALUES(?, ?)`, "Ada", "ada@x"))
	res, err := cl.Query(ctx, "app", `SELECT name FROM users WHERE email = ?`, "ada@x")
	ck.expect("parameterized query round-trip", err == nil && cell(res) == "Ada", fmt.Sprint(err))
	_, dup := cl.Exec(ctx, "app", `INSERT INTO users(name, email) VALUES(?, ?)`, "dup", "ada@x")
	ck.denied("UNIQUE violation surfaces as an error", dup)
}

// --- interactive transaction over the Hrana pipeline (commit + rollback) ---

func txSection(ctx context.Context, ck *checker, cl *client.Client) {
	section("interactive transaction over Hrana (one pinned connection)")
	_ = exec(ctx, cl, "app", `CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, bal INT)`)
	_ = exec(ctx, cl, "app", `DELETE FROM accounts`)
	_ = exec(ctx, cl, "app", `INSERT INTO accounts VALUES(1, 100), (2, 0)`)

	tx := cl.OpenStream("app")
	_, _ = tx.Exec(ctx, `BEGIN`, nil)
	_, _ = tx.Exec(ctx, `UPDATE accounts SET bal = bal - 10 WHERE id = 1`, nil)
	_, _ = tx.Exec(ctx, `UPDATE accounts SET bal = bal + 10 WHERE id = 2`, nil)
	_, _ = tx.Exec(ctx, `COMMIT`, nil)
	_ = tx.Close(ctx)
	ck.expect("COMMIT moved 10 across accounts", cellInt(ctx, cl, "app", `SELECT bal FROM accounts WHERE id = 2`) == 10, "")

	tx2 := cl.OpenStream("app")
	_, _ = tx2.Exec(ctx, `BEGIN`, nil)
	_, _ = tx2.Exec(ctx, `UPDATE accounts SET bal = 999 WHERE id = 1`, nil)
	_, _ = tx2.Exec(ctx, `ROLLBACK`, nil)
	_ = tx2.Close(ctx)
	ck.expect("ROLLBACK discarded the change", cellInt(ctx, cl, "app", `SELECT bal FROM accounts WHERE id = 1`) == 90, "")
}

// --- server-composed engine: custom function + bundled extensions, all via SQL ---

func engineSection(ctx context.Context, ck *checker, cl *client.Client) {
	section("server-composed engine (custom function + extensions, via SQL)")
	res, err := cl.Query(ctx, "app", `SELECT showcase_greet('tour')`)
	ck.expect("custom server function showcase_greet()", err == nil && cell(res) == "hello from quicSQL, tour", fmt.Sprint(err))
	res, err = cl.Query(ctx, "app", `SELECT 'foobar' REGEXP '^foo'`)
	ck.expect("REGEXP extension", err == nil && cell(res) == "1", fmt.Sprint(err))
	res, err = cl.Query(ctx, "app", `SELECT hex(sha256('quicsql'))`)
	ck.expect("hash extension (sha256)", err == nil && len(cell(res)) == 64, fmt.Sprint(err))
	// generate_series is a table-valued function whose ctor (xConnect) runs on
	// whichever pooled connection serves the query — the path that regressed with
	// SQLITE_MISUSE when the vtab ctor ran against the wrong connection. Exercising
	// it over the wire guards that fix.
	res, err = cl.Query(ctx, "app", `SELECT count(*) FROM generate_series(1, 100)`)
	ck.expect("generate_series table-valued function", err == nil && cell(res) == "100", fmt.Sprint(err))
	ck.ok("rtree virtual table", exec(ctx, cl, "cache", `CREATE VIRTUAL TABLE IF NOT EXISTS geo USING rtree(id, minx, maxx, miny, maxy)`))
	// Full-text search (fts5 is built in) — a MATCH query executed on the server.
	_ = exec(ctx, cl, "app", `CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(body)`)
	_ = exec(ctx, cl, "app", `DELETE FROM notes_fts`)
	_ = exec(ctx, cl, "app", `INSERT INTO notes_fts(body) VALUES('the quick brown fox'), ('a lazy dog sleeps')`)
	res, err = cl.Query(ctx, "app", `SELECT count(*) FROM notes_fts WHERE notes_fts MATCH 'fox'`)
	ck.expect("FTS5 full-text MATCH", err == nil && cell(res) == "1", fmt.Sprint(err))
}

// --- SESSION / changeset over the wire (capture → invert → apply → concat) ---

func changesetSection(ctx context.Context, ck *checker, cl *client.Client) {
	section("SESSION / changeset over the wire (capture → invert → apply → concat)")
	_ = exec(ctx, cl, "app", `CREATE TABLE IF NOT EXISTS tags(id INTEGER PRIMARY KEY, name TEXT)`)
	_ = exec(ctx, cl, "app", `DELETE FROM tags`)

	// Capture two inserts as a changeset on a pinned stream.
	st := cl.OpenStream("app")
	if err := st.SessionStart(ctx, []string{"tags"}); err != nil {
		ck.expect("start changeset capture", false, err.Error())
		_ = st.Close(ctx)
		return
	}
	_, _ = st.Exec(ctx, `INSERT INTO tags(name) VALUES('urgent')`, nil)
	_, _ = st.Exec(ctx, `INSERT INTO tags(name) VALUES('later')`, nil)
	cs, err := st.SessionChangeset(ctx)
	_ = st.Close(ctx)
	ck.expect("capture 2 inserts", err == nil && len(cs) > 0 && cellInt(ctx, cl, "app", `SELECT count(*) FROM tags`) == 2, fmt.Sprint(err))

	inv, err := cl.InvertChangeset(ctx, "app", cs)
	ck.ok("invert changeset", err)
	ck.ok("apply inverse (undo)", cl.ApplyChangeset(ctx, "app", inv))
	ck.expect("undo emptied the table", cellInt(ctx, cl, "app", `SELECT count(*) FROM tags`) == 0, "")
	ck.ok("replay original", cl.ApplyChangeset(ctx, "app", cs))
	ck.expect("replay restored the rows", cellInt(ctx, cl, "app", `SELECT count(*) FROM tags`) == 2, "")
	_, err = cl.ConcatChangesets(ctx, "app", cs, inv)
	ck.expect("concat two changesets", err == nil, fmt.Sprint(err))
}

// --- large objects streamed over the wire (past the 8 MiB request cap) ---

func blobSection(ctx context.Context, ck *checker, cl *client.Client) {
	section("large objects (blobstore, streamed over the wire)")
	ck.ok("provision store", cl.BlobProvision(ctx, "app", "attachments", 0, "", false))
	id, err := cl.BlobCreate(ctx, "app", "attachments")
	ck.ok("create object", err)
	payload := bytes.Repeat([]byte("quicsql streams large objects — "), 400_000) // ~12 MiB, > the 8 MiB request cap
	n, err := cl.BlobWrite(ctx, "app", "attachments", id, bytes.NewReader(payload))
	ck.expect("write ~12 MiB (streamed)", err == nil && n == int64(len(payload)), fmt.Sprint(err))
	got, err := cl.BlobRead(ctx, "app", "attachments", id)
	ck.expect("read round-trips byte-identical", err == nil && bytes.Equal(got, payload), fmt.Sprint(err))
	sz, err := cl.BlobSize(ctx, "app", "attachments", id)
	ck.expect("size matches", err == nil && sz == int64(len(payload)), fmt.Sprint(err))
	ck.ok("delete frees the object", cl.BlobDelete(ctx, "app", "attachments", id))
}

// --- database/sql driver (both driver names, over TLS) ---

func driverSection(ctx context.Context, ck *checker, addr string) {
	section("database/sql driver (quicsql:// over TLS)")
	// A DSN can't carry an mTLS cert, so the driver path uses bearer over TLS with
	// insecure=1 for the dev cert (use OpenConnectorClient for CA/mTLS, as elsewhere).
	// The driver refuses a credential over an unverified channel by default; this is a
	// trusted local link with the dev cert, so allow_insecure_auth=1 opts in knowingly.
	dsn := "quicsql://" + addr + "/app?transport=h2&insecure=1&allow_insecure_auth=1&token=" + showcase.Token
	db, err := sql.Open("quicsql", dsn)
	if err == nil {
		defer db.Close()
		var n int
		err = db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	}
	ck.expect(`sql.Open("quicsql", …)`, err == nil, fmt.Sprint(err))
	// The gosqlite dispatch hook: the built-in "sqlite" driver opens quicsql:// too.
	hookDB, err := sql.Open("sqlite", dsn)
	if err == nil {
		defer hookDB.Close()
		var one int
		err = hookDB.QueryRowContext(ctx, `SELECT 1`).Scan(&one)
	}
	ck.expect(`sql.Open("sqlite", "quicsql://…") (hook)`, err == nil, fmt.Sprint(err))
}

// --- export an encrypted+compressed vault DB, decrypted, and verify ---

func exportSection(ctx context.Context, ck *checker, cl *client.Client) {
	section("export the encrypted+compressed vault DB (decrypted image)")
	if err := exec(ctx, cl, "catalog", `CREATE TABLE IF NOT EXISTS item(id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		ck.expect("seed vault catalog", false, err.Error())
		return
	}
	_ = exec(ctx, cl, "catalog", `DELETE FROM item`)
	_ = exec(ctx, cl, "catalog", `INSERT INTO item(name) VALUES('vaulted')`)
	data, err := cl.Export(ctx, "catalog")
	if err != nil || !bytes.HasPrefix(data, []byte("SQLite format 3\x00")) {
		ck.expect("export returns a SQLite image", false, fmt.Sprint(err))
		return
	}
	// Deserialize the decrypted image into a fresh LOCAL db and read it back.
	local, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		ck.expect("open local", false, err.Error())
		return
	}
	defer local.Close()
	local.SetMaxOpenConns(1)
	if err := sqlite.Deserialize(ctx, local, data); err != nil {
		ck.expect("deserialize exported vault image", false, err.Error())
		return
	}
	var name string
	err = local.QueryRowContext(ctx, `SELECT name FROM item`).Scan(&name)
	ck.expect("exported vault decrypts to the row we wrote", err == nil && name == "vaulted", fmt.Sprint(err))
}

// --- auth matrix ---

func authMatrix(ctx context.Context, ck *checker, addr string, pool *x509.CertPool, cert tls.Certificate) {
	section("auth matrix (each method + a denial), all over TLS")
	priv, line := showcase.AuthKey()

	bearer := client.H2TLS(addr, false, client.WithRootCA(pool), client.WithBearer(showcase.Token))
	defer bearer.Close()
	_, err := bearer.Query(ctx, "app", `SELECT 1`)
	ck.ok("bearer → tourist reads app", err)

	pw := client.H2TLS(addr, false, client.WithRootCA(pool), client.WithBasicAuth(showcase.User, showcase.Password))
	defer pw.Close()
	_, err = pw.Query(ctx, "app", `SELECT 1`)
	ck.ok("password → analyst reads app", err)
	_, werr := pw.Exec(ctx, "app", `CREATE TABLE nope(x)`)
	ck.denied("password/analyst write on app (read-only)", werr)

	mtls := client.H2TLS(addr, false, client.WithRootCA(pool), client.WithClientCert(cert))
	defer mtls.Close()
	_, err = mtls.Query(ctx, "catalog", `SELECT 1`)
	ck.ok("mTLS → tourist reads the vault catalog (admin)", err)

	signer := client.H2TLS(addr, false, client.WithRootCA(pool), client.WithEd25519(line, priv))
	defer signer.Close()
	_, err = signer.Exec(ctx, "app", `CREATE TABLE IF NOT EXISTS signer_touch(x)`)
	ck.ok("ed25519 keyring → signer writes app", err)

	bad := client.H2TLS(addr, false, client.WithRootCA(pool), client.WithBearer("wrong-token"))
	defer bad.Close()
	_, err = bad.Query(ctx, "app", `SELECT 1`)
	ck.denied("wrong bearer token → 401", err)
}

// --- transport matrix ---

func transportMatrix(ctx context.Context, ck *checker, addr, h3addr string, pool *x509.CertPool, cert tls.Certificate) {
	section("transport matrix (same query over h2 and h3)")
	h2 := client.H2TLS(addr, false, client.WithRootCA(pool), client.WithClientCert(cert))
	defer h2.Close()
	_, err := h2.Query(ctx, "app", `SELECT 1`)
	ck.ok("h2 (TLS)", err)
	h3 := client.H3(h3addr, false, client.WithRootCA(pool), client.WithClientCert(cert))
	defer h3.Close()
	_, err = h3.Query(ctx, "app", `SELECT 1`)
	ck.ok("h3 (QUIC/TLS)", err)
}

// --- control plane ---

func controlPlane(ctx context.Context, ck *checker, addr string, pool *x509.CertPool, cert tls.Certificate) {
	section("control plane /_admin (admin only) + vault maintenance")
	hc := adminHTTP(pool, cert)
	base := "https://" + addr
	code, _ := postJSON(ctx, hc, base+"/_admin/create", `{"database":{"name":"scratch","backend":"memory-shared"},"grants":[{"principal":"tourist","level":"read-write"}]}`)
	ck.expect("create a database", code == 200, fmt.Sprintf("HTTP %d", code))
	code, body := getURL(ctx, hc, base+"/_admin/databases")
	ck.expect("list databases includes it", code == 200 && strings.Contains(body, "scratch"), fmt.Sprintf("HTTP %d", code))
	code, _ = postJSON(ctx, hc, base+"/_admin/maintenance", `{"database":"catalog","op":"trim"}`)
	ck.expect("vault maintenance (trim) over the wire", code == 200, fmt.Sprintf("HTTP %d", code))
}

// --- observability ---

func observability(ctx context.Context, ck *checker, addr string, pool *x509.CertPool, cert tls.Certificate) {
	section("observability (/_metrics)")
	hc := adminHTTP(pool, cert)
	code, body := getURL(ctx, hc, "https://"+addr+"/_metrics")
	ck.expect("scrape /_metrics (Prometheus text)", code == 200 && strings.Contains(body, "quicsql_requests_total"), fmt.Sprintf("HTTP %d", code))
}

// --- helpers ---

func exec(ctx context.Context, cl *client.Client, db, sql string, args ...any) error {
	_, err := cl.Exec(ctx, db, sql, args...)
	return err
}

func cell(res *client.Result) string {
	if res == nil || len(res.Rows) == 0 || len(res.Rows[0]) == 0 {
		return ""
	}
	return fmt.Sprint(res.Rows[0][0])
}

func cellInt(ctx context.Context, cl *client.Client, db, sql string) int {
	res, err := cl.Query(ctx, db, sql)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(cell(res))
	if err != nil {
		return -1
	}
	return n
}

func adminHTTP(pool *x509.CertPool, cert tls.Certificate) *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
		ForceAttemptHTTP2: true,
	}}
}

func postJSON(ctx context.Context, hc *http.Client, url, body string) (int, string) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return doHTTP(hc, req)
}

func getURL(ctx context.Context, hc *http.Client, url string) (int, string) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return doHTTP(hc, req)
}

func doHTTP(hc *http.Client, req *http.Request) (int, string) {
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func section(title string) { fmt.Printf("\n\033[1m▸ %s\033[0m\n", title) }

// --- checker ---

type checker struct{ failures int }

func (c *checker) ok(label string, err error) {
	if err != nil {
		c.failures++
		fmt.Printf("    ✗ %-52s FAILED: %s\n", label, short(err))
	} else {
		fmt.Printf("    ✓ %-52s ok\n", label)
	}
}

func (c *checker) denied(label string, err error) {
	if err == nil {
		c.failures++
		fmt.Printf("    ✗ %-52s WRONGLY ALLOWED\n", label)
	} else {
		fmt.Printf("    ✓ %-52s denied (%s)\n", label, short(err))
	}
}

func (c *checker) expect(label string, pass bool, detail string) {
	if pass {
		fmt.Printf("    ✓ %-52s ok\n", label)
	} else {
		c.failures++
		fmt.Printf("    ✗ %-52s FAILED (%s)\n", label, detail)
	}
}

func (c *checker) result() error {
	if c.failures > 0 {
		return fmt.Errorf("%d check(s) failed", c.failures)
	}
	fmt.Println("  ✓ every quicSQL-reachable feature held.")
	return nil
}

func short(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	return s
}
