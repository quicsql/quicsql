// Command auth is a runnable demonstration of every quicSQL authentication method
// and every authorization level. It starts an in-process server configured with a
// principal per method (no-auth, Unix peer-credentials, bearer, HTTP-basic
// password, mTLS, and the ed25519 challenge/response) and per-database grants at
// each level (none / read-only / read-write / admin), then connects with each
// credential and prints, as a matrix, which operations are allowed and which are
// denied — including the wrong-credential and wrong-level denial paths and the
// admin-only control plane.
//
//	go run ./examples/auth
//
// Everything runs on loopback with a temp data directory removed on exit. It
// exits non-zero if any expectation fails, so it doubles as a smoke test.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"quicsql.net/client"
	"quicsql.net/config"
	"quicsql.net/serverd"
)

// creds holds every credential the demo mints and shares between the server
// config and the clients.
type creds struct {
	token     string // bearer secret
	tokenHash string // sha256 hex, stored in config
	password  string
	pwHash    string // bcrypt, stored in config
	caPEMPath string // client-CA bundle for the mTLS listener
	opsCert   tls.Certificate
	strayCert tls.Certificate // signed by a different CA — should be refused
	edPubLine string          // ssh-ed25519 authorized_keys line, stored in config
	edPriv    ed25519.PrivateKey
	uid       int
}

func main() {
	tlsMode := flag.Bool("tls", false, "carry the credential methods (bearer/password/keyring/none) over a TLS h2 listener instead of cleartext HTTP/1.1 — the production-shaped path")
	flag.Parse()
	if err := run(*tlsMode); err != nil {
		fmt.Fprintln(os.Stderr, "auth demo:", err)
		os.Exit(1)
	}
}

func run(tlsMode bool) error {
	dataDir, err := os.MkdirTemp("", "quicsql-auth-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dataDir)

	cr, err := mintCreds(dataDir)
	if err != nil {
		return err
	}
	h2, sock := freeTCP(), filepath.Join(dataDir, "q.sock")
	cc := credConn{addr: freeTCP(), tls: tlsMode, scheme: "http"}
	if tlsMode {
		cc.scheme = "https"
	}
	cfg := buildConfig(dataDir, cr, cc, h2, sock)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, err := serverd.Run(cfg, log)
	if err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	if err := waitReady(cc); err != nil {
		return err
	}

	credProto := "h1 (cleartext)"
	if cc.tls {
		credProto = "h2 (TLS, server-auth)"
	}
	banner("quicSQL auth/authz demo",
		fmt.Sprintf("data (file) grants: app=read-write, analyst=read-only, ops=admin, signer=read-write, localdev=read-write, *=none\n  public (memory) grants: *=read-only\n  listeners: credentials %s=%s [bearer,password,keyring,none]  mtls h2=%s [mtls]  unix=%s [peercred,none]", credProto, cc.addr, h2, sock))

	ck := &checker{}
	ctx := context.Background()

	// Seed the schema as the read-write bearer principal.
	app := cc.client(client.WithBearer(cr.token))
	defer app.Close()
	if _, err := app.Exec(ctx, "data", `CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		return fmt.Errorf("seed schema: %w", err)
	}
	// Seed the read-only public database (app holds read-write there).
	if _, err := app.Exec(ctx, "public", `CREATE TABLE note(v TEXT)`); err != nil {
		return fmt.Errorf("seed public: %w", err)
	}
	if _, err := app.Exec(ctx, "public", `INSERT INTO note VALUES('hello from app')`); err != nil {
		return fmt.Errorf("seed public row: %w", err)
	}

	noAuthSection(ctx, ck, cc)
	bearerSection(ctx, ck, cc, cr, app)
	passwordSection(ctx, ck, cc, cr)
	keyringSection(ctx, ck, cc, cr)
	mtlsSection(ctx, ck, h2, cr)
	peercredSection(ctx, ck, sock, cr)
	authzRecap(ctx, ck, cc, cr)
	controlPlaneSection(ck, h2, cc, cr)

	fmt.Println()
	return ck.result()
}

// credConn is how the demo reaches the listener that carries the credential-based
// methods (bearer / password / keyring / none). It is cleartext HTTP/1.1 by
// default, or a server-authenticated TLS h2 listener under -tls — the shape you
// would actually deploy, since those methods send a secret on every request.
type credConn struct {
	addr   string // host:port
	scheme string // "http" | "https"
	tls    bool
}

// client builds a native client to the credential listener over the right transport.
func (cc credConn) client(opts ...client.Option) *client.Client {
	if cc.tls {
		return client.H2TLS(cc.addr, true, opts...) // insecure: trust the dev self-signed cert
	}
	return client.H1(cc.addr, opts...)
}

func (cc credConn) url() string { return cc.scheme + "://" + cc.addr }

// httpClient is a raw *http.Client to the credential listener, used for the
// control-plane endpoints that aren't part of the SQL client surface.
func (cc credConn) httpClient() *http.Client {
	if cc.tls {
		return &http.Client{Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
			ForceAttemptHTTP2: true,
		}, Timeout: 5 * time.Second}
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func buildConfig(dataDir string, cr creds, cc credConn, h2, sock string) *config.Config {
	// The mTLS listener always needs its client-CA profile ("m"). Under -tls the
	// credential listener gets a server-only profile ("s") — no client CA, so it
	// presents a cert but does not demand one, and bearer/password/keyring ride
	// over the encrypted channel.
	tlsProfiles := map[string]config.TLSProfile{
		"m": {Mode: "self_signed", Hosts: []string{"localhost", "127.0.0.1"}, ClientCA: cr.caPEMPath},
	}
	local := config.Listener{Name: "local", Transport: "h1", Address: cc.addr, Auth: []string{"bearer", "password", "keyring", "none"}}
	if cc.tls {
		tlsProfiles["s"] = config.TLSProfile{Mode: "self_signed", Hosts: []string{"localhost", "127.0.0.1"}}
		local.Transport, local.TLS = "h2", "s"
	}
	return &config.Config{
		Server: config.Server{DataDir: dataDir, MetaStore: config.MetaStore{Backend: "file", Path: "_meta.db"}},
		TLS:    tlsProfiles,
		Listeners: []config.Listener{
			local,
			{Name: "mtls", Transport: "h2", Address: h2, TLS: "m", Auth: []string{"mtls"}},
			{Name: "unix", Transport: "unix", Address: sock, SocketMode: "0600", Auth: []string{"peercred", "none"}},
		},
		Auth: config.Auth{Principals: []config.Principal{
			{Name: "app", Methods: []map[string]any{{"bearer": map[string]any{"token_hash": cr.tokenHash}}}},
			{Name: "analyst", Methods: []map[string]any{{"password": map[string]any{"user": "analyst", "password_hash": cr.pwHash}}}},
			{Name: "ops", Methods: []map[string]any{{"mtls": map[string]any{"subject_cn": "ops"}}}},
			{Name: "signer", Methods: []map[string]any{{"keyring": map[string]any{"ed25519": cr.edPubLine}}}},
			{Name: "localdev", Methods: []map[string]any{{"peercred": map[string]any{"uid": strconv.Itoa(cr.uid)}}}},
		}},
		ControlPlane: config.ControlPlane{Enabled: true, Admins: []string{"ops"}},
		Databases: []config.Database{
			{Name: "data", Backend: "file", Path: "data.db", Mode: "rwc", Grants: []config.Grant{
				{Principal: "app", Level: "read-write"},
				{Principal: "analyst", Level: "read-only"},
				{Principal: "ops", Level: "admin"},
				{Principal: "signer", Level: "read-write"},
				{Principal: "localdev", Level: "read-write"},
			}},
			{Name: "public", Backend: "memory-shared", Grants: []config.Grant{
				{Principal: "app", Level: "read-write"}, // seeds the table
				{Principal: "*", Level: "read-only"},    // everyone else may only read
			}},
		},
		Limits: config.Limits{StatementTimeout: 30 * time.Second},
	}
}

// --- per-method sections ---

func noAuthSection(ctx context.Context, ck *checker, cc credConn) {
	section("no-auth (anonymous)", "listener accepts `none`; public has a `*` read-only grant, data has none")
	anon := cc.client()
	defer anon.Close()
	_, readErr := anon.Query(ctx, "public", `SELECT v FROM note`)
	ck.ok("anonymous reads public (wildcard read-only)", readErr)
	_, writeErr := anon.Exec(ctx, "public", `INSERT INTO note VALUES('x')`)
	ck.denied("anonymous writes public (read-only)", writeErr)
	_, dataErr := anon.Query(ctx, "data", `SELECT 1`)
	ck.denied("anonymous touches data (no grant)", dataErr)
}

func bearerSection(ctx context.Context, ck *checker, cc credConn, cr creds, app *client.Client) {
	section("bearer token", "principal app → read-write on data")
	_, err := app.Exec(ctx, "data", `INSERT INTO items(name) VALUES('widget')`)
	ck.ok("app writes data (read-write)", err)
	_, err = app.Query(ctx, "data", `SELECT count(*) FROM items`)
	ck.ok("app reads data", err)
	bad := cc.client(client.WithBearer("not-the-token"))
	defer bad.Close()
	_, err = bad.Query(ctx, "data", `SELECT 1`)
	ck.denied("wrong bearer token", err)
}

func passwordSection(ctx context.Context, ck *checker, cc credConn, cr creds) {
	section("HTTP-basic password", "principal analyst → read-ONLY on data")
	analyst := cc.client(client.WithBasicAuth("analyst", cr.password))
	defer analyst.Close()
	_, err := analyst.Query(ctx, "data", `SELECT count(*) FROM items`)
	ck.ok("analyst reads data", err)
	_, err = analyst.Exec(ctx, "data", `INSERT INTO items(name) VALUES('nope')`)
	ck.denied("analyst writes data (read-only enforced)", err)
	bad := cc.client(client.WithBasicAuth("analyst", "wrong"))
	defer bad.Close()
	_, err = bad.Query(ctx, "data", `SELECT 1`)
	ck.denied("wrong password", err)
}

func keyringSection(ctx context.Context, ck *checker, cc credConn, cr creds) {
	section("ed25519 challenge/response (crypto/keyring)", "principal signer → read-write on data")
	signer := cc.client(client.WithEd25519(cr.edPubLine, cr.edPriv))
	defer signer.Close()
	_, err := signer.Exec(ctx, "data", `INSERT INTO items(name) VALUES('signed')`)
	ck.ok("signer writes data (valid signature)", err)
	// A stranger key not in the roster is rejected.
	_, strayPriv, _ := ed25519.GenerateKey(rand.Reader)
	strayLine := authorizedKeyLine(strayPriv.Public().(ed25519.PublicKey))
	stray := cc.client(client.WithEd25519(strayLine, strayPriv))
	defer stray.Close()
	_, err = stray.Query(ctx, "data", `SELECT 1`)
	ck.denied("stranger ed25519 key (not in roster)", err)
}

func mtlsSection(ctx context.Context, ck *checker, h2 string, cr creds) {
	section("mTLS client certificate", "principal ops (CN=ops) → admin on data")
	ops := client.H2TLS(h2, true, client.WithClientCert(cr.opsCert))
	defer ops.Close()
	_, err := ops.Exec(ctx, "data", `INSERT INTO items(name) VALUES('mtls')`)
	ck.ok("ops writes data (mTLS, admin)", err)
	// No client certificate → refused (RequireAndVerifyClientCert).
	noCert := client.H2TLS(h2, true)
	defer noCert.Close()
	_, err = noCert.Query(ctx, "data", `SELECT 1`)
	ck.denied("no client certificate", err)
	// A cert from an untrusted CA → refused at the handshake.
	stray := client.H2TLS(h2, true, client.WithClientCert(cr.strayCert))
	defer stray.Close()
	_, err = stray.Query(ctx, "data", `SELECT 1`)
	ck.denied("client cert from an untrusted CA", err)
}

func peercredSection(ctx context.Context, ck *checker, sock string, cr creds) {
	section("Unix peer-credentials", fmt.Sprintf("uid %d → principal localdev (read-write); no explicit credential", cr.uid))
	u := client.Unix(sock)
	defer u.Close()
	_, err := u.Exec(ctx, "data", `INSERT INTO items(name) VALUES('peercred')`)
	ck.ok("localdev writes data (identified by socket peer uid)", err)
}

func authzRecap(ctx context.Context, ck *checker, cc credConn, cr creds) {
	section("authorization levels", "the same data database, four capability tiers")
	// read-write (app) already shown; re-affirm read-only and none here as the recap.
	analyst := cc.client(client.WithBasicAuth("analyst", cr.password))
	defer analyst.Close()
	_, roRead := analyst.Query(ctx, "data", `SELECT count(*) FROM items`)
	ck.ok("read-only: analyst SELECT", roRead)
	_, roWrite := analyst.Exec(ctx, "data", `DELETE FROM items`)
	ck.denied("read-only: analyst DELETE", roWrite)
	anon := cc.client()
	defer anon.Close()
	_, none := anon.Query(ctx, "data", `SELECT 1`)
	ck.denied("none: anonymous SELECT on data", none)
}

func controlPlaneSection(ck *checker, h2 string, cc credConn, cr creds) {
	section("control plane (/_admin, admin only)", "ops (admin) may create databases; app (read-write, not admin) may not")
	// ops over mTLS is a server-admin.
	opsHTTP := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cr.opsCert}, NextProtos: []string{"h2", "http/1.1"}},
		ForceAttemptHTTP2: true,
	}, Timeout: 5 * time.Second}
	code, _ := postJSON(opsHTTP, "https://"+h2+"/_admin/create", `{"database":{"name":"scratch","backend":"memory-shared"}}`, nil)
	ck.expect("ops creates a database via /_admin", code == http.StatusOK, fmt.Sprintf("HTTP %d", code))
	lcode, body := getURL(opsHTTP, "https://"+h2+"/_admin/databases")
	ck.expect("ops lists databases", lcode == http.StatusOK && strings.Contains(body, "scratch"), fmt.Sprintf("HTTP %d", lcode))

	// app (bearer) is read-write on data but NOT a server-admin — over whichever
	// transport the credential listener uses.
	dcode, _ := postJSON(cc.httpClient(), cc.url()+"/_admin/create", `{"database":{"name":"evil","backend":"memory-shared"}}`,
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+cr.token) })
	ck.expectDenied("app (non-admin) creates a database", dcode == http.StatusForbidden, fmt.Sprintf("HTTP %d", dcode))
}

// --- credential minting ---

func mintCreds(dataDir string) (creds, error) {
	var cr creds
	cr.token = "s3cr3t-bearer-token"
	sum := sha256.Sum256([]byte(cr.token))
	cr.tokenHash = hex.EncodeToString(sum[:])

	cr.password = "hunter2"
	h, err := bcrypt.GenerateFromPassword([]byte(cr.password), bcrypt.DefaultCost)
	if err != nil {
		return cr, err
	}
	cr.pwHash = string(h)

	caCert, caKey, err := makeCA()
	if err != nil {
		return cr, err
	}
	cr.caPEMPath = filepath.Join(dataDir, "client-ca.pem")
	if err := os.WriteFile(cr.caPEMPath, pemCert(caCert), 0o600); err != nil {
		return cr, err
	}
	if cr.opsCert, err = clientCert("ops", caCert, caKey); err != nil {
		return cr, err
	}
	// A cert from a DIFFERENT CA — the server must refuse it.
	strayCA, strayKey, err := makeCA()
	if err != nil {
		return cr, err
	}
	if cr.strayCert, err = clientCert("intruder", strayCA, strayKey); err != nil {
		return cr, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return cr, err
	}
	cr.edPriv = priv
	cr.edPubLine = authorizedKeyLine(pub)

	cr.uid = os.Getuid()
	return cr, nil
}

func makeCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "quicsql demo CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func clientCert(cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func authorizedKeyLine(pub ed25519.PublicKey) string {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// --- checker + output ---

type checker struct{ failures int }

func (ck *checker) ok(label string, err error) {
	if err != nil {
		ck.failures++
		fmt.Printf("    ✗ %-46s UNEXPECTEDLY DENIED: %s\n", label, short(err))
	} else {
		fmt.Printf("    ✓ %-46s allowed\n", label)
	}
}

func (ck *checker) denied(label string, err error) {
	if err == nil {
		ck.failures++
		fmt.Printf("    ✗ %-46s WRONGLY ALLOWED\n", label)
	} else {
		fmt.Printf("    ✓ %-46s denied (%s)\n", label, short(err))
	}
}

func (ck *checker) expect(label string, pass bool, detail string) {
	if pass {
		fmt.Printf("    ✓ %-46s ok\n", label)
	} else {
		ck.failures++
		fmt.Printf("    ✗ %-46s FAILED (%s)\n", label, detail)
	}
}

func (ck *checker) expectDenied(label string, pass bool, detail string) {
	if pass {
		fmt.Printf("    ✓ %-46s denied (%s)\n", label, detail)
	} else {
		ck.failures++
		fmt.Printf("    ✗ %-46s WRONGLY ALLOWED (%s)\n", label, detail)
	}
}

func (ck *checker) result() error {
	if ck.failures > 0 {
		return fmt.Errorf("%d expectation(s) failed", ck.failures)
	}
	fmt.Println("  all auth/authz expectations held ✓")
	return nil
}

func short(err error) string {
	s := err.Error()
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 70 {
		s = s[:70] + "…"
	}
	return s
}

func banner(title, sub string) { fmt.Printf("\n\033[1m%s\033[0m\n  %s\n", title, sub) }
func section(title, sub string) {
	fmt.Printf("\n\033[1m▸ %s\033[0m\n  %s\n", title, sub)
}

// --- raw HTTP helpers for the control-plane endpoints ---

func postJSON(hc *http.Client, url, body string, hdr func(*http.Request)) (int, string) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return 0, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	if hdr != nil {
		hdr(req)
	}
	return doHTTP(hc, req)
}

func getURL(hc *http.Client, url string) (int, string) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err.Error()
	}
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

func freeTCP() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func waitReady(cc credConn) error {
	hc := cc.httpClient()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := hc.Get(cc.url() + "/_health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("server did not become ready at %s", cc.addr)
}
