// Command quicsql-charged-server is a deployable, fully-charged quicSQL server:
// an encrypted + compressed vault database, a plain file DB and a shared in-memory
// DB; the standard extension bundle plus a custom server-registered SQL function;
// every auth method and authz level; TLS h2 + HTTP/3 as the primary secure
// transports (with cleartext h1/h2c and a Unix socket as dev extras); the control
// plane; rate/concurrency limits; a slow-query log; and a vault-backed meta store.
//
// It binds a real interface (default 0.0.0.0) and mints its TLS leaf for the SANs
// you pass, so it is meant to run on a HOST and be reached from elsewhere:
//
//	go run . -hosts your.host.name,203.0.113.10          # bind 0.0.0.0, cert for these SANs
//	docker run -p 7777:7777 -p 7777:7777/udp quicsql-charged   # see Dockerfile
//
// Then point the remote tour at it: `go run ./examples/remote-tour -addr your.host.name:7777`.
// Credentials are fixed dev material (see the shared internal/showcase package) —
// the tour derives the identical CA/keys, so nothing is copied between machines.
// Replace it all for a real deployment.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	sqlite "gosqlite.org"
	"quicsql.net/config"
	"quicsql.net/examples/internal/showcase" // shared dev creds (server + tour derive the same)
	_ "quicsql.net/extensions"               // regexp, fts5, vec0, spellfix1, rtree, … on every connection
	"quicsql.net/serverd"
)

const shutdownGrace = 10 * time.Second

func main() {
	bind := flag.String("bind", "0.0.0.0", "interface to bind (0.0.0.0 = reachable from other machines)")
	hosts := flag.String("hosts", "localhost,127.0.0.1", "comma-separated TLS SAN hosts/IPs — the address clients dial")
	dataDir := flag.String("data", "./quicsql-charged-data", "persistent data directory (keys, vault containers, tls)")
	flag.Parse()

	// Composition: register a CUSTOM server-side SQL function on every connection,
	// BEFORE serverd.Run. Clients call it via SQL — this is how server-side
	// functions (and any extension/VFS) reach remote clients: the server runs them.
	sqlite.RegisterAutoHook(func(c *sqlite.Conn) error {
		return c.RegisterFunc("showcase_greet", func(name string) string {
			return "hello from quicSQL, " + name
		}, true /* deterministic */)
	})

	if err := run(*bind, *hosts, *dataDir); err != nil {
		fmt.Fprintln(os.Stderr, "charged-server:", err)
		os.Exit(1)
	}
}

func run(bind, hostsCSV, dataDir string) error {
	hosts := splitCSV(hostsCSV)
	keysDir := filepath.Join(dataDir, "keys")
	tlsDir := filepath.Join(dataDir, "tls")
	for _, d := range []string{keysDir, tlsDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}

	// Fixed dev secrets on disk: the vault (Adiantum, 32-byte) key and the meta
	// store's vault key. The catalog vault encrypts + compresses at rest.
	if err := os.WriteFile(filepath.Join(keysDir, "catalog"), showcase.VaultKey(), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(keysDir, "meta"), showcase.Seed("meta"), 0o600); err != nil {
		return err
	}

	// TLS: mint the server leaf for the SANs and write the files-mode profile
	// inputs (leaf cert + key, and the CA as the mTLS client-CA).
	ca, _ := showcase.CA()
	certFile, keyFile, caFile, err := writeTLSFiles(tlsDir, showcase.Leaf(hosts), ca)
	if err != nil {
		return err
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(showcase.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	cfg := &config.Config{
		Server: config.Server{
			DataDir:   dataDir,
			MetaStore: config.MetaStore{Backend: "vault", Path: "_meta.vault", Key: "keys:meta"},
		},
		Secrets: []config.SecretSource{{Name: "keys", Type: "file", Dir: keysDir}},
		TLS: map[string]config.TLSProfile{
			"charged": {Mode: "files", Cert: certFile, Key: keyFile, ClientCA: caFile, MinVersion: "1.2"},
		},
		Listeners: []config.Listener{
			{Name: "h2", Transport: "h2", Address: net.JoinHostPort(bind, "7777"), TLS: "charged", Auth: []string{"mtls", "bearer", "keyring", "password"}},
			// h3 (QUIC/UDP) shares the h2 (TLS/TCP) port, the way HTTPS shares :443;
			// advertise: true makes the TCP transports emit Alt-Svc so clients upgrade.
			{Name: "h3", Transport: "h3", Address: net.JoinHostPort(bind, "7777"), TLS: "charged", Auth: []string{"mtls", "bearer", "keyring", "password"}, Advertise: true},
			{Name: "h1", Transport: "h1", Address: net.JoinHostPort(bind, "7775"), Auth: []string{"bearer", "password", "none"}},
			{Name: "h2c", Transport: "h2c", Address: net.JoinHostPort(bind, "7776"), Auth: []string{"bearer", "password", "none"}},
			{Name: "unix", Transport: "unix", Address: filepath.Join(dataDir, "quicsql.sock"), SocketMode: "0600", Auth: []string{"peercred", "none"}},
		},
		Auth: config.Auth{Principals: []config.Principal{
			{Name: "tourist", Methods: []map[string]any{
				{"bearer": map[string]any{"token_hash": showcase.TokenHash()}},
				{"mtls": map[string]any{"subject_cn": showcase.MTLSCN}},
			}},
			{Name: "analyst", Methods: []map[string]any{{"password": map[string]any{"user": showcase.User, "password_hash": string(pwHash)}}}},
			{Name: "signer", Methods: []map[string]any{{"keyring": map[string]any{"ed25519": showcase.AuthLine()}}}},
		}},
		Databases: []config.Database{
			{Name: "catalog", Backend: "vault", Path: "catalog.vault",
				Vault:  &config.VaultConfig{Compression: "best", Cipher: "adiantum", Key: "keys:catalog"},
				Grants: []config.Grant{{Principal: "tourist", Level: "admin"}}},
			{Name: "app", Backend: "file", Path: "app.db", Mode: "rwc", PragmasPreset: "recommended",
				Grants: []config.Grant{{Principal: "tourist", Level: "read-write"}, {Principal: "analyst", Level: "read-only"}, {Principal: "signer", Level: "read-write"}}},
			{Name: "cache", Backend: "memory-shared",
				Grants: []config.Grant{{Principal: "tourist", Level: "read-write"}, {Principal: "*", Level: "read-only"}}},
		},
		ControlPlane: config.ControlPlane{Enabled: true, Admins: []string{"tourist"}},
		Limits:       config.Limits{StatementTimeout: 30 * time.Second, MaxConcurrentPerDB: 512, Rate: config.Rate{PerPrincipalRPS: 100}},
		Logging:      config.Logging{SlowThreshold: 200 * time.Millisecond},
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv, err := serverd.Run(cfg, log)
	if err != nil {
		return err
	}
	banner(hosts)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stderr, "\ncharged-server: shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	srv.Shutdown(ctx)
	return nil
}

// writeTLSFiles writes the leaf cert + key and the CA cert as PEM and returns
// their paths (for the files-mode TLS profile).
func writeTLSFiles(dir string, leaf tls.Certificate, ca *x509.Certificate) (certFile, keyFile, caFile string, err error) {
	certFile = filepath.Join(dir, "leaf.crt")
	keyFile = filepath.Join(dir, "leaf.key")
	caFile = filepath.Join(dir, "ca.crt")
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		return "", "", "", err
	}
	files := map[string][]byte{
		certFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}),
		keyFile:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		caFile:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}),
	}
	for path, data := range files {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return "", "", "", err
		}
	}
	return certFile, keyFile, caFile, nil
}

func splitCSV(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func banner(hosts []string) {
	dial := "localhost"
	if len(hosts) > 0 {
		dial = hosts[0]
	}
	fmt.Fprintf(os.Stderr, `
quicSQL charged server — up.
  encrypted+compressed vault: "catalog"   plain file: "app"   in-memory: "cache"
  secure transports:  h2 :7777 (TLS/TCP) + h3 :7777 (QUIC/UDP, same port; Alt-Svc)
  dev transports:     h1  :7775          h2c :7776          unix (data dir)
  auth: bearer / password / mTLS(CN=%s) / ed25519 keyring     control plane: on

  connect the remote tour:
    go run ./examples/remote-tour -addr %s:7777
  bearer token (dev): %s

  Ctrl-C to stop.
`, showcase.MTLSCN, dial, showcase.Token)
}
