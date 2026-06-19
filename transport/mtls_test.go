package transport_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"quicsql.net/auth"
	"quicsql.net/authz"
	"quicsql.net/config"
	"quicsql.net/secret"
	"quicsql.net/transport"
)

// TestMTLSEndToEnd stands up an h2-over-TLS listener with a client CA and the
// mtls auth method, then connects with a client certificate and asserts the
// request authenticated as the mapped principal — the whole path: buildTLS
// ClientCAs → TLS handshake → r.TLS.PeerCertificates → auth mtls → principal.
func TestMTLSEndToEnd(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := makeCA(t)
	caPEM := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPEM, pemCert(caCert), 0o600); err != nil {
		t.Fatal(err)
	}
	clientTLS := clientCertFor(t, "ops.example.com", caCert, caKey)

	sec, _ := secret.New(nil)
	cfg := &config.Config{
		TLS: map[string]config.TLSProfile{"m": {Mode: "self_signed", ClientCA: caPEM}},
		Listeners: []config.Listener{{
			Name: "pub", Transport: "h2", Address: freeTCP(t), TLS: "m", Auth: []string{"mtls"},
		}},
		Auth: config.Auth{Principals: []config.Principal{
			{Name: "ops", Methods: []map[string]any{{"mtls": map[string]any{"subject_cn": "ops.example.com"}}}},
		}},
	}
	authn, err := auth.New(cfg, sec, quiet())
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := authz.FromContext(r.Context())
		_, _ = io.WriteString(w, p.Name+":"+p.Method)
	})
	opts := transport.Options{Wrap: func(lc config.Listener, h http.Handler) http.Handler {
		return authn.Middleware(lc, quiet()).Wrap(h)
	}}
	set, err := transport.Serve(quiet(), cfg, inner, opts)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { set.Shutdown(context.Background()) })

	addr := cfg.Listeners[0].Address
	waitTCP(t, addr)

	// A client presenting the CA-signed cert authenticates as "ops".
	body := mtlsGet(t, addr, &tls.Config{
		Certificates: []tls.Certificate{clientTLS}, InsecureSkipVerify: true, NextProtos: []string{"h2"},
	})
	if body != "ops:mtls" {
		t.Fatalf("principal = %q, want ops:mtls", body)
	}

	// A client with no certificate is refused (RequireAndVerifyClientCert). Under
	// TLS 1.3 the server's rejection surfaces on the first request, not at dial.
	noCert := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
	}, Timeout: 5 * time.Second}
	if resp, err := noCert.Get("https://" + addr + "/db/query"); err == nil {
		resp.Body.Close()
		t.Fatal("a client with no certificate should be refused")
	}
}

// TestMTLSOptionalAlongsideBearer covers the VerifyClientCertIfGiven branch: when
// mtls sits alongside bearer, a client without a certificate is NOT refused at the
// handshake and can authenticate with a bearer token instead.
func TestMTLSOptionalAlongsideBearer(t *testing.T) {
	dir := t.TempDir()
	caCert, _ := makeCA(t)
	caPEM := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPEM, pemCert(caCert), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("t0ken"))
	sec, _ := secret.New(nil)
	cfg := &config.Config{
		TLS: map[string]config.TLSProfile{"m": {Mode: "self_signed", ClientCA: caPEM}},
		Listeners: []config.Listener{{
			Name: "pub", Transport: "h2", Address: freeTCP(t), TLS: "m", Auth: []string{"mtls", "bearer"},
		}},
		Auth: config.Auth{Principals: []config.Principal{
			{Name: "app", Methods: []map[string]any{{"bearer": map[string]any{"token_hash": hex.EncodeToString(sum[:])}}}},
		}},
	}
	authn, err := auth.New(cfg, sec, quiet())
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := authz.FromContext(r.Context())
		_, _ = io.WriteString(w, p.Name+":"+p.Method)
	})
	opts := transport.Options{Wrap: func(lc config.Listener, h http.Handler) http.Handler {
		return authn.Middleware(lc, quiet()).Wrap(h)
	}}
	set, err := transport.Serve(quiet(), cfg, inner, opts)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { set.Shutdown(context.Background()) })
	addr := cfg.Listeners[0].Address
	waitTCP(t, addr)

	// No client cert (the handshake accepts it), authenticates by bearer token.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}, ForceAttemptHTTP2: true,
	}, Timeout: 5 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/db/query", nil)
	req.Header.Set("Authorization", "Bearer t0ken")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "app:bearer" {
		t.Fatalf("principal = %q, want app:bearer", b)
	}
}

func mtlsGet(t *testing.T, addr string, tc *tls.Config) string {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   tc,
		ForceAttemptHTTP2: true,
	}, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + addr + "/db/query")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	for range 100 {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s never came up", addr)
}

func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "quicsql test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func clientCertFor(t *testing.T, cn string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
