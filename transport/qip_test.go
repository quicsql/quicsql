package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// discardLogger is a no-op logger for the renew tests (renew logs on refetch failure).
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// nearExpiryCert mints a cert whose Leaf.NotAfter is inside renew's 30-day refresh
// window, so the renewer attempts a refetch instead of skipping.
func nearExpiryCert(t *testing.T) *tls.Certificate {
	t.Helper()
	cert, err := selfSignedCert([]string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			t.Fatal(err)
		}
	}
	cert.Leaf.NotAfter = time.Now().Add(time.Hour) // within the 30-day window
	return &cert
}

// combinedPEM returns a self-signed cert + key in one PEM, the shape qip.sh serves.
func combinedPEM(t *testing.T) []byte {
	t.Helper()
	cert, err := selfSignedCert([]string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return append(certPEM, keyPEM...)
}

// TestQIPCertFetch proves the qip fetcher downloads a combined cert+key PEM and
// serves it via GetCertificate — the whole path, against a local httptest server
// (no real network / no qip.sh dependency).
func TestQIPCertFetch(t *testing.T) {
	pemBytes := combinedPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(pemBytes)
	}))
	defer srv.Close()

	q := &qipCert{url: srv.URL}
	if err := q.fetch(); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	got, err := q.get(&tls.ClientHelloInfo{})
	if err != nil || got == nil || got.Leaf == nil {
		t.Fatalf("get: cert=%v err=%v", got, err)
	}
	if len(got.Leaf.DNSNames) == 0 || got.Leaf.DNSNames[0] != "localhost" {
		t.Fatalf("cert SANs = %v, want [localhost]", got.Leaf.DNSNames)
	}
}

// TestQIPCertFetchBadStatus proves a non-200 from qip.sh is an error (not a silent
// empty cert).
func TestQIPCertFetchBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	q := &qipCert{url: srv.URL}
	if err := q.fetch(); err == nil {
		t.Fatal("expected an error on a non-200 response")
	}
}

// TestQIPGetBeforeFetch proves GetCertificate errors (rather than returning nil)
// before any cert is loaded.
func TestQIPGetBeforeFetch(t *testing.T) {
	q := &qipCert{url: "http://unused.invalid"}
	if _, err := q.get(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("expected an error before the first fetch")
	}
}

// TestQIPRenewSkipsWithinWindow proves renew does NOT refetch while the current cert
// is comfortably before expiry (a self-signed cert is valid ~365d, well outside the
// 30-day window) — so it also proves renew returns promptly on ctx cancel.
func TestQIPRenewSkipsWithinWindow(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(combinedPEM(t))
	}))
	defer srv.Close()

	q := &qipCert{url: srv.URL}
	if err := q.fetch(); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { q.renew(ctx, time.Millisecond, discardLogger()); close(done) }()
	time.Sleep(40 * time.Millisecond) // ~40 ticks; a broken skip check would refetch each
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("renew did not return on ctx cancel")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("renew refetched a cert with ~365d left: server hits=%d, want 1 (initial only)", got)
	}
}

// TestQIPRenewKeepsCertOnFailure proves a failed refetch (qip.sh down) keeps the
// current certificate rather than dropping it — GetCertificate must never go nil.
func TestQIPRenewKeepsCertOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	q := &qipCert{url: srv.URL}
	want := nearExpiryCert(t) // inside the window → renew attempts a (failing) refetch
	q.cur.Store(want)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { q.renew(ctx, time.Millisecond, discardLogger()); close(done) }()
	time.Sleep(40 * time.Millisecond)
	cancel()
	<-done

	got, err := q.get(&tls.ClientHelloInfo{})
	if err != nil || got != want {
		t.Fatalf("failed refetch dropped the old cert: got=%p err=%v, want %p", got, err, want)
	}
}

// TestQIPRenewStopsOnCancel proves the renewer goroutine exits on ctx cancel even
// when it is blocked between ticks (a long interval) — so Shutdown reliably stops it.
func TestQIPRenewStopsOnCancel(t *testing.T) {
	q := &qipCert{url: "http://unused.invalid"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { q.renew(ctx, time.Hour, discardLogger()); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("renew did not return after ctx cancel")
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:7777": true, "[::1]:7777": true, "localhost:7777": true,
		"0.0.0.0:7777": false, "192.168.1.5:7777": false, ":7777": false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Fatalf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}
