package transport_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"gosqlite.org/server/config"
	"gosqlite.org/server/transport"
)

func dummy() http.Handler {
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestH3ShutdownReleasesPort regresses the UDP-socket leak: after Shutdown the
// h3 UDP port must be rebindable (quic-go doesn't close a caller-supplied conn).
func TestH3ShutdownReleasesPort(t *testing.T) {
	addr := freeUDP(t)
	cfg := &config.Config{
		TLS:       map[string]config.TLSProfile{"dev": {Mode: "self_signed"}},
		Listeners: []config.Listener{{Name: "h3", Transport: "h3", Address: addr, TLS: "dev"}},
	}
	set, err := transport.Serve(quiet(), cfg, dummy(), transport.Options{})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	set.Shutdown(context.Background())

	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("h3 shutdown leaked the UDP port %s: %v", addr, err)
	}
	_ = c.Close()
}

// TestServeRejectsEmptyTLSMode regresses the silent self-signed fallback: an
// empty tls mode must error, not mint a throwaway dev cert.
func TestServeRejectsEmptyTLSMode(t *testing.T) {
	cfg := &config.Config{
		TLS:       map[string]config.TLSProfile{"bad": {Mode: ""}},
		Listeners: []config.Listener{{Name: "h2", Transport: "h2", Address: freeTCP(t), TLS: "bad"}},
	}
	if _, err := transport.Serve(quiet(), cfg, dummy(), transport.Options{}); err == nil {
		t.Fatal("empty tls mode should be rejected")
	}
}

// TestUnixSocketMode regresses socket_mode being ignored.
func TestUnixSocketMode(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "q.sock")
	cfg := &config.Config{
		Listeners: []config.Listener{{Name: "u", Transport: "unix", Address: sock, SocketMode: "0600"}},
	}
	set, err := transport.Serve(quiet(), cfg, dummy(), transport.Options{})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { set.Shutdown(context.Background()) })
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket perms %o, want 0600", perm)
	}
}
