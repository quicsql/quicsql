//go:build linux || darwin

package auth

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"gosqlite.org/server/authz"
	"gosqlite.org/server/config"
	"gosqlite.org/server/secret"
)

// TestPeercredOverUnixSocket exercises the real SO_PEERCRED/LOCAL_PEERCRED path:
// a request over a Unix socket authenticates as the principal mapped to the
// caller's uid (this test process's own uid).
func TestPeercredOverUnixSocket(t *testing.T) {
	uid := os.Getuid()
	sec, _ := secret.New(nil)
	cfg := &config.Config{Auth: config.Auth{Principals: []config.Principal{
		principal("me", "peercred", map[string]any{"uid": strconv.Itoa(uid)}),
	}}}
	a, err := New(cfg, sec, nil)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	m := a.Middleware(config.Listener{Name: "u", Transport: "unix", Auth: []string{"peercred", "none"}}, nil)

	// A handler that reports the authenticated principal.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := authz.FromContext(r.Context())
		_, _ = w.Write([]byte(p.Name + ":" + p.Method))
	})

	sock := filepath.Join(t.TempDir(), "peer.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{
		Handler:     m.Wrap(inner),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context { return NewConnContext(ctx, c) },
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}, Timeout: 5 * time.Second}

	resp, err := client.Post("http://unix/db/query", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	if got, want := string(buf[:n]), "me:peercred"; got != want {
		t.Fatalf("principal = %q, want %q", got, want)
	}
}
