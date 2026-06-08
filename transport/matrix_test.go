package transport_test

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"gosqlite.org/server/backend"
	"gosqlite.org/server/config"
	"gosqlite.org/server/engine"
	"gosqlite.org/server/httpapi"
	"gosqlite.org/server/registry"
	"gosqlite.org/server/secret"
	"gosqlite.org/server/session"
	"gosqlite.org/server/transport"
)

func newMatrixHandler(t *testing.T) http.Handler {
	t.Helper()
	sec, _ := secret.New(nil)
	be, err := backend.For(config.Database{
		Name: "app", Backend: "file", Path: filepath.Join(t.TempDir(), "app.db"),
		Pragmas: map[string]any{"journal_mode": "WAL"},
	}, sec, "")
	if err != nil {
		t.Fatalf("backend.For: %v", err)
	}
	reg := registry.New(map[string]backend.Backend{"app": be}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	store, _ := session.NewStore(time.Minute, time.Minute, 16)
	t.Cleanup(store.CloseAll)
	return httpapi.New(reg, engine.New(0, 0), config.Routing{ByPath: true}, httpapi.WithSessions(store))
}

func freeTCP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	_ = l.Close()
	return a
}

func freeUDP(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := c.LocalAddr().String()
	_ = c.Close()
	return a
}

// post retries briefly to absorb the tiny server-startup window.
func post(t *testing.T, c *http.Client, url, body string) (*http.Response, string) {
	t.Helper()
	var lastErr error
	for range 20 {
		req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(25 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(b)
	}
	t.Fatalf("post %s: %v", url, lastErr)
	return nil, ""
}

// TestTransportMatrix runs the native-JSON and Hrana suites over every transport
// and asserts both the result and the negotiated wire protocol.
func TestTransportMatrix(t *testing.T) {
	handler := newMatrixHandler(t)
	h1Addr, h2cAddr, h2Addr, h3Addr := freeTCP(t), freeTCP(t), freeTCP(t), freeUDP(t)
	sock := filepath.Join(t.TempDir(), "q.sock")

	cfg := &config.Config{
		TLS: map[string]config.TLSProfile{"dev": {Mode: "self_signed", Hosts: []string{"localhost"}}},
		Listeners: []config.Listener{
			{Name: "h1", Transport: "h1", Address: h1Addr},
			{Name: "h2c", Transport: "h2c", Address: h2cAddr},
			{Name: "h2", Transport: "h2", Address: h2Addr, TLS: "dev"},
			{Name: "h3", Transport: "h3", Address: h3Addr, TLS: "dev"},
			{Name: "unix", Transport: "unix", Address: sock},
		},
	}
	quietLog := slog.New(slog.NewTextHandler(io.Discard, nil))
	set, err := transport.Serve(quietLog, cfg, handler, transport.Options{})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { set.Shutdown(context.Background()) })

	insecure := &tls.Config{InsecureSkipVerify: true}
	h3tr := &http3.Transport{TLSClientConfig: insecure}
	t.Cleanup(func() { _ = h3tr.Close() })

	cases := []struct {
		name      string
		base      string
		client    *http.Client
		wantProto int
	}{
		{"h1", "http://" + h1Addr, &http.Client{}, 1},
		{"h2c", "http://" + h2cAddr, &http.Client{Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(_ context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		}}, 2},
		{"h2", "https://" + h2Addr, &http.Client{Transport: &http.Transport{TLSClientConfig: insecure, ForceAttemptHTTP2: true}}, 2},
		{"h3", "https://" + h3Addr, &http.Client{Transport: h3tr}, 3},
		{"unix", "http://unix", &http.Client{Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) { return net.Dial("unix", sock) },
		}}, 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// native JSON
			resp, body := post(t, c.client, c.base+"/app/query", `{"sql":"SELECT 1 AS n"}`)
			if resp.ProtoMajor != c.wantProto {
				t.Errorf("native: proto HTTP/%d, want HTTP/%d", resp.ProtoMajor, c.wantProto)
			}
			if !strings.Contains(body, "[[1]]") {
				t.Errorf("native: want [[1]], got %s", body)
			}
			// Hrana pipeline
			resp2, body2 := post(t, c.client, c.base+"/app/v3/pipeline",
				`{"baton":null,"requests":[{"type":"execute","stmt":{"sql":"SELECT 1 AS n","want_rows":true}}]}`)
			if resp2.ProtoMajor != c.wantProto {
				t.Errorf("hrana: proto HTTP/%d, want HTTP/%d", resp2.ProtoMajor, c.wantProto)
			}
			if !strings.Contains(body2, `"value":"1"`) {
				t.Errorf("hrana: want integer value \"1\", got %s", body2)
			}
		})
	}
}
