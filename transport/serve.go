package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go/http3"

	"quicsql.net/config"
)

const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
)

// Options carries the optional per-listener wiring the daemon supplies: Wrap
// installs a listener's auth middleware around the shared handler, and
// ConnContext stashes the accepted connection into the request context (so the
// peercred method can read a Unix socket's peer credentials). Both are nil in
// tests that exercise the raw transport.
type Options struct {
	Wrap        func(config.Listener, http.Handler) http.Handler
	ConnContext func(context.Context, net.Conn) context.Context
}

// Set holds the started servers so they can be shut down together.
type Set struct {
	http []*http.Server
	h3   []h3Listener
}

// h3Listener pairs a QUIC HTTP/3 server with its UDP conn: quic-go does NOT
// close a caller-supplied PacketConn, so we must close it ourselves on shutdown
// or the UDP port leaks.
type h3Listener struct {
	srv  *http3.Server
	conn net.PacketConn
}

// Serve starts a server per configured listener across every transport, serving
// the same handler (wrapped per-listener by opts.Wrap when set). On a mid-startup
// failure it tears down what it started and returns the error.
func Serve(log *slog.Logger, cfg *config.Config, handler http.Handler, opts Options) (*Set, error) {
	set := &Set{}
	for _, lc := range cfg.Listeners {
		if err := set.start(log, cfg, lc, handler, opts); err != nil {
			set.Shutdown(context.Background())
			return nil, fmt.Errorf("listener %s: %w", lc.Name, err)
		}
	}
	return set, nil
}

func (s *Set) start(log *slog.Logger, cfg *config.Config, lc config.Listener, handler http.Handler, opts Options) error {
	// Apply this listener's auth middleware around the shared handler.
	if opts.Wrap != nil {
		handler = opts.Wrap(lc, handler)
	}
	switch lc.Transport {
	case "unix":
		_ = os.Remove(lc.Address)
		ln, err := net.Listen("unix", lc.Address)
		if err != nil {
			return err
		}
		if lc.SocketMode != "" { // restrict who can reach this (often no-auth) socket
			mode, err := strconv.ParseUint(lc.SocketMode, 8, 32)
			if err != nil {
				_ = ln.Close()
				return fmt.Errorf("invalid socket_mode %q: %w", lc.SocketMode, err)
			}
			if err := os.Chmod(lc.Address, os.FileMode(mode)); err != nil {
				_ = ln.Close()
				return fmt.Errorf("chmod socket: %w", err)
			}
		}
		s.serveHTTP(log, lc.Name, "unix", ln, h1Server(handler, opts.ConnContext))
		return nil

	case "h1":
		ln, err := net.Listen("tcp", lc.Address)
		if err != nil {
			return err
		}
		s.serveHTTP(log, lc.Name, "h1", ln, h1Server(handler, opts.ConnContext))
		return nil

	case "h2c":
		ln, err := net.Listen("tcp", lc.Address)
		if err != nil {
			return err
		}
		// Cleartext HTTP/2 (and HTTP/1.1) on the same socket, via the stdlib's
		// native unencrypted-HTTP/2 support (Go 1.26+).
		srv := h2Server(handler, opts.ConnContext)
		var protos http.Protocols
		protos.SetHTTP1(true)
		protos.SetUnencryptedHTTP2(true)
		srv.Protocols = &protos
		s.serveHTTP(log, lc.Name, "h2c", ln, srv)
		return nil

	case "h2":
		tc, p, err := s.tlsFor(cfg, lc)
		if err != nil {
			return err
		}
		warnSelfSigned(log, lc.Name, p)
		tc.NextProtos = []string{"h2", "http/1.1"}
		ln, err := net.Listen("tcp", lc.Address)
		if err != nil {
			return err
		}
		srv := h2Server(handler, opts.ConnContext)
		srv.TLSConfig = tc
		s.http = append(s.http, srv)
		go func() {
			log.Info("quicsql: serving", "listener", lc.Name, "transport", "h2", "addr", ln.Addr().String())
			if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("quicsql: serve h2", "listener", lc.Name, "err", err)
			}
		}()
		return nil

	case "h3":
		tc, p, err := s.tlsFor(cfg, lc) // buildTLS forced TLS 1.3 for h3
		if err != nil {
			return err
		}
		warnSelfSigned(log, lc.Name, p)
		tc.NextProtos = []string{"h3"}
		conn, err := net.ListenPacket("udp", lc.Address) // bind synchronously to surface errors
		if err != nil {
			return err
		}
		h3 := &http3.Server{Handler: handler, TLSConfig: tc}
		s.h3 = append(s.h3, h3Listener{srv: h3, conn: conn})
		go func() {
			log.Info("quicsql: serving", "listener", lc.Name, "transport", "h3(QUIC)", "addr", lc.Address)
			if err := h3.Serve(conn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				log.Error("quicsql: serve h3", "listener", lc.Name, "err", err)
			}
		}()
		return nil

	default:
		log.Warn("quicsql: unknown transport ignored", "listener", lc.Name, "transport", lc.Transport)
		return nil
	}
}

func (s *Set) tlsFor(cfg *config.Config, lc config.Listener) (*tls.Config, config.TLSProfile, error) {
	if lc.TLS == "" {
		return nil, config.TLSProfile{}, fmt.Errorf("transport %q requires a tls profile (set tls: <name>)", lc.Transport)
	}
	p, ok := cfg.TLS[lc.TLS]
	if !ok {
		return nil, config.TLSProfile{}, fmt.Errorf("unknown tls profile %q", lc.TLS)
	}
	// A client cert is REQUIRED only when mtls is the listener's sole auth method;
	// alongside other methods it is optional (VerifyClientCertIfGiven) so bearer /
	// keyring clients can still connect.
	tc, err := buildTLS(p, lc.Transport == "h3", onlyAuthMethod(lc, "mtls"))
	return tc, p, err
}

// onlyAuthMethod reports whether method is the single auth method a listener
// accepts.
func onlyAuthMethod(lc config.Listener, method string) bool {
	return len(lc.Auth) == 1 && lc.Auth[0] == method
}

func warnSelfSigned(log *slog.Logger, name string, p config.TLSProfile) {
	if p.Mode == "self_signed" {
		log.Warn("quicsql: serving a self-signed (dev-only) TLS certificate — do not use in production", "listener", name)
	}
}

func (s *Set) serveHTTP(log *slog.Logger, name, transport string, ln net.Listener, srv *http.Server) {
	s.http = append(s.http, srv)
	go func() {
		log.Info("quicsql: serving", "listener", name, "transport", transport, "addr", ln.Addr().String())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("quicsql: serve", "listener", name, "err", err)
		}
	}()
}

// h1Server bounds a whole HTTP/1.1 connection (slowloris protection). connCtx,
// when set, stashes the accepted conn into the request context for peercred.
func h1Server(h http.Handler, connCtx func(context.Context, net.Conn) context.Context) *http.Server {
	return &http.Server{
		Handler:           h,
		ConnContext:       connCtx,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

// h2Server omits the connection-level read/write timeouts (they would kill a
// long-lived multiplexed HTTP/2 connection); per-request bounds come from the
// statement timeout and result caps.
func h2Server(h http.Handler, connCtx func(context.Context, net.Conn) context.Context) *http.Server {
	return &http.Server{Handler: h, ConnContext: connCtx, ReadHeaderTimeout: readHeaderTimeout, IdleTimeout: idleTimeout}
}

// Shutdown gracefully stops every server: HTTP servers drain, and each h3
// server sends GOAWAY and drains (Shutdown, not the abrupt Close) before its UDP
// conn is closed to release the port.
func (s *Set) Shutdown(ctx context.Context) {
	for _, srv := range s.http {
		_ = srv.Shutdown(ctx)
	}
	for _, l := range s.h3 {
		_ = l.srv.Shutdown(ctx)
		_ = l.conn.Close()
	}
}

// Count reports how many servers are running (for logging).
func (s *Set) Count() int { return len(s.http) + len(s.h3) }
