package auth

import (
	"context"
	"net"
)

// connKey carries the accepted net.Conn into the request context so the peercred
// method can read the Unix-socket peer credentials. transport wires it via
// http.Server.ConnContext.
type connKey struct{}

// NewConnContext returns a context that carries c, for http.Server.ConnContext.
func NewConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

func connFrom(ctx context.Context) net.Conn {
	c, _ := ctx.Value(connKey{}).(net.Conn)
	return c
}

// peerUID returns the uid of the process on the other end of a Unix-domain
// socket connection, if it can be determined on this platform. The
// implementation is per-OS (peercred_linux.go / peercred_darwin.go), with a
// portable no-op fallback (peercred_other.go).
func peerUID(c net.Conn) (uint32, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	return unixPeerUID(uc)
}
