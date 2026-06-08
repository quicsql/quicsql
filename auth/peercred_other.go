//go:build !linux && !darwin

package auth

import "net"

// unixPeerUID has no portable implementation off Linux/macOS; peercred auth is
// unavailable there and the method simply never matches.
func unixPeerUID(*net.UnixConn) (uint32, bool) { return 0, false }
