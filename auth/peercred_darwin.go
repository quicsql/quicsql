//go:build darwin

package auth

import (
	"net"

	"golang.org/x/sys/unix"
)

// unixPeerUID reads LOCAL_PEERCRED from the connected Unix socket (macOS/BSD).
func unixPeerUID(uc *net.UnixConn) (uint32, bool) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var uid uint32
	var ok bool
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			return
		}
		uid, ok = cred.Uid, true
	})
	return uid, ok
}
