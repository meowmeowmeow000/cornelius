//go:build linux

package proxy

import (
	"net"
	"syscall"
)

// clientSocketFailed reports whether the client's TCP socket has a pending
// error: the kernel records one when the peer resets the connection (an
// abortive close sends RST) or a keepalive fails. After a clean half-close
// there is none. SO_ERROR is used rather than a recv peek because recv
// reports the earlier FIN as EOF (0 bytes) before it ever looks at the
// socket error. Reading SO_ERROR clears it, which is fine: the caller tears
// the stream down on the first hit.
func clientSocketFailed(c net.Conn) bool {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return true
	}
	var soErr int
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		soErr, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_ERROR)
	}); err != nil {
		return true
	}
	return gerr != nil || soErr != 0
}
