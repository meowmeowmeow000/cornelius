//go:build !linux

package proxy

import "net"

// clientSocketFailed has no portable non-blocking peek; on non-Linux builds
// only the idle timeout in watchHalfClosedClient detects a departed client.
func clientSocketFailed(net.Conn) bool { return false }
