package handshake

import (
	"net"
	"sync/atomic"
	"time"
)

// TracedConn times a connection's first reply: how long the network and the
// server took to answer the first bytes written to it. For a TLS handshake
// that is the time to the first byte of the ServerHello, and a connection
// that connects but never replies (a network that drops the hello) has none.
type TracedConn struct {
	net.Conn
	firstWrite atomic.Int64 // UnixNano
	firstRead  atomic.Int64
}

// Trace wraps conn, which should be the connection as it was dialed, below
// anything that cuts what is written to it.
func Trace(conn net.Conn) *TracedConn { return &TracedConn{Conn: conn} }

func (c *TracedConn) Write(p []byte) (int, error) {
	if len(p) > 0 {
		c.firstWrite.CompareAndSwap(0, time.Now().UnixNano())
	}
	return c.Conn.Write(p)
}

func (c *TracedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.firstRead.CompareAndSwap(0, time.Now().UnixNano())
	}
	return n, err
}

// Reply is the time from the first write to the first byte read, and false
// while either has not happened.
func (c *TracedConn) Reply() (time.Duration, bool) {
	w, r := c.firstWrite.Load(), c.firstRead.Load()
	if w == 0 || r == 0 {
		return 0, false
	}
	return time.Duration(r - w), true
}
