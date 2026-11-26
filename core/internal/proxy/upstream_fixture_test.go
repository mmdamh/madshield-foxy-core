package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/handshake"
)

// forgetUpstreamShape clears what the tests of the connection race share: the
// shape that worked, and Go's hello as the first one.
func forgetUpstreamShape() {
	upstreamShapes = &handshake.Memory{}
	upstreamGoTLS.Store(false)
}

// serverBehavior is what upstreamTLSServerWith does with a connection.
type serverBehavior int

const (
	serveTLS  serverBehavior = iota // complete TLS with h2
	dropConn                        // close it before TLS
	stallConn                       // accept it and never answer, as a network that drops the hello
)

// upstreamTLSServer serves TLS with h2 on a loopback port and trusts it for the
// test. reject closes the connections it names, before TLS.
func upstreamTLSServer(t *testing.T, reject func(n int32) bool) (*url.URL, string, *atomic.Int32) {
	t.Helper()
	return upstreamTLSServerWith(t, func(n int32) serverBehavior {
		if reject != nil && reject(n) {
			return dropConn
		}
		return serveTLS
	})
}

// upstreamTLSServerWith is upstreamTLSServer with a behavior for each
// connection (numbered from 1).
func upstreamTLSServerWith(t *testing.T, behave func(n int32) serverBehavior) (*url.URL, string, *atomic.Int32) {
	t.Helper()
	fixture := httptest.NewUnstartedServer(nil)
	fixture.EnableHTTP2 = true
	fixture.StartTLS()
	t.Cleanup(fixture.Close)
	pool := x509.NewCertPool()
	pool.AddCert(fixture.Certificate())
	previous := upstreamRoots.Load()
	upstreamRoots.Store(pool)
	forgetUpstreamShape()
	t.Cleanup(func() { upstreamRoots.Store(previous); forgetUpstreamShape() })
	config := fixture.TLS.Clone()
	config.NextProtos = []string{"h2"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	t.Cleanup(func() { _ = listener.Close(); close(released) })
	var count atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			n := count.Add(1)
			go func() {
				defer conn.Close()
				switch behave(n) {
				case dropConn:
					return
				case stallConn:
					<-released
					return
				}
				server := tls.Server(conn, config)
				if server.Handshake() != nil {
					return
				}
				_, _ = io.Copy(io.Discard, server)
			}()
		}
	}()
	return &url.URL{Scheme: "https", Host: "127.0.0.1"}, listener.Addr().String(), &count
}

func dialContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
