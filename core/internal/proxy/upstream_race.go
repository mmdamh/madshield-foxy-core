package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/dialrace"
	"github.com/mmdamh/madshield-foxy-core/core/internal/handshake"
	"github.com/mmdamh/madshield-foxy-core/core/internal/hellosplit"
	"github.com/mmdamh/madshield-foxy-core/core/internal/logx"
	"github.com/mmdamh/madshield-foxy-core/core/internal/resolver"
)

// A network can let TCP through to Mozilla's proxy and still never answer
// the TLS hello (the handshake then times out): a filter that dislikes one
// hello, the way it is cut into segments, or the name it carries. Which of
// these it is cannot be known from here, so a connection tries several
// handshake shapes (package handshake) one after another, each starting when
// the one before it has failed or has had upstreamShapeStagger, and keeps the
// first that completes. The shape that worked is remembered (and saved, see
// SetUpstreamShapeFile), so the next connection starts with it.

var (
	// upstreamShapes is the shape that last connected.
	upstreamShapes = &handshake.Memory{}
	// upstreamECH has the ECH keys of the proxies' names, from DNS.
	upstreamECH = &handshake.ECHKeys{
		Lookup: func(ctx context.Context, host string) ([]byte, time.Duration, error) {
			return resolver.LookupECH(ctx, host)
		},
		Missing: resolver.ErrNoECH,
	}
	// upstreamShapeStagger is how long a shape runs alone before the next
	// one starts. A variable for the tests.
	upstreamShapeStagger = 500 * time.Millisecond
)

// echLookupTimeout bounds finding a proxy's ECH key, so that a DNS that does
// not answer costs one shape of the race and nothing else.
const echLookupTimeout = 3 * time.Second

// SetUpstreamShapeFile makes file where the handshake shape that worked is
// kept across restarts, and starts from the one it holds.
func SetUpstreamShapeFile(file string) {
	if err := upstreamShapes.Load(file); err != nil {
		logx.Warn("loading the upstream handshake shape failed path=%s err=%s", file, logx.Err(err))
	}
	if s := upstreamShapes.Last(); s != nil {
		upstreamGoTLS.Store(s.Hello == handshake.HelloGo)
		logx.Info("upstream handshake starts with the shape that worked last shape=%s", s)
	}
}

// rememberedShape is the shape the next connection starts with, nil when
// there is none. upstreamGoTLS is the switch for Go's hello: cleared, a
// remembered shape with it is forgotten.
func rememberedShape() *handshake.Shape {
	s := upstreamShapes.Last()
	if s != nil && s.Hello == handshake.HelloGo && !upstreamGoTLS.Load() {
		return nil
	}
	return s
}

func rememberShape(s handshake.Shape) {
	upstreamGoTLS.Store(s.Hello == handshake.HelloGo)
	changed, err := upstreamShapes.Remember(s)
	if err != nil {
		logx.Warn("saving the upstream handshake shape failed err=%s", logx.Err(err))
	}
	if changed {
		logx.Info("upstream handshake shape that connects shape=%s", s)
	}
}

// upstreamHandshakeError marks a failure of TLS itself, which another shape
// may get past; a failure to connect is not one.
type upstreamHandshakeError struct{ err error }

func (e *upstreamHandshakeError) Error() string { return e.err.Error() }
func (e *upstreamHandshakeError) Unwrap() error { return e.err }

// upstreamLink is a connection to the proxy with TLS done.
type upstreamLink struct {
	conn net.Conn
	raw  *watchedConn
}

// discard closes a link that came after another had won.
func (l upstreamLink) discard() { _ = l.conn.Close() }

// shakeFunc completes TLS on raw.
type shakeFunc func(ctx context.Context, raw net.Conn) (net.Conn, error)

// connectShape connects to proxyHost, sends the hello the way shape cuts it,
// and completes TLS with shake. It logs what the attempt learned: the
// address, the time to connect, and the time to the first byte the server
// sent back, which is missing when the network drops the hello.
func connectShape(ctx context.Context, shape handshake.Shape, proxyHost string, shake shakeFunc) (upstreamLink, error) {
	began := time.Now()
	dialed, err := resolver.Dial(ctx, "tcp", proxyHost)
	if err != nil {
		return upstreamLink{}, err
	}
	connected := time.Since(began)
	remote := "unknown"
	if addr := dialed.RemoteAddr(); addr != nil {
		remote = addr.String()
	}
	traced := handshake.Trace(dialed)
	raw := newWatchedConn(hellosplit.WrapWith(traced, shape.Split))
	conn, err := shake(ctx, raw)

	firstReply := "none"
	if reply, ok := traced.Reply(); ok {
		firstReply = reply.Round(time.Millisecond).String()
	}
	took := time.Since(began).Round(time.Millisecond)
	switch {
	case err == nil && ctx.Err() != nil:
		logx.Debug("upstream TLS finished after another shape had connected proxy=%s shape=%s", proxyHost, shape)
	case err == nil:
		logx.Info("upstream TLS established proxy=%s ip=%s shape=%s tcp_connect=%s first_reply=%s total=%s",
			proxyHost, remote, shape, connected.Round(time.Millisecond), firstReply, took)
	case errors.Is(err, context.Canceled):
		logx.Debug("upstream TLS cancelled, another shape connected first proxy=%s ip=%s shape=%s", proxyHost, remote, shape)
	default:
		logx.Info("upstream TLS failed proxy=%s ip=%s shape=%s tcp_connect=%s first_reply=%s total=%s err=%s",
			proxyHost, remote, shape, connected.Round(time.Millisecond), firstReply, took, logx.Err(err))
	}
	if err != nil {
		_ = raw.Close()
		if errors.Is(err, errProxyHTTP2Unavailable) {
			return upstreamLink{}, err
		}
		return upstreamLink{}, &upstreamHandshakeError{err}
	}
	return upstreamLink{conn: conn, raw: raw}, nil
}

// dialShape makes one connection to proxyHost in shape; name is the proxy's
// name (the server name of TLS).
func dialShape(ctx context.Context, shape handshake.Shape, proxyHost, name string) (upstreamLink, error) {
	switch {
	case shape.ECH:
		return dialECHShape(ctx, shape, proxyHost, name)
	case shape.Hello == handshake.HelloGo:
		return connectShape(ctx, shape, proxyHost, func(ctx context.Context, raw net.Conn) (net.Conn, error) {
			return goHandshake(ctx, raw, name)
		})
	}
	return connectShape(ctx, shape, proxyHost, func(ctx context.Context, raw net.Conn) (net.Conn, error) {
		return firefoxHandshake(ctx, raw, name)
	})
}

// dialECHShape connects with Encrypted Client Hello: the network sees the
// public name of the proxy's ECH key, not the proxy's. A stale key is
// refused with the current one, which gets one more connection.
func dialECHShape(ctx context.Context, shape handshake.Shape, proxyHost, name string) (upstreamLink, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, echLookupTimeout)
	key, err := upstreamECH.Get(lookupCtx, name)
	cancel()
	if err != nil {
		return upstreamLink{}, &upstreamHandshakeError{fmt.Errorf("no ECH key for %s: %w", name, err)}
	}
	link, err := connectShape(ctx, shape, proxyHost, echShake(name, key))
	if retry := handshake.RetryKey(err); retry != nil {
		upstreamECH.Set(name, retry)
		link, err = connectShape(ctx, shape, proxyHost, echShake(name, retry))
	}
	return link, err
}

// echShake completes TLS with the ECH key, for h2.
func echShake(name string, key []byte) shakeFunc {
	return func(ctx context.Context, raw net.Conn) (net.Conn, error) {
		conn, err := handshake.ECHHandshake(ctx, raw, name, upstreamRoots.Load(), key)
		if err != nil {
			return nil, err
		}
		if conn.ConnectionState().NegotiatedProtocol != "h2" {
			return nil, errProxyHTTP2Unavailable
		}
		return conn, nil
	}
}

// dialUpstreamTLS connects to proxyHost and completes TLS with proxyURL's
// name, for HTTP/2. It starts with the shape that worked last, or with the
// Firefox hello its User-Agent says it is; shapes that fail, or that have not
// answered by the time upstreamShapeStagger passes, are followed by the
// next shape, and the first connection to complete wins. A failure to
// connect ends it: no other shape would get through.
func dialUpstreamTLS(ctx context.Context, proxyURL *url.URL, proxyHost string) (net.Conn, *watchedConn, error) {
	name := proxyURL.Hostname()
	echMaybe := handshake.ECHEligible(name) && !upstreamECH.Absent(name)
	shapes := handshake.Order(handshake.Shapes(hellosplit.Configured(), echMaybe), rememberedShape())
	attempts := make([]dialrace.Attempt[upstreamLink], len(shapes))
	for i, shape := range shapes {
		attempts[i] = dialrace.Attempt[upstreamLink]{
			Name: shape.String(),
			Run: func(ctx context.Context) (upstreamLink, error) {
				return dialShape(ctx, shape, proxyHost, name)
			},
		}
	}
	won, err := dialrace.Race(ctx, attempts, dialrace.Options[upstreamLink]{
		Stagger: upstreamShapeStagger,
		Fatal: func(err error) bool {
			var failed *upstreamHandshakeError
			return !errors.As(err, &failed)
		},
		Discard: upstreamLink.discard,
	})
	if err != nil {
		return nil, nil, err
	}
	rememberShape(shapes[won.Index])
	return won.Value.conn, won.Value.raw, nil
}
