package proxy

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/handshake"
	"github.com/mmdamh/madshield-foxy-core/core/internal/hellosplit"
	"github.com/mmdamh/madshield-foxy-core/core/internal/resolver"
)

// fastStagger makes the race start the next shape soon, as the network that
// drops a hello makes it; the connections of these tests take a few
// milliseconds, so the first shape of a working server still wins alone.
func fastStagger(t *testing.T) {
	t.Helper()
	previous := upstreamShapeStagger
	upstreamShapeStagger = 200 * time.Millisecond
	t.Cleanup(func() { upstreamShapeStagger = previous })
}

func rememberedOrFail(t *testing.T) handshake.Shape {
	t.Helper()
	s := upstreamShapes.Last()
	if s == nil {
		t.Fatal("no shape was remembered")
	}
	return *s
}

// A network that drops the first shape's hello without a word does not hold
// the connection for the whole timeout: the next shape starts after the
// stagger, and is the one the next connection starts with.
func TestUpstreamRaceMovesPastAStalledShape(t *testing.T) {
	fastStagger(t)
	proxyURL, host, count := upstreamTLSServerWith(t, func(n int32) serverBehavior {
		if n == 1 {
			return stallConn
		}
		return serveTLS
	})
	began := time.Now()
	conn, _, err := dialUpstreamTLS(dialContext(t), proxyURL, host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("took %s: the stalled shape held the connection", took)
	}
	if got := rememberedOrFail(t); got != (handshake.Shape{Hello: handshake.HelloGo}) {
		t.Fatalf("remembered %v, want Go's hello with the configured split", got)
	}
	if !upstreamGoTLS.Load() {
		t.Fatal("Go's hello worked where Firefox's did not: the flag must say so")
	}

	before := count.Load()
	next, _, err := dialUpstreamTLS(dialContext(t), proxyURL, host)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if n := count.Load() - before; n != 1 {
		t.Fatalf("the second dial opened %d connections, want 1 (it must start with the shape that worked)", n)
	}
}

// Every shape is tried when the ones before it fail at once, and the one that
// works is remembered.
func TestUpstreamRaceTriesTheShapesInOrder(t *testing.T) {
	fastStagger(t)
	t.Cleanup(func() { hellosplit.Set(hellosplit.Off) })
	hellosplit.Set(hellosplit.SNI)
	proxyURL, host, count := upstreamTLSServer(t, func(n int32) bool { return n <= 3 })
	conn, _, err := dialUpstreamTLS(dialContext(t), proxyURL, host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// firefox/default, go/default, go/record fail; firefox/record is the 4th.
	want := handshake.Shapes(hellosplit.SNI, false)[3]
	if got := rememberedOrFail(t); got != want {
		t.Fatalf("remembered %v, want %v", got, want)
	}
	if n := count.Load(); n != 4 {
		t.Fatalf("%d connections, want 4", n)
	}
}

// A failure to connect ends the race: no other shape would connect.
func TestUpstreamRaceConnectFailureTriesNoOtherShape(t *testing.T) {
	fastStagger(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := listener.Addr().String()
	_ = listener.Close()
	forgetUpstreamShape()
	began := time.Now()
	if _, _, err := dialUpstreamTLS(dialContext(t), &url.URL{Scheme: "https", Host: "127.0.0.1"}, host); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	if time.Since(began) > 150*time.Millisecond {
		t.Fatalf("took %s: the race waited for the stagger", time.Since(began))
	}
	if upstreamShapes.Last() != nil {
		t.Fatal("a failure to connect says nothing about the shape")
	}
}

// What worked survives a restart of the program.
func TestUpstreamRaceSavesTheShape(t *testing.T) {
	fastStagger(t)
	proxyURL, host, _ := upstreamTLSServer(t, func(n int32) bool { return n == 1 })
	file := filepath.Join(t.TempDir(), "upstream_shape.json")
	SetUpstreamShapeFile(file)
	conn, _, err := dialUpstreamTLS(dialContext(t), proxyURL, host)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	want := rememberedOrFail(t)

	forgetUpstreamShape() // the program restarts
	if rememberedShape() != nil {
		t.Fatal("a fresh program remembered something")
	}
	SetUpstreamShapeFile(file)
	got := rememberedShape()
	if got == nil || *got != want {
		t.Fatalf("after a restart: %v, want %v", got, want)
	}
	if want.Hello == handshake.HelloGo && !upstreamGoTLS.Load() {
		t.Fatal("Go's hello was remembered but not switched on")
	}
}

// ECH test server and key, as the relay's tests have them: the server takes
// ECH for testECHPublicName and serves testECHName.
const (
	testECHName       = "proxy.test"
	testECHPublicName = "public.test"
)

func testECHKey(t *testing.T) (tls.EncryptedClientHelloKey, []byte) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u16 := func(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) }
	var contents []byte
	contents = append(contents, 1)
	contents = u16(contents, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	pub := priv.PublicKey().Bytes()
	contents = u16(contents, len(pub))
	contents = append(contents, pub...)
	contents = u16(contents, 4)
	contents = u16(contents, 0x0001) // HKDF-SHA256
	contents = u16(contents, 0x0001) // AES-128-GCM
	contents = append(contents, 0)   // maximum_name_length
	contents = append(contents, byte(len(testECHPublicName)))
	contents = append(contents, testECHPublicName...)
	contents = u16(contents, 0) // no extensions
	config := u16(u16(nil, 0xfe0d), len(contents))
	config = append(config, contents...)
	list := append(u16(nil, len(config)), config...)
	return tls.EncryptedClientHelloKey{Config: config, PrivateKey: priv.Bytes(), SendAsRetry: true}, list
}

// startECHProxy serves h2 over TLS with ECH on a loopback port, dropping the
// first drop connections before TLS, and trusts it. It returns its address,
// the connection count, and whether each completed handshake used ECH.
func startECHProxy(t *testing.T, drop int32, key tls.EncryptedClientHelloKey) (string, *atomic.Int32, chan bool) {
	t.Helper()
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testECHName},
		DNSNames:              []string{testECHName, testECHPublicName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &signing.PublicKey, signing)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	previous := upstreamRoots.Load()
	upstreamRoots.Store(pool)
	forgetUpstreamShape()
	t.Cleanup(func() { upstreamRoots.Store(previous); forgetUpstreamShape() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	config := &tls.Config{
		Certificates:             []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: signing}},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key},
		MinVersion:               tls.VersionTLS12,
		NextProtos:               []string{"h2"},
	}
	var count atomic.Int32
	usedECH := make(chan bool, 32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n := count.Add(1)
			go func() {
				defer conn.Close()
				if n <= drop {
					return
				}
				server := tls.Server(conn, config)
				if server.Handshake() != nil {
					return
				}
				usedECH <- server.ConnectionState().ECHAccepted
				_, _ = io.Copy(io.Discard, server)
			}()
		}
	}()
	return ln.Addr().String(), &count, usedECH
}

// useECHKeys replaces the keys DNS would give, for the test.
func useECHKeys(t *testing.T, lookup func(context.Context, string) ([]byte, time.Duration, error)) {
	t.Helper()
	previous := upstreamECH
	upstreamECH = &handshake.ECHKeys{Lookup: lookup, Missing: resolver.ErrNoECH}
	t.Cleanup(func() { upstreamECH = previous })
}

// When the proxy's name has an ECH key and the plain hellos fail, the third
// shape reaches it with ECH, and is the one remembered.
func TestUpstreamRaceReachesTheProxyWithECH(t *testing.T) {
	fastStagger(t)
	key, list := testECHKey(t)
	host, count, usedECH := startECHProxy(t, 2, key)
	var lookups atomic.Int32
	useECHKeys(t, func(_ context.Context, name string) ([]byte, time.Duration, error) {
		lookups.Add(1)
		if name != testECHName {
			t.Errorf("looked up %q", name)
		}
		return list, 5 * time.Minute, nil
	})
	conn, _, err := dialUpstreamTLS(dialContext(t), &url.URL{Scheme: "https", Host: testECHName}, host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := rememberedOrFail(t); got != (handshake.Shape{Hello: handshake.HelloGo, ECH: true}) {
		t.Fatalf("remembered %v, want Go's hello with ECH", got)
	}
	if !<-usedECH {
		t.Fatal("the server did not see ECH")
	}
	if count.Load() != 3 || lookups.Load() != 1 {
		t.Fatalf("%d connections and %d key lookups, want 3 and 1", count.Load(), lookups.Load())
	}
}

// A proxy name without an ECH key leaves that shape out of the next races, and
// the race goes on with the next shape.
func TestUpstreamRaceLeavesOutECHWithoutAKey(t *testing.T) {
	fastStagger(t)
	key, _ := testECHKey(t)
	host, _, _ := startECHProxy(t, 2, key)
	var lookups atomic.Int32
	useECHKeys(t, func(context.Context, string) ([]byte, time.Duration, error) {
		lookups.Add(1)
		return nil, 0, resolver.ErrNoECH
	})
	proxyURL := &url.URL{Scheme: "https", Host: testECHName}
	conn, _, err := dialUpstreamTLS(dialContext(t), proxyURL, host)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := rememberedOrFail(t); got.ECH {
		t.Fatalf("remembered %v without a key", got)
	}
	if !upstreamECH.Absent(testECHName) {
		t.Fatal("the missing key was not kept")
	}
	forgetUpstreamShape()
	next, _, err := dialUpstreamTLS(dialContext(t), proxyURL, host)
	if err != nil {
		t.Fatal(err)
	}
	_ = next.Close()
	if lookups.Load() != 1 {
		t.Fatalf("%d lookups, want 1: the name has no key", lookups.Load())
	}
}
