package handshake

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
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/hellosplit"
)

func TestShapesStartWithTheDefaultsAndLeaveOutTheConfiguredSplit(t *testing.T) {
	got := Shapes(hellosplit.SNI, false)
	if got[0] != (Shape{Hello: HelloFirefox}) || got[1] != (Shape{Hello: HelloGo}) {
		t.Fatalf("first shapes: %v", got[:2])
	}
	for _, s := range got {
		if s.Split == hellosplit.SNI {
			t.Errorf("%v repeats the configured split", s)
		}
		if s.ECH {
			t.Errorf("%v: ECH without a key", s)
		}
	}
	seen := map[Shape]bool{}
	for _, s := range got {
		if seen[s] {
			t.Errorf("%v is listed twice", s)
		}
		seen[s] = true
		if !s.valid() {
			t.Errorf("%v is not valid", s)
		}
	}
	// record, first-byte and off, each with both hellos, besides the defaults.
	if len(got) != 2+3*2 {
		t.Errorf("%d shapes: %v", len(got), got)
	}
}

func TestShapesPutECHAfterTheTwoDefaults(t *testing.T) {
	got := Shapes("", true)
	if got[2] != (Shape{Hello: HelloGo, ECH: true}) {
		t.Fatalf("third shape: %v", got[2])
	}
	// Off configured: the "off" split is the default, not another way.
	for _, s := range got {
		if s.Split == hellosplit.Off {
			t.Errorf("%v repeats the configured split", s)
		}
	}
}

func TestOrderPutsTheRememberedFirstOnce(t *testing.T) {
	shapes := Shapes(hellosplit.SNI, false)
	remembered := Shape{Hello: HelloGo, Split: hellosplit.Record}
	got := Order(shapes, &remembered)
	if got[0] != remembered {
		t.Fatalf("first: %v", got[0])
	}
	if len(got) != len(shapes) {
		t.Fatalf("%d shapes, want %d", len(got), len(shapes))
	}
	if !slices.Equal(got[1:3], shapes[:2]) {
		t.Fatalf("the rest keeps its order: %v", got[1:3])
	}

	// Nothing remembered, or something that is not listed: the list as is.
	if !slices.Equal(Order(shapes, nil), shapes) {
		t.Fatal("nil changed the order")
	}
	ech := Shape{Hello: HelloGo, ECH: true}
	if !slices.Equal(Order(shapes, &ech), shapes) {
		t.Fatal("an unlisted shape was added")
	}
	// The default as remembered stays where it is.
	def := shapes[0]
	if !slices.Equal(Order(shapes, &def), shapes) {
		t.Fatal("remembering the first changed the order")
	}
}

func TestECHEligible(t *testing.T) {
	for host, want := range map[string]bool{
		"p.m1.fastly-masque.net": true,
		"example.com.":           true,
		"127.0.0.1":              false,
		"::1":                    false,
		"localhost":              false,
		"":                       false,
	} {
		if got := ECHEligible(host); got != want {
			t.Errorf("ECHEligible(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestMemoryKeepsTheShapeAcrossRestarts(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sub", "shape.json")
	var m Memory
	if err := m.Load(file); err != nil {
		t.Fatalf("no file is not an error: %v", err)
	}
	if m.Last() != nil {
		t.Fatal("remembered something from nothing")
	}
	shape := Shape{Hello: HelloGo, Split: hellosplit.Record, ECH: true}
	changed, err := m.Remember(shape)
	if err != nil || !changed {
		t.Fatalf("Remember = %v, %v", changed, err)
	}
	if changed, _ := m.Remember(shape); changed {
		t.Fatal("the same shape counted as a change")
	}
	var next Memory
	if err := next.Load(file); err != nil {
		t.Fatal(err)
	}
	if got := next.Last(); got == nil || *got != shape {
		t.Fatalf("after a restart: %v", got)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v %v", info, err)
	}
}

func TestMemoryIgnoresAFileThatIsNotAShape(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"garbage":     "not json",
		"unknown":     `{"hello":"curl"}`,
		"ech-firefox": `{"hello":"firefox","ech":true}`,
		"bad-split":   `{"hello":"go","split":"sideways"}`,
	} {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		var m Memory
		_ = m.Load(file)
		if m.Last() != nil {
			t.Errorf("%s: remembered %v", name, m.Last())
		}
	}
}

func TestMemoryWithoutAFileRemembersInMemory(t *testing.T) {
	var m Memory
	if _, err := m.Remember(Shape{Hello: HelloFirefox}); err != nil {
		t.Fatal(err)
	}
	if m.Last() == nil {
		t.Fatal("not remembered")
	}
	m.Forget()
	if m.Last() != nil {
		t.Fatal("not forgotten")
	}
}

func TestECHKeysLookUpOnceWhileFresh(t *testing.T) {
	now := time.Unix(1000, 0)
	var calls atomic.Int32
	keys := &ECHKeys{
		Lookup: func(_ context.Context, host string) ([]byte, time.Duration, error) {
			calls.Add(1)
			return []byte("key-of-" + host), 5 * time.Minute, nil
		},
		now: func() time.Time { return now },
	}
	for range 3 {
		key, err := keys.Get(context.Background(), "a.example")
		if err != nil || string(key) != "key-of-a.example" {
			t.Fatalf("Get = %q, %v", key, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("%d lookups", calls.Load())
	}
	now = now.Add(6 * time.Minute)
	if _, err := keys.Get(context.Background(), "a.example"); err != nil || calls.Load() != 2 {
		t.Fatalf("an expired key was not looked up again: %d lookups, %v", calls.Load(), err)
	}
}

func TestECHKeysRemembersAMissingKey(t *testing.T) {
	errMissing := errors.New("no ECH key")
	now := time.Unix(1000, 0)
	var calls atomic.Int32
	keys := &ECHKeys{
		Lookup: func(context.Context, string) ([]byte, time.Duration, error) {
			calls.Add(1)
			return nil, 0, errMissing
		},
		Missing: errMissing,
		now:     func() time.Time { return now },
	}
	if keys.Absent("a.example") {
		t.Fatal("absent before asking")
	}
	for range 3 {
		if _, err := keys.Get(context.Background(), "a.example"); !errors.Is(err, errMissing) {
			t.Fatalf("Get err = %v", err)
		}
	}
	if calls.Load() != 1 || !keys.Absent("a.example") {
		t.Fatalf("%d lookups, absent=%v", calls.Load(), keys.Absent("a.example"))
	}
	now = now.Add(2 * time.Hour)
	if keys.Absent("a.example") {
		t.Fatal("absent forever")
	}
}

// Another failure (DNS not reachable) is retried soon, and is not "absent":
// the shape stays in the race.
func TestECHKeysRetriesOtherFailures(t *testing.T) {
	now := time.Unix(1000, 0)
	var calls atomic.Int32
	keys := &ECHKeys{
		Lookup: func(context.Context, string) ([]byte, time.Duration, error) {
			calls.Add(1)
			return nil, 0, errors.New("dns timeout")
		},
		Missing: errors.New("no ECH key"),
		now:     func() time.Time { return now },
	}
	_, _ = keys.Get(context.Background(), "a.example")
	_, _ = keys.Get(context.Background(), "a.example")
	if calls.Load() != 1 || keys.Absent("a.example") {
		t.Fatalf("%d lookups, absent=%v", calls.Load(), keys.Absent("a.example"))
	}
	now = now.Add(2 * time.Minute)
	_, _ = keys.Get(context.Background(), "a.example")
	if calls.Load() != 2 {
		t.Fatalf("%d lookups after the retry time", calls.Load())
	}
}

func TestECHKeysDoesNotKeepACancelledLookup(t *testing.T) {
	var calls atomic.Int32
	keys := &ECHKeys{Lookup: func(ctx context.Context, _ string) ([]byte, time.Duration, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = keys.Get(ctx, "a.example")
	_, _ = keys.Get(ctx, "a.example")
	if calls.Load() != 2 {
		t.Fatalf("%d lookups: a cancelled one was kept as the answer", calls.Load())
	}
}

func TestECHKeysSetReplacesTheKey(t *testing.T) {
	keys := &ECHKeys{Lookup: func(context.Context, string) ([]byte, time.Duration, error) {
		return []byte("old"), time.Hour, nil
	}}
	_, _ = keys.Get(context.Background(), "a.example")
	keys.Set("a.example", []byte("new"))
	if key, _ := keys.Get(context.Background(), "a.example"); string(key) != "new" {
		t.Fatalf("key = %q", key)
	}
}

const (
	testName       = "proxy.test"
	testPublicName = "public.test"
)

// echKey makes an ECH key for testPublicName: the server's half, and the
// ECHConfigList a client gets from DNS.
func echKey(t *testing.T, id byte) (tls.EncryptedClientHelloKey, []byte) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u16 := func(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) }
	var contents []byte
	contents = append(contents, id)
	contents = u16(contents, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	pub := priv.PublicKey().Bytes()
	contents = u16(contents, len(pub))
	contents = append(contents, pub...)
	contents = u16(contents, 4)
	contents = u16(contents, 0x0001) // HKDF-SHA256
	contents = u16(contents, 0x0001) // AES-128-GCM
	contents = append(contents, 0)   // maximum_name_length
	contents = append(contents, byte(len(testPublicName)))
	contents = append(contents, testPublicName...)
	contents = u16(contents, 0) // no extensions
	config := u16(u16(nil, 0xfe0d), len(contents))
	config = append(config, contents...)
	list := append(u16(nil, len(config)), config...)
	return tls.EncryptedClientHelloKey{Config: config, PrivateKey: priv.Bytes(), SendAsRetry: true}, list
}

type seen struct {
	serverName string
	ech        bool
	protocol   string
}

// echServer runs a TLS 1.3 h2 server for testName and testPublicName that
// takes ECH with keys; it returns its address, a pool trusting it, and what
// it saw of each handshake.
func echServer(t *testing.T, keys ...tls.EncryptedClientHelloKey) (string, *x509.CertPool, chan seen) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testName},
		DNSNames:              []string{testName, testPublicName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:             []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		EncryptedClientHelloKeys: keys,
		MinVersion:               tls.VersionTLS12,
		NextProtos:               []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	handshakes := make(chan seen, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn *tls.Conn) {
				defer conn.Close()
				if conn.Handshake() != nil {
					return
				}
				st := conn.ConnectionState()
				handshakes <- seen{st.ServerName, st.ECHAccepted, st.NegotiatedProtocol}
				_, _ = conn.Write([]byte("ok"))
			}(conn.(*tls.Conn))
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return ln.Addr().String(), roots, handshakes
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestECHHandshakeHidesTheName(t *testing.T) {
	key, list := echKey(t, 1)
	addr, roots, handshakes := echServer(t, key)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := ECHHandshake(ctx, dial(t, addr), testName, roots, list)
	if err != nil {
		t.Fatal(err)
	}
	st := conn.ConnectionState()
	if !st.ECHAccepted || st.NegotiatedProtocol != "h2" || st.Version != tls.VersionTLS13 {
		t.Fatalf("client state: ech=%v proto=%q version=%x", st.ECHAccepted, st.NegotiatedProtocol, st.Version)
	}
	if got := <-handshakes; !got.ech || got.serverName != testName {
		t.Fatalf("server saw %+v", got)
	}
}

// A stale key is refused with the current one, and a second handshake with
// it completes.
func TestECHHandshakeStaleKeyGivesTheCurrentOne(t *testing.T) {
	_, stale := echKey(t, 1)
	current, currentList := echKey(t, 2)
	addr, roots, _ := echServer(t, current)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := ECHHandshake(ctx, dial(t, addr), testName, roots, stale)
	if err == nil {
		t.Fatal("a stale key was accepted")
	}
	retry := RetryKey(err)
	if len(retry) == 0 {
		t.Fatalf("no key in the refusal: %v", err)
	}
	if _, err := ECHHandshake(ctx, dial(t, addr), testName, roots, retry); err != nil {
		t.Fatalf("with the server's key: %v", err)
	}
	_ = currentList
	if RetryKey(errors.New("other")) != nil || RetryKey(nil) != nil {
		t.Fatal("RetryKey found a key in what is not a refusal")
	}
}

// A server without ECH refuses the handshake rather than answering with a
// hello that shows the name.
func TestECHHandshakeWithoutServerSupportFails(t *testing.T) {
	_, list := echKey(t, 1)
	addr, roots, _ := echServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := ECHHandshake(ctx, dial(t, addr), testName, roots, list); err == nil {
		t.Fatal("completed without ECH")
	}
}

func TestTraceTimesTheFirstReply(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	traced := Trace(client)
	if _, ok := traced.Reply(); ok {
		t.Fatal("a reply before anything was written")
	}
	go func() {
		buf := make([]byte, len("hello")) // net.Pipe is synchronous: read it all
		_, _ = io.ReadFull(server, buf)
		time.Sleep(30 * time.Millisecond)
		_, _ = server.Write([]byte("hi"))
	}()
	if _, err := traced.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, ok := traced.Reply(); ok {
		t.Fatal("a reply before the server answered")
	}
	buf := make([]byte, 2)
	if _, err := traced.Read(buf); err != nil {
		t.Fatal(err)
	}
	reply, ok := traced.Reply()
	if !ok || reply < 25*time.Millisecond || reply > 5*time.Second {
		t.Fatalf("Reply = %v, %v", reply, ok)
	}
}
