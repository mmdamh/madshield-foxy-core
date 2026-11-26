package handshake

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	// echKeyMinTTL and echKeyMaxTTL bound how long a key from DNS is kept,
	// as for the API relay's: a server that refuses a stale key sends the
	// current one.
	echKeyMinTTL = time.Minute
	echKeyMaxTTL = time.Hour
	// echKeyRetry is how long a failed lookup stands. A name that has no
	// key stands echKeyMaxTTL: the race should not ask DNS again for it on
	// each connection.
	echKeyRetry = time.Minute
)

// ECHKeys finds and keeps the ECH keys (ECHConfigLists) of the names the
// program connects to.
type ECHKeys struct {
	// Lookup gets the key of host from DNS, with its TTL.
	Lookup func(ctx context.Context, host string) ([]byte, time.Duration, error)
	// Missing is the error Lookup returns for a name that has no key.
	Missing error

	mu      sync.Mutex
	entries map[string]echEntry
	// now is the clock; tests replace it.
	now func() time.Time
}

type echEntry struct {
	key     []byte
	err     error
	missing bool
	expires time.Time
}

func (k *ECHKeys) clock() time.Time {
	if k.now != nil {
		return k.now()
	}
	return time.Now()
}

// Get returns host's key: the one kept while it is fresh, else a new
// lookup. An error is kept for echKeyRetry (echKeyMaxTTL when host has no
// key), so a name without one costs one lookup.
func (k *ECHKeys) Get(ctx context.Context, host string) ([]byte, error) {
	k.mu.Lock()
	if e, ok := k.entries[host]; ok && k.clock().Before(e.expires) {
		k.mu.Unlock()
		return e.key, e.err
	}
	k.mu.Unlock()

	key, ttl, err := k.Lookup(ctx, host)
	k.mu.Lock()
	defer k.mu.Unlock()
	if err != nil {
		if ctx.Err() == nil {
			missing := k.Missing != nil && errors.Is(err, k.Missing)
			wait := echKeyRetry
			if missing {
				wait = echKeyMaxTTL
			}
			k.store(host, echEntry{err: err, missing: missing, expires: k.clock().Add(wait)})
		}
		return nil, err
	}
	k.store(host, echEntry{key: key, expires: k.clock().Add(min(echKeyMaxTTL, max(echKeyMinTTL, ttl)))})
	return key, nil
}

// Set keeps key, the current one a server sent when it refused a stale
// key, for host.
func (k *ECHKeys) Set(host string, key []byte) {
	k.mu.Lock()
	k.store(host, echEntry{key: key, expires: k.clock().Add(echKeyMaxTTL)})
	k.mu.Unlock()
}

func (k *ECHKeys) store(host string, e echEntry) {
	if k.entries == nil {
		k.entries = make(map[string]echEntry)
	}
	k.entries[host] = e
}

// Absent reports whether host is known not to have a key: its lookup said
// so, recently.
func (k *ECHKeys) Absent(host string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.entries[host]
	return ok && e.missing && k.clock().Before(e.expires)
}

// ECHHandshake completes TLS 1.3 with Encrypted Client Hello on raw, for the
// server name, offering h2. The network sees the key's public name in the
// hello, not name; the certificate is checked against name.
func ECHHandshake(ctx context.Context, raw net.Conn, name string, roots *x509.CertPool, key []byte) (*tls.Conn, error) {
	conn := tls.Client(raw, &tls.Config{
		RootCAs:                        roots,
		ServerName:                     name,
		MinVersion:                     tls.VersionTLS13,
		NextProtos:                     []string{"h2"},
		EncryptedClientHelloConfigList: key,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

// RetryKey returns the key a server sent in refusing ours (a stale one),
// when err is that refusal; nil otherwise.
func RetryKey(err error) []byte {
	var rejected *tls.ECHRejectionError
	if errors.As(err, &rejected) && len(rejected.RetryConfigList) > 0 {
		return rejected.RetryConfigList
	}
	return nil
}
