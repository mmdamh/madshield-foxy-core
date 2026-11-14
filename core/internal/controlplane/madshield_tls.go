package controlplane

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/dicttls"
)

// MadShield hook: the requests to Mozilla's account and Guardian servers carry a Firefox
// User-Agent, so the TLS under them should look like Firefox's too. Go's own ClientHello does not, and Mozilla's edge
// (Fastly) answers a client whose hello and User-Agent disagree with HTTP 406. The hello below is the one the data-plane
// connections already use (package proxy keeps its own copy; it cannot be imported here).

var browserSessions = utls.NewLRUClientSessionCache(64)

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// browserTLS is a DialTLSContext: it connects with connect and completes TLS with Firefox's hello within wait. A
// network or server that does not take that hello gets Go's own for this connection (nothing is remembered: one bad
// connection must not give up the Firefox look for good). HTTP/1.1 only: net/http speaks HTTP/2 just over its own TLS.
func browserTLS(connect dialFunc, wait time.Duration) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		raw, err := connect(ctx, network, address)
		if err != nil {
			return nil, err
		}
		shakeCtx, cancel := context.WithTimeout(ctx, wait)
		conn, err := browserHandshake(shakeCtx, raw, host)
		cancel()
		if err == nil {
			return conn, nil
		}
		_ = raw.Close()
		if ctx.Err() != nil {
			return nil, err
		}
		raw, err = connect(ctx, network, address)
		if err != nil {
			return nil, err
		}
		shakeCtx, cancel = context.WithTimeout(ctx, wait)
		defer cancel()
		plain := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
		if err := plain.HandshakeContext(shakeCtx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return plain, nil
	}
}

func browserHandshake(ctx context.Context, raw net.Conn, host string) (net.Conn, error) {
	conn := utls.UClient(raw, &utls.Config{
		ServerName:         host,
		ClientSessionCache: browserSessions,
		OmitEmptyPsk:       true,
	}, utls.HelloCustom)
	if err := conn.ApplyPreset(browserHello()); err != nil {
		return nil, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

// browserHello is desktop Firefox's ClientHello, in its order. A spec is good for one connection.
func browserHello() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512, utls.ECDSAWithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768}, {Group: utls.X25519}, {Group: utls.CurveP256},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256, utls.PSSWithSHA384, utls.PSSWithSHA512,
				utls.PKCS1WithSHA256, utls.PKCS1WithSHA384, utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1, utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib, utls.CertCompressionBrotli, utls.CertCompressionZstd,
			}},
			&utls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
					{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
					{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
				},
				CandidatePayloadLens: []uint16{224},
			},
			&utls.UtlsPreSharedKeyExtension{},
		},
	}
}
