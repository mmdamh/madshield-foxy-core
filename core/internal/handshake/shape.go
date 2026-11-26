// Package handshake is what the program's connections to Mozilla's proxy
// vary when a network keeps one of them from completing TLS: the hello that
// is sent (Firefox's, Go's), the way it is cut into segments, and Encrypted
// Client Hello, which hides the proxy's name. A Shape is one such choice; the
// connection race (package dialrace) tries several at once, and Memory keeps
// the one that worked so the next connection starts with it.
package handshake

import (
	"net"
	"strings"

	"github.com/mmdamh/madshield-foxy-core/core/internal/hellosplit"
)

// The hellos a Shape can send.
const (
	HelloFirefox = "firefox"
	HelloGo      = "go"
)

// Shape is one way to make the TLS handshake with the proxy.
type Shape struct {
	// Hello is HelloFirefox (uTLS, Firefox's ClientHello) or HelloGo.
	Hello string `json:"hello"`
	// Split is how the ClientHello is cut (a hellosplit mode); empty is the
	// way network.hello_split sets.
	Split string `json:"split,omitempty"`
	// ECH sends the hello with Encrypted Client Hello (always Go's: uTLS
	// has no client side of it).
	ECH bool `json:"ech,omitempty"`
}

// String names the shape in logs: "firefox/default", "go/record",
// "go+ech/default".
func (s Shape) String() string {
	name := s.Hello
	if s.ECH {
		name += "+ech"
	}
	split := s.Split
	if split == "" {
		split = "default"
	}
	return name + "/" + split
}

// valid reports whether s is a shape this package makes.
func (s Shape) valid() bool {
	if s.Hello != HelloFirefox && s.Hello != HelloGo {
		return false
	}
	if s.ECH && s.Hello != HelloGo {
		return false
	}
	return hellosplit.Valid(s.Split)
}

// otherSplits are the ways to cut the hello that the race tries besides the
// configured one, most different from "whole or at the name" first.
var otherSplits = []string{hellosplit.Record, hellosplit.FirstByte, hellosplit.Off, hellosplit.SNI}

// Shapes lists the shapes to try, in the order they start when none is
// remembered: Firefox's hello and Go's with the configured split, then ECH
// when ech says the proxy's name may have a key, then the other splits.
func Shapes(configured string, ech bool) []Shape {
	out := []Shape{{Hello: HelloFirefox}, {Hello: HelloGo}}
	if ech {
		out = append(out, Shape{Hello: HelloGo, ECH: true})
	}
	if configured == "" {
		configured = hellosplit.Off
	}
	for _, split := range otherSplits {
		if split == configured {
			continue
		}
		out = append(out, Shape{Hello: HelloGo, Split: split}, Shape{Hello: HelloFirefox, Split: split})
	}
	return out
}

// Order puts the remembered shape (nil: none) first and the others after it
// in their order. A remembered shape that shapes does not list (an ECH one
// for a name without a key) is left out.
func Order(shapes []Shape, remembered *Shape) []Shape {
	out := make([]Shape, 0, len(shapes))
	if remembered != nil {
		for _, s := range shapes {
			if s == *remembered {
				out = append(out, s)
				break
			}
		}
	}
	for _, s := range shapes {
		if len(out) > 0 && s == out[0] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// ECHEligible reports whether host, a proxy's name, can have an ECH key in
// DNS: it is a domain name, not an address or a bare label.
func ECHEligible(host string) bool {
	host = strings.TrimSuffix(host, ".")
	return host != "" && strings.Contains(host, ".") && net.ParseIP(host) == nil
}
