package proxy

import (
	"context"
	"net/url"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/dialrace"
	"github.com/mmdamh/madshield-foxy-core/core/internal/logx"
)

// A network can cut the connection to one Mozilla server and not to the
// next, and a server that does not answer holds a connection for its whole
// timeout. So the first session is not made on one server and waited for:
// the selected server starts, and other servers of the location (or the
// stand-ins of the recommended location) start after serverRaceStagger, or
// when the one before has failed; the first session that is established
// wins.

// serverRaceStagger is how long a server runs alone before the next starts.
// A variable for the tests.
var serverRaceStagger = 2500 * time.Millisecond

// maxRaceServers is how many servers a race has at most, the selected one
// included.
const maxRaceServers = 3

// sessionDialer opens one session to target and gives up when ctx is done.
type sessionDialer func(ctx context.Context, target *url.URL, token string) (proxySession, error)

// serverWin is the session that was established first, and its server.
type serverWin struct {
	server  Candidate
	target  *url.URL
	session proxySession
}

// RaceCandidates picks up to max-1 servers to race the selected one against:
// those nextServer would move to (its city's other servers, then the
// location's next cities, then the stand-ins), skipping avoided ones.
func RaceCandidates(location, fallback []Candidate, selected Candidate, avoided func(addr string) bool, max int) []Candidate {
	choices := append(append([]Candidate(nil), location...), fallback...)
	var out []Candidate
	taken := func(addr string) bool {
		key, err := canonicalProxyAddr(addr)
		if err != nil {
			return true
		}
		for _, c := range out {
			if k, err := canonicalProxyAddr(c.Addr); err == nil && k == key {
				return true
			}
		}
		return avoided != nil && avoided(addr)
	}
	for len(out)+1 < max {
		next, ok := nextServer(choices, selected, taken)
		if !ok {
			break
		}
		out = append(out, next)
	}
	return out
}

// raceServers opens the first session. With no cfg.Race it is one dial to
// cfg.Server; else the servers race as described above. A failure that is
// not a server's (no network, a refused pass) ends the race: another server
// would fail the same way.
func raceServers(ctx context.Context, cfg ControllerConfig, dial sessionDialer) (serverWin, error) {
	first := cfg.Server
	if first.Addr == "" {
		first.Addr = cfg.ProxyURL.Host
	}
	type entry struct {
		server Candidate
		target *url.URL
	}
	entries := []entry{{first, cfg.ProxyURL}}
	seen := map[string]bool{}
	if key, err := canonicalProxyAddr(first.Addr); err == nil {
		seen[key] = true
	}
	for _, candidate := range cfg.Race {
		key, err := canonicalProxyAddr(candidate.Addr)
		if err != nil || seen[key] {
			continue
		}
		target, err := NormalizeURL(candidate.Addr)
		if err != nil {
			continue
		}
		seen[key] = true
		entries = append(entries, entry{candidate, target})
	}
	if len(entries) == 1 {
		session, err := dial(ctx, cfg.ProxyURL, cfg.Pass.RawToken)
		if err != nil {
			return serverWin{}, err
		}
		return serverWin{server: first, target: cfg.ProxyURL, session: session}, nil
	}

	attempts := make([]dialrace.Attempt[proxySession], len(entries))
	for i, e := range entries {
		attempts[i] = dialrace.Attempt[proxySession]{
			Name: e.server.Addr,
			Run: func(ctx context.Context) (proxySession, error) {
				return dial(ctx, e.target, cfg.Pass.RawToken)
			},
		}
	}
	won, err := dialrace.Race(ctx, attempts, dialrace.Options[proxySession]{
		Stagger: serverRaceStagger,
		Fatal:   func(err error) bool { return !serverFault(err) },
		Discard: func(session proxySession) { _ = session.Close() },
		Observe: func(o dialrace.Outcome) {
			if o.Err != nil {
				logx.Info("upstream server did not connect proxy=%s after=%s err=%s",
					o.Name, o.Elapsed.Round(time.Millisecond), logx.Err(o.Err))
			}
		},
	})
	if err != nil {
		return serverWin{}, err
	}
	logx.Info("upstream server connected first proxy=%s after=%s servers=%d",
		entries[won.Index].server.Addr, won.Elapsed.Round(time.Millisecond), len(entries))
	e := entries[won.Index]
	return serverWin{server: e.server, target: e.target, session: won.Value}, nil
}
