package proxy

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/guardian"
)

type raceSession struct{ closed atomic.Bool }

func (s *raceSession) OpenTunnel(string) (net.Conn, error) {
	return nil, errors.New("not a real session")
}
func (s *raceSession) Close() error { s.closed.Store(true); return nil }

func raceServer(addr, city string) Candidate {
	return Candidate{Addr: addr, CountryName: "Netherlands", CountryCode: "NL", CityName: city, CityCode: city}
}

func raceConfig(selected Candidate, others ...Candidate) ControllerConfig {
	target, _ := NormalizeURL(selected.Addr)
	return ControllerConfig{
		ProxyURL: target,
		Server:   selected,
		Race:     others,
		Pass:     &guardian.ProxyPassInfo{RawToken: "token"},
	}
}

func fastServerStagger(t *testing.T) {
	t.Helper()
	previous := serverRaceStagger
	serverRaceStagger = 100 * time.Millisecond
	t.Cleanup(func() { serverRaceStagger = previous })
}

func TestRaceCandidatesPreferTheSameCityThenOthers(t *testing.T) {
	selected := raceServer("a.example:443", "ams")
	sameCity := raceServer("b.example:443", "ams")
	otherCity := raceServer("c.example:443", "rtm")
	standIn := Candidate{Addr: "d.example:443", CountryName: "Germany", CountryCode: "DE", CityName: "fra", CityCode: "fra"}
	location := []Candidate{selected, sameCity, otherCity}

	got := RaceCandidates(location, []Candidate{standIn}, selected, nil, 3)
	if len(got) != 2 || got[0].Addr != sameCity.Addr || got[1].Addr != otherCity.Addr {
		t.Fatalf("candidates = %v", got)
	}
	// The selected server is never its own rival, and the limit counts it.
	if got := RaceCandidates(location, nil, selected, nil, 2); len(got) != 1 {
		t.Fatalf("max 2: %v", got)
	}
	// Avoided servers are skipped; stand-ins follow the location's own.
	avoided := func(addr string) bool { return addr == sameCity.Addr }
	got = RaceCandidates(location, []Candidate{standIn}, selected, avoided, 4)
	if len(got) != 2 || got[0].Addr != otherCity.Addr || got[1].Addr != standIn.Addr {
		t.Fatalf("with an avoided server: %v", got)
	}
	// A location with one server and no stand-ins has nothing to race.
	if got := RaceCandidates([]Candidate{selected}, nil, selected, nil, 3); len(got) != 0 {
		t.Fatalf("alone: %v", got)
	}
}

func TestRaceServersAloneDialsTheSelectedServer(t *testing.T) {
	selected := raceServer("a.example:443", "ams")
	var dialed []string
	win, err := raceServers(context.Background(), raceConfig(selected), func(_ context.Context, target *url.URL, token string) (proxySession, error) {
		dialed = append(dialed, target.Host+"/"+token)
		return &raceSession{}, nil
	})
	if err != nil || win.server.Addr != selected.Addr || len(dialed) != 1 || dialed[0] != "a.example:443/token" {
		t.Fatalf("win %+v, dialed %v, err %v", win, dialed, err)
	}
}

// The server that does not answer does not hold the connection: the next one
// starts after the stagger, wins, and the first is cancelled.
func TestRaceServersMovesPastAServerThatDoesNotAnswer(t *testing.T) {
	fastServerStagger(t)
	stalled := raceServer("blocked.example:443", "ams")
	working := raceServer("ok.example:443", "rtm")
	cancelled := make(chan struct{})
	win, err := raceServers(context.Background(), raceConfig(stalled, working), func(ctx context.Context, target *url.URL, _ string) (proxySession, error) {
		if target.Host == "blocked.example:443" {
			<-ctx.Done()
			close(cancelled)
			return nil, ctx.Err()
		}
		return &raceSession{}, nil
	})
	if err != nil || win.server.Addr != working.Addr || win.target.Host != "ok.example:443" {
		t.Fatalf("win %+v err %v", win, err)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the server that did not answer was not cancelled")
	}
}

// A server that fails at once passes the turn at once; a session that
// connects after another has won is closed.
func TestRaceServersClosesTheSessionsThatLost(t *testing.T) {
	fastServerStagger(t)
	slow := raceServer("slow.example:443", "ams")
	fast := raceServer("fast.example:443", "rtm")
	release := make(chan struct{})
	var mu sync.Mutex
	var slowSession *raceSession
	win, err := raceServers(context.Background(), raceConfig(slow, fast), func(_ context.Context, target *url.URL, _ string) (proxySession, error) {
		if target.Host == "slow.example:443" {
			<-release // a dial that cannot be cancelled
			session := &raceSession{}
			mu.Lock()
			slowSession = session
			mu.Unlock()
			return session, nil
		}
		return &raceSession{}, nil
	})
	if err != nil || win.server.Addr != fast.Addr {
		t.Fatalf("win %+v err %v", win, err)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		session := slowSession
		mu.Unlock()
		if session != nil && session.closed.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the session of the server that lost was left open")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if win.session.(*raceSession).closed.Load() {
		t.Fatal("the winner was closed")
	}
}

func TestRaceServersFailsWhenNoServerConnects(t *testing.T) {
	fastServerStagger(t)
	a, b := raceServer("a.example:443", "ams"), raceServer("b.example:443", "rtm")
	errA, errB := errors.New("a: tls handshake timeout"), errors.New("b: tls handshake timeout")
	_, err := raceServers(context.Background(), raceConfig(a, b), func(_ context.Context, target *url.URL, _ string) (proxySession, error) {
		if target.Host == "a.example:443" {
			return nil, errA
		}
		return nil, errB
	})
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Fatalf("err = %v", err)
	}
}

// What is not the server's fault (no network, a refused pass) ends the race
// at once: another server would fail the same way.
func TestRaceServersStopsOnAFailureThatIsNotTheServers(t *testing.T) {
	fastServerStagger(t)
	a, b := raceServer("a.example:443", "ams"), raceServer("b.example:443", "rtm")
	var dials atomic.Int32
	_, err := raceServers(context.Background(), raceConfig(a, b), func(context.Context, *url.URL, string) (proxySession, error) {
		dials.Add(1)
		return nil, context.Canceled // serverFault: false
	})
	if !errors.Is(err, context.Canceled) || dials.Load() != 1 {
		t.Fatalf("err %v after %d dials", err, dials.Load())
	}
}

func TestRaceServersIgnoresDuplicatesOfTheSelectedServer(t *testing.T) {
	selected := raceServer("a.example:443", "ams")
	var dials atomic.Int32
	win, err := raceServers(context.Background(), raceConfig(selected, raceServer("A.example", "ams")), func(context.Context, *url.URL, string) (proxySession, error) {
		dials.Add(1)
		return &raceSession{}, nil
	})
	if err != nil || win.server.Addr != selected.Addr || dials.Load() != 1 {
		t.Fatalf("win %+v dials %d err %v", win, dials.Load(), err)
	}
}
