package dialrace

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stall waits for ctx, as an attempt on a network that drops it does.
func stall(ctx context.Context) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

func ok(value string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return value, nil }
}

func fail(err error) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return "", err }
}

func TestFirstSuccessWins(t *testing.T) {
	w, err := Race(context.Background(), []Attempt[string]{
		{"a", ok("a")},
		{"b", ok("b")},
	}, Options[string]{Stagger: time.Hour})
	if err != nil || w.Value != "a" || w.Index != 0 || w.Name != "a" {
		t.Fatalf("winner %+v err %v", w, err)
	}
}

func TestSecondStartsAfterStagger(t *testing.T) {
	cancelled := make(chan struct{})
	w, err := Race(context.Background(), []Attempt[string]{
		{"stalled", func(ctx context.Context) (string, error) {
			<-ctx.Done()
			close(cancelled)
			return "", ctx.Err()
		}},
		{"b", ok("b")},
	}, Options[string]{Stagger: 20 * time.Millisecond})
	if err != nil || w.Value != "b" {
		t.Fatalf("winner %+v err %v", w, err)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the stalled attempt was not cancelled")
	}
}

func TestFailureStartsNextAtOnce(t *testing.T) {
	began := time.Now()
	w, err := Race(context.Background(), []Attempt[string]{
		{"a", fail(errors.New("refused by the network"))},
		{"b", ok("b")},
	}, Options[string]{Stagger: time.Hour})
	if err != nil || w.Value != "b" {
		t.Fatalf("winner %+v err %v", w, err)
	}
	if time.Since(began) > 2*time.Second {
		t.Fatal("the next attempt waited for the stagger")
	}
}

func TestAllFailed(t *testing.T) {
	errA, errB := errors.New("a failed"), errors.New("b failed")
	_, err := Race(context.Background(), []Attempt[string]{
		{"a", fail(errA)},
		{"b", fail(errB)},
	}, Options[string]{Stagger: time.Hour})
	var all *AllFailedError
	if !errors.As(err, &all) {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Fatalf("errors of the attempts are not reachable: %v", err)
	}
}

func TestFatalEndsTheRace(t *testing.T) {
	refused := errors.New("connection refused")
	var ran atomic.Int32
	_, err := Race(context.Background(), []Attempt[string]{
		{"a", fail(refused)},
		{"b", func(context.Context) (string, error) { ran.Add(1); return "b", nil }},
	}, Options[string]{
		Stagger: time.Hour,
		Fatal:   func(err error) bool { return errors.Is(err, refused) },
	})
	if !errors.Is(err, refused) {
		t.Fatalf("err = %v", err)
	}
	if ran.Load() != 0 {
		t.Fatal("an attempt started after a fatal error")
	}
}

func TestLateSuccessIsDiscarded(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var discarded []string
	closed := make(chan struct{})
	w, err := Race(context.Background(), []Attempt[string]{
		{"slow", func(context.Context) (string, error) {
			<-release // ignores ctx, as a dial that cannot be cancelled
			return "slow", nil
		}},
		{"fast", ok("fast")},
	}, Options[string]{
		Stagger: 10 * time.Millisecond,
		Discard: func(v string) {
			mu.Lock()
			discarded = append(discarded, v)
			mu.Unlock()
			close(closed)
		},
	})
	if err != nil || w.Value != "fast" {
		t.Fatalf("winner %+v err %v", w, err)
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the late success was not discarded")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(discarded) != 1 || discarded[0] != "slow" {
		t.Fatalf("discarded %v", discarded)
	}
}

func TestContextEndsTheRace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := Race(ctx, []Attempt[string]{
		{"a", stall},
		{"b", stall},
	}, Options[string]{Stagger: 10 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestNoStaggerStartsAllAtOnce(t *testing.T) {
	var started atomic.Int32
	both := make(chan struct{})
	run := func(context.Context) (string, error) {
		if started.Add(1) == 2 {
			close(both)
		}
		<-both
		return "x", nil
	}
	w, err := Race(context.Background(), []Attempt[string]{{"a", run}, {"b", run}}, Options[string]{})
	if err != nil || w.Value != "x" {
		t.Fatalf("winner %+v err %v", w, err)
	}
}

func TestObserveSeesFailuresAndWinner(t *testing.T) {
	var seen []Outcome
	_, err := Race(context.Background(), []Attempt[string]{
		{"a", fail(errors.New("no"))},
		{"b", ok("b")},
	}, Options[string]{Stagger: time.Hour, Observe: func(o Outcome) { seen = append(seen, o) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0].Err == nil || seen[1].Err != nil || seen[1].Name != "b" {
		t.Fatalf("outcomes %+v", seen)
	}
}

func TestNoAttempts(t *testing.T) {
	if _, err := Race[string](context.Background(), nil, Options[string]{}); err == nil {
		t.Fatal("no error without attempts")
	}
}
