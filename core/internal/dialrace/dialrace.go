// Package dialrace runs connection attempts that differ in one thing (the
// server, or the way the TLS handshake is made) at the same time, one
// starting after another, and keeps the first that succeeds.
//
// A network that cuts one kind of connection silently makes a single attempt
// wait for its whole timeout; with the next attempt started a moment later
// (at once when the one before it has failed) the connection is made as fast
// as the fastest way that works.
package dialrace

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Attempt is one way to connect. Run must stop when ctx is done.
type Attempt[T any] struct {
	Name string
	Run  func(ctx context.Context) (T, error)
}

// Outcome is how one attempt ended; Options.Observe gets one for each
// attempt that ended before the race did.
type Outcome struct {
	Index   int
	Name    string
	Elapsed time.Duration
	Err     error // nil for the winner
}

// Options tune a race. The zero value starts every attempt at once.
type Options[T any] struct {
	// Stagger is how long an attempt runs before the next one starts. An
	// attempt that fails starts the next one at once.
	Stagger time.Duration
	// Fatal, when it reports true for an attempt's error, ends the race
	// with that error: the other attempts would fail the same way (a
	// connection that was refused, say). Nil: no error is.
	Fatal func(err error) bool
	// Discard closes a value from an attempt that succeeded after the race
	// was decided. Nil: such a value is dropped.
	Discard func(T)
	// Observe is called, from the goroutine running Race, for each attempt
	// that ended before the race was decided, the winner included.
	Observe func(Outcome)
}

// Winner is the attempt that connected first.
type Winner[T any] struct {
	Index   int
	Name    string
	Value   T
	Elapsed time.Duration
}

// AllFailedError is the result of a race in which every attempt failed.
type AllFailedError struct {
	Names []string
	Errs  []error // Errs[i] is the error of Names[i]; nil when it never ran
}

func (e *AllFailedError) Error() string {
	var parts []string
	for i, err := range e.Errs {
		if err != nil {
			parts = append(parts, fmt.Sprintf("%s: %v", e.Names[i], err))
		}
	}
	return fmt.Sprintf("all %d connection attempts failed (%s)", len(parts), strings.Join(parts, "; "))
}

// Unwrap lets errors.Is and errors.As look into every attempt's error.
func (e *AllFailedError) Unwrap() []error {
	var out []error
	for _, err := range e.Errs {
		if err != nil {
			out = append(out, err)
		}
	}
	return out
}

// Race runs attempts in order, as Options says, and returns the first
// success. The others are cancelled (their ctx is done) and, if they succeed
// anyway, discarded. When none succeeds the error is the Fatal one, ctx's
// when ctx ended the race, or an *AllFailedError.
func Race[T any](ctx context.Context, attempts []Attempt[T], opt Options[T]) (Winner[T], error) {
	var none Winner[T]
	if len(attempts) == 0 {
		return none, errors.New("dialrace: no attempts")
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		index   int
		value   T
		err     error
		elapsed time.Duration
	}
	results := make(chan result, len(attempts))
	// A result is queued only while the race is undecided, and the race is
	// decided (and the queue emptied) under the same lock: no value is
	// left in the queue unclaimed.
	var mu sync.Mutex
	decided := false

	start := func(i int) {
		go func() {
			began := time.Now()
			value, err := attempts[i].Run(raceCtx)
			mu.Lock()
			defer mu.Unlock()
			if decided {
				if err == nil && opt.Discard != nil {
					opt.Discard(value)
				}
				return
			}
			results <- result{i, value, err, time.Since(began)}
		}()
	}
	decide := func() {
		mu.Lock()
		defer mu.Unlock()
		decided = true
		for {
			select {
			case r := <-results:
				if r.err == nil && opt.Discard != nil {
					opt.Discard(r.value)
				}
			default:
				return
			}
		}
	}

	errs := make([]error, len(attempts))
	names := make([]string, len(attempts))
	for i, a := range attempts {
		names[i] = a.Name
	}
	started, running := 0, 0
	startNext := func() {
		start(started)
		started++
		running++
	}
	if opt.Stagger <= 0 {
		for started < len(attempts) {
			startNext()
		}
	} else {
		startNext()
	}

	var tick <-chan time.Time
	var timer *time.Timer
	arm := func() {
		if opt.Stagger <= 0 || started >= len(attempts) {
			tick = nil
			return
		}
		if timer == nil {
			timer = time.NewTimer(opt.Stagger)
		} else {
			timer.Reset(opt.Stagger)
		}
		tick = timer.C
	}
	arm()
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case r := <-results:
			running--
			outcome := Outcome{Index: r.index, Name: attempts[r.index].Name, Elapsed: r.elapsed, Err: r.err}
			if opt.Observe != nil {
				opt.Observe(outcome)
			}
			if r.err == nil {
				decide()
				return Winner[T]{Index: r.index, Name: outcome.Name, Value: r.value, Elapsed: r.elapsed}, nil
			}
			errs[r.index] = r.err
			if opt.Fatal != nil && opt.Fatal(r.err) {
				decide()
				return none, r.err
			}
			if started < len(attempts) {
				startNext()
				arm()
			} else if running == 0 {
				decide()
				return none, &AllFailedError{Names: names, Errs: errs}
			}
		case <-tick:
			startNext()
			arm()
		case <-ctx.Done():
			decide()
			for _, err := range errs {
				if err != nil {
					return none, fmt.Errorf("%w: %w", ctx.Err(), &AllFailedError{Names: names, Errs: errs})
				}
			}
			return none, ctx.Err()
		}
	}
}
