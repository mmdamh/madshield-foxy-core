package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/fxa"
	"github.com/mmdamh/madshield-foxy-core/core/internal/logx"
)

const testPicture = "data:image/png;base64,AQID"

func newTestReauth() *reauthJob { return &reauthJob{view: reauthView{State: reauthIdle}} }

func waitState(t *testing.T, j *reauthJob, states ...string) reauthView {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		v := j.snapshot()
		for _, s := range states {
			if v.State == s {
				return v
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("none of %v reached, now %+v", states, j.snapshot())
	return reauthView{}
}

func mustStart(t *testing.T, j *reauthJob, account string, run reauthRun) reauthView {
	t.Helper()
	v, err := j.start(account, run)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func code(err error) string {
	var re *reauthError
	if errors.As(err, &re) {
		return re.code
	}
	if err == nil {
		return ""
	}
	return "other:" + err.Error()
}

// captureLog collects everything the job logs during a test.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	buf := &bytes.Buffer{}
	logx.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return buf.Write(p) }))
	t.Cleanup(func() { logx.SetOutput(os.Stderr) })
	return func() string { mu.Lock(); defer mu.Unlock(); return buf.String() }
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// 1. A CAPTCHA answered and the renewal completes; the answer is delivered, and "verifying" is a state of its own.
func TestMadShieldReauthSuccessfulCaptchaAndRenewal(t *testing.T) {
	j := newTestReauth()
	got := make(chan string, 1)
	release := make(chan struct{})
	started := mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		text, err := solve(ctx, testPicture)
		got <- text
		<-release // the post-back, probe and the original refresh are in flight
		return true, err
	})
	if started.State != reauthStarting || started.Op == "" {
		t.Fatalf("started: %+v", started)
	}
	v := waitState(t, j, reauthWaiting)
	if v.Image != testPicture || v.Op != started.Op || v.Round != 1 || v.ID != started.Op+".1" || v.Cause != "" {
		t.Fatalf("the picture is not offered as expected: %+v", v)
	}
	if err := j.deliver(v.Op, v.ID, "  k7Q2 "); err != nil {
		t.Fatal(err)
	}
	if text := <-got; text != "k7Q2" {
		t.Fatalf("the solver got %q", text)
	}
	ver := waitState(t, j, reauthVerifying)
	if ver.Image != "" || ver.ID != "" {
		t.Fatalf("a verifying view must not offer a picture: %+v", ver)
	}
	close(release)
	done := waitState(t, j, reauthCompleted)
	if !done.Renewed || done.Image != "" || done.Error != "" || done.Code != "" {
		t.Fatalf("finished view: %+v", done)
	}
}

// 2. A valid answer followed by another picture: an additional challenge, not a failure and not "wrong".
func TestMadShieldReauthAdditionalChallengeAfterAnAnswer(t *testing.T) {
	j := newTestReauth()
	mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		if _, err := solve(ctx, testPicture); err != nil {
			return false, err
		}
		note(fxa.ChallengeEvent{Kind: fxa.EvPostBack, Round: 2, Status: 200, Result: "more"})
		_, err := solve(ctx, testPicture)
		return true, err
	})
	first := waitState(t, j, reauthWaiting)
	if err := j.deliver(first.Op, first.ID, "one"); err != nil {
		t.Fatal(err)
	}
	second := waitState(t, j, reauthAdditional)
	if second.ID == first.ID || second.Round != 2 || second.Cause != reauthCauseMore || second.Error != "" || second.Code != "" {
		t.Fatalf("second picture: %+v", second)
	}
	if err := j.deliver(first.Op, first.ID, "late"); code(err) != "stale_challenge" && code(err) != "already_submitted" {
		t.Fatalf("an answer for the old picture: %v", err)
	}
	if err := j.deliver(second.Op, second.ID, "two"); err != nil {
		t.Fatal(err)
	}
	if v := waitState(t, j, reauthCompleted); !v.Renewed {
		t.Fatalf("%+v", v)
	}
}

// The challenge accepted but the original request got 406 again: the next picture says so (asked_again).
func TestMadShieldReauthPictureAfterASolvedChallengeSaysAskedAgain(t *testing.T) {
	j := newTestReauth()
	mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		note(fxa.ChallengeEvent{Kind: fxa.EvAttempt, Attempt: 1, Status: 406})
		if _, err := solve(ctx, testPicture); err != nil {
			return false, err
		}
		note(fxa.ChallengeEvent{Kind: fxa.EvSolved, Host: "accounts.firefox.com"})
		note(fxa.ChallengeEvent{Kind: fxa.EvRetry, Attempt: 2})
		note(fxa.ChallengeEvent{Kind: fxa.EvReply, Attempt: 2, Status: 406})
		note(fxa.ChallengeEvent{Kind: fxa.EvAttempt, Attempt: 2, Status: 406})
		note(fxa.ChallengeEvent{Kind: fxa.EvHost, Host: "api.accounts.firefox.com"})
		note(fxa.ChallengeEvent{Kind: fxa.EvNoPage, Host: "api.accounts.firefox.com"}) // the normal case: must not hide the cause
		_, err := solve(ctx, testPicture)
		return true, err
	})
	first := waitState(t, j, reauthWaiting)
	if err := j.deliver(first.Op, first.ID, "one"); err != nil {
		t.Fatal(err)
	}
	if v := waitState(t, j, reauthAdditional); v.Cause != reauthCauseAgain {
		t.Fatalf("cause: %+v", v)
	}
}

// 3. A refusal that Fastly itself states (HTTP 4xx to the post-back) is the one case reported as a rejected answer.
func TestMadShieldReauthConfirmedRejection(t *testing.T) {
	j := newTestReauth()
	mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		note(fxa.ChallengeEvent{Kind: fxa.EvHost, Host: "accounts.firefox.com"})
		if _, err := solve(ctx, testPicture); err != nil {
			return false, err
		}
		note(fxa.ChallengeEvent{Kind: fxa.EvPostBack, Round: 2, Status: 403, Result: "rejected"})
		note(fxa.ChallengeEvent{Kind: fxa.EvFailed, Host: "accounts.firefox.com", Result: "other"})
		return false, errors.New("Fastly anti-bot challenge: challenge post-back returned HTTP 403")
	})
	v := waitState(t, j, reauthWaiting)
	_ = j.deliver(v.Op, v.ID, "x")
	f := waitState(t, j, reauthFailed)
	if f.Code != reauthCodeRejected || f.HTTP != 403 || f.Error == "" {
		t.Fatalf("%+v", f)
	}
}

// 4. Consecutive rounds are bounded: after reauthMaxCaptchas pictures the operation gives up with its own code.
func TestMadShieldReauthConsecutiveRoundsAreBounded(t *testing.T) {
	j := newTestReauth()
	pictures := int32(0)
	mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		for {
			if _, err := solve(ctx, testPicture); err != nil {
				return false, fmt.Errorf("CAPTCHA: %w", err)
			}
			atomic.AddInt32(&pictures, 1)
			note(fxa.ChallengeEvent{Kind: fxa.EvPostBack, Status: 200, Result: "more"})
		}
	})
	for i := 1; i <= reauthMaxCaptchas; i++ {
		v := waitState(t, j, reauthWaiting, reauthAdditional)
		if v.Round != i {
			// the previous answer has not been taken yet
			time.Sleep(2 * time.Millisecond)
			i--
			continue
		}
		if err := j.deliver(v.Op, v.ID, "a"); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for int(atomic.LoadInt32(&pictures)) < i && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	f := waitState(t, j, reauthFailed)
	if f.Code != reauthCodeTooMany || f.Round != reauthMaxCaptchas {
		t.Fatalf("%+v", f)
	}
}

// 5-8. Why a failed operation failed, from what the events told.
func TestMadShieldReauthFailureCodes(t *testing.T) {
	type step = fxa.ChallengeEvent
	cases := []struct {
		name     string
		events   []step
		err      error
		wantCode string
		wantHTTP int
	}{
		{"post-back failed (HTTP 500)", []step{{Kind: fxa.EvHost}, {Kind: fxa.EvPostBack, Status: 500, Result: "error"}, {Kind: fxa.EvFailed, Result: "other"}}, errors.New("post-back returned HTTP 500"), reauthCodePostBack, 500},
		{"missing session cookies", []step{{Kind: fxa.EvHost}, {Kind: fxa.EvPostBack, Status: 200, Result: "success"}, {Kind: fxa.EvProbe, Result: "accepted"}, {Kind: fxa.EvCookies, Result: "missing"}, {Kind: fxa.EvFailed, Result: "cookies"}}, errors.New("no cookies were issued"), reauthCodeNoCookies, 0},
		{"transport / exit-IP change (probe)", []step{{Kind: fxa.EvHost}, {Kind: fxa.EvPostBack, Status: 200, Result: "success"}, {Kind: fxa.EvProbe, Result: "still_challenged"}, {Kind: fxa.EvFailed, Result: "probe"}}, errors.New("cookie not accepted"), reauthCodeNotAccepted, 0},
		{"fastly rounds exceeded", []step{{Kind: fxa.EvHost}, {Kind: fxa.EvFailed, Result: "rounds"}}, errors.New("did not complete"), reauthCodeRounds, 0},
		{"solved, original refresh failed (HTTP 401)", []step{{Kind: fxa.EvSolved}, {Kind: fxa.EvRetry, Attempt: 2}, {Kind: fxa.EvReply, Attempt: 2, Status: 401}}, errors.New("invalid token"), reauthCodeRefresh, 401},
		{"solved, original refresh still 406", []step{{Kind: fxa.EvSolved}, {Kind: fxa.EvGiveUp, Attempt: 5, Status: 406}}, fmt.Errorf("%w after 5 attempts (HTTP 406)", fxa.ErrChallengeStillRefused), reauthCodeStill406, 406},
		{"sign-in required", nil, fmt.Errorf("%w: no refresh token stored", fxa.ErrReauthRequired), reauthCodeSignIn, 0},
		{"persistence failed", []step{{Kind: fxa.EvSolved}}, &persistFailure{}, reauthCodePersist, 0},
		{"plain network failure", nil, errors.New("dial tcp: no route to host"), reauthCodeNetwork, 0},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			j := newTestReauth()
			mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
				for _, ev := range c.events {
					note(ev)
				}
				return false, c.err
			})
			f := waitState(t, j, reauthFailed)
			if f.Code != c.wantCode || f.HTTP != c.wantHTTP || f.Error == "" || f.Renewed {
				t.Fatalf("%+v, want code %s http %d", f, c.wantCode, c.wantHTTP)
			}
		})
	}
}

type persistFailure struct{}

func (*persistFailure) Error() string       { return "the renewed sign-in could not be saved" }
func (*persistFailure) PersistFailed() bool { return true }

// 10. Duplicate, stale, empty and out-of-order answers never reach the solver; the first one wins.
func TestMadShieldReauthRejectsDuplicateAndStaleAnswers(t *testing.T) {
	j := newTestReauth()
	answers := make(chan string, 4)
	release := make(chan struct{})
	mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		text, err := solve(ctx, testPicture)
		answers <- text
		<-release
		return true, err
	})
	v := waitState(t, j, reauthWaiting)
	for _, c := range []struct{ op, id, text, want string }{
		{"", v.ID, "a", "missing_operation"},
		{"other", v.ID, "a", "stale_operation"},
		{v.Op, "", "a", "stale_challenge"},
		{v.Op, v.Op + ".9", "a", "stale_challenge"},
		{v.Op, v.ID, "   ", "empty_answer"},
		{v.Op, v.ID, strings.Repeat("x", reauthMaxAnswerLen+1), "answer_too_long"},
	} {
		if err := j.deliver(c.op, c.id, c.text); code(err) != c.want {
			t.Fatalf("deliver(%q,%q): %v, want %s", c.op, c.id, err, c.want)
		}
	}
	if len(answers) != 0 {
		t.Fatal("a refused answer reached the solver")
	}
	if err := j.deliver(v.Op, v.ID, "first"); err != nil {
		t.Fatal(err)
	}
	if err := j.deliver(v.Op, v.ID, "second"); code(err) != "already_submitted" {
		t.Fatalf("a repeat: %v", err)
	}
	waitState(t, j, reauthVerifying)
	if err := j.deliver(v.Op, v.ID, "third"); code(err) != "already_submitted" {
		t.Fatalf("a repeat while verifying: %v", err)
	}
	close(release)
	waitState(t, j, reauthCompleted)
	if err := j.deliver(v.Op, v.ID, "fourth"); code(err) != "no_challenge" {
		t.Fatalf("an answer after the end: %v", err)
	}
	if text := <-answers; text != "first" || len(answers) != 0 {
		t.Fatalf("the solver got %q (and %d more)", text, len(answers))
	}
}

// 12. Many answers at once for one picture: exactly one is taken.
func TestMadShieldReauthConcurrentAnswersOneWins(t *testing.T) {
	j := newTestReauth()
	got := make(chan string, 8)
	mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		text, err := solve(ctx, testPicture)
		got <- text
		return true, err
	})
	v := waitState(t, j, reauthWaiting)
	var ok, dup int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch err := j.deliver(v.Op, v.ID, fmt.Sprintf("ans%d", i)); code(err) {
			case "":
				atomic.AddInt32(&ok, 1)
			case "already_submitted", "no_challenge":
				atomic.AddInt32(&dup, 1)
			default:
				t.Errorf("unexpected %v", err)
			}
		}(i)
	}
	wg.Wait()
	waitState(t, j, reauthCompleted)
	if ok != 1 || dup != 23 || len(got) != 1 {
		t.Fatalf("accepted=%d duplicates=%d solver got %d", ok, dup, len(got))
	}
}

// 12. Concurrent renewal attempts: one operation runs; the same account joins it, another account is told it is busy.
func TestMadShieldReauthConcurrentStartsRunOnce(t *testing.T) {
	j := newTestReauth()
	var runs int32
	release := make(chan struct{})
	run := func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		atomic.AddInt32(&runs, 1)
		<-release
		return false, nil
	}
	ops := make(chan string, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := j.start("acc", run)
			if err != nil {
				t.Errorf("a start of the same account must join: %v", err)
				return
			}
			ops <- v.Op
		}()
	}
	wg.Wait()
	close(ops)
	first := ""
	for op := range ops {
		if first == "" {
			first = op
		}
		if op != first {
			t.Fatalf("two operations: %s and %s", first, op)
		}
	}
	if _, err := j.start("other-account", run); code(err) != "busy" {
		t.Fatalf("another account while one runs: %v", err)
	}
	close(release)
	waitState(t, j, reauthCompleted)
	if runs != 1 {
		t.Fatalf("runs=%d", runs)
	}
}

// 13. Cancel while the answer is being verified: it stops that operation, the run's context ends, and the late end of
// the run changes nothing. A newer operation is not touched by the cancel of an older one.
func TestMadShieldReauthCancelDuringVerificationAndStaleCancel(t *testing.T) {
	j := newTestReauth()
	ended := make(chan error, 1)
	releaseOld := make(chan struct{})
	old := mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		if _, err := solve(ctx, testPicture); err != nil {
			return false, err
		}
		<-ctx.Done() // the post-back hangs until cancelled
		<-releaseOld // ... and the old run lingers a while after that
		ended <- ctx.Err()
		return true, nil // a stale "success" that must not show
	})
	v := waitState(t, j, reauthWaiting)
	if err := j.deliver(v.Op, v.ID, "x"); err != nil {
		t.Fatal(err)
	}
	waitState(t, j, reauthVerifying)
	if err := j.stop(old.Op); err != nil {
		t.Fatal(err)
	}
	c := j.snapshot()
	if c.State != reauthCancelled || c.Op != old.Op || c.Image != "" {
		t.Fatalf("after cancel: %+v", c)
	}
	// a newer operation starts while the old run still unwinds
	secondRelease := make(chan struct{})
	second := mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		<-secondRelease
		return true, nil
	})
	if second.Op == old.Op {
		t.Fatal("the new operation reused the id")
	}
	close(releaseOld)
	if err := <-ended; !errors.Is(err, context.Canceled) {
		t.Fatalf("the old run's context: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if cur := j.snapshot(); cur.Op != second.Op || cur.State != reauthStarting {
		t.Fatalf("the old operation changed the new one: %+v", cur)
	}
	// the cleanup of the older dialog arrives late and names the old operation: it must not stop the new one
	if err := j.stop(old.Op); code(err) != "stale_operation" {
		t.Fatalf("stale cancel: %v", err)
	}
	if cur := j.snapshot(); cur.State != reauthStarting || cur.Op != second.Op {
		t.Fatalf("stale cancel stopped the new operation: %+v", cur)
	}
	if err := j.stop(""); code(err) != "missing_operation" {
		t.Fatalf("cancel without an operation: %v", err)
	}
	close(secondRelease)
	waitState(t, j, reauthCompleted)
	if err := j.stop(second.Op); err != nil {
		t.Fatalf("cancelling a finished operation is a no-op: %v", err)
	}
	if j.snapshot().State != reauthCompleted {
		t.Fatal("a cancel after the end changed the result")
	}
}

// The picture request of an operation that was cancelled is refused, not shown.
func TestMadShieldReauthStalePictureIsNotShown(t *testing.T) {
	j := newTestReauth()
	solved := make(chan error, 1)
	op := mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		<-ctx.Done()
		_, err := solve(context.Background(), testPicture)
		solved <- err
		return false, err
	})
	if err := j.stop(op.Op); err != nil {
		t.Fatal(err)
	}
	if err := <-solved; !errors.Is(err, errReauthSuperseded) {
		t.Fatalf("got %v", err)
	}
	if v := j.snapshot(); v.State != reauthCancelled || v.Image != "" {
		t.Fatalf("%+v", v)
	}
}

// 14. A timeout: while waiting for the answer, and while verifying (the submission is in flight).
func TestMadShieldReauthTimeouts(t *testing.T) {
	old := reauthTimeLimit
	reauthTimeLimit = 150 * time.Millisecond
	defer func() { reauthTimeLimit = old }()

	t.Run("waiting for the answer", func(t *testing.T) {
		j := newTestReauth()
		mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
			_, err := solve(ctx, testPicture)
			return false, fmt.Errorf("CAPTCHA: %w", err)
		})
		v := waitState(t, j, reauthTimedOut)
		if v.Code != reauthCodeTimeout || v.Error != "no answer in time" || v.Image != "" {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("during the submission", func(t *testing.T) {
		j := newTestReauth()
		mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
			if _, err := solve(ctx, testPicture); err != nil {
				return false, err
			}
			<-ctx.Done()
			// as fxaDo does, the error reaches the caller as a cancellation even when the deadline ran out
			return false, fmt.Errorf("challenge post-back: %w", context.Canceled)
		})
		v := waitState(t, j, reauthWaiting)
		if err := j.deliver(v.Op, v.ID, "x"); err != nil {
			t.Fatal(err)
		}
		tv := waitState(t, j, reauthTimedOut)
		if tv.Code != reauthCodeTimeout || tv.Error != "Mozilla did not confirm in time" {
			t.Fatalf("%+v", tv)
		}
	})
}

// A request's own timeout is a failure of that request, not the operation's timeout.
func TestMadShieldReauthRequestTimeoutIsNotTheOperationsTimeout(t *testing.T) {
	j := newTestReauth()
	mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		return false, fmt.Errorf("refresh request: %w", context.DeadlineExceeded) // e.g. http.Client.Timeout
	})
	if v := waitState(t, j, reauthFailed); v.Code != reauthCodeNetwork {
		t.Fatalf("%+v", v)
	}
}

// A new operation can start after a failure, with a new id, and the old view is gone.
func TestMadShieldReauthStartsAgainAfterAnEnd(t *testing.T) {
	j := newTestReauth()
	first := mustStart(t, j, "acc", func(context.Context, fxa.CaptchaSolver, func(fxa.ChallengeEvent)) (bool, error) {
		return false, errors.New("account server unreachable")
	})
	if v := waitState(t, j, reauthFailed); v.Error != "account server unreachable" || v.Op != first.Op {
		t.Fatalf("%+v", v)
	}
	second := mustStart(t, j, "acc", func(context.Context, fxa.CaptchaSolver, func(fxa.ChallengeEvent)) (bool, error) { return true, nil })
	if second.Op == first.Op {
		t.Fatal("the same operation id twice")
	}
	if v := waitState(t, j, reauthCompleted); !v.Renewed || v.Error != "" || v.Code != "" {
		t.Fatalf("%+v", v)
	}
}

// Diagnostics: the transitions are logged with ids, rounds, statuses and outcome; the answer is not in the log or in
// any view.
func TestMadShieldReauthLogsTransitionsWithoutSecrets(t *testing.T) {
	logged := captureLog(t)
	j := newTestReauth()
	secret := "ZsEcReT9"
	mustStart(t, j, "acc", func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		note(fxa.ChallengeEvent{Kind: fxa.EvAttempt, Attempt: 1, Status: 406})
		note(fxa.ChallengeEvent{Kind: fxa.EvHost, Host: "accounts.firefox.com"})
		if _, err := solve(ctx, testPicture); err != nil {
			return false, err
		}
		note(fxa.ChallengeEvent{Kind: fxa.EvPostBack, Round: 2, Status: 200, Result: "success"})
		note(fxa.ChallengeEvent{Kind: fxa.EvSolved, Host: "accounts.firefox.com"})
		return true, nil
	})
	v := waitState(t, j, reauthWaiting)
	if err := j.deliver(v.Op, v.ID, secret); err != nil {
		t.Fatal(err)
	}
	done := waitState(t, j, reauthCompleted)
	for deadline := time.Now().Add(3 * time.Second); !strings.Contains(logged(), "renewal ended") && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond) // the end is logged just after the state changes
	}
	log := logged()
	for _, want := range []string{"renewal started op=" + v.Op, "renewal picture op=" + v.Op + " challenge=" + v.ID + " round=1", "renewal verifying", "kind=post_back", "status=200", "result=success", "renewal ended op=" + v.Op + " state=completed"} {
		if !strings.Contains(log, want) {
			t.Fatalf("the log lacks %q:\n%s", want, log)
		}
	}
	views, _ := json.Marshal([]reauthView{v, done})
	if strings.Contains(log, secret) || strings.Contains(string(views), secret) || strings.Contains(log, "AQID") {
		t.Fatalf("a secret reached the log or a view:\n%s", log)
	}
}
