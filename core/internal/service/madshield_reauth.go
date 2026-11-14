package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mmdamh/madshield-foxy-core/core/internal/fxa"
	"github.com/mmdamh/madshield-foxy-core/core/internal/logx"
)

// MadShield: renewing an account's access token while a person answers Fastly's image CAPTCHA.
//
// When the access token has expired, the next connection renews it in the background, which Fastly may answer with an
// image CAPTCHA that nobody is there to read ("Fastly requires an image CAPTCHA; sign in from the dashboard"). This is
// the same question the sign-in asks, with the same pictures, but for an account that is already added: the app starts a
// renewal (POST /api/ms/reauth), shows the picture the daemon offers (GET /api/ms/reauth) and sends the characters back
// (POST /api/ms/reauth/answer). Nothing is kept: the picture and the answer live only in memory while the renewal runs.
//
// One renewal is an operation with its own id (Op). Every picture it shows has an id of its own (ID = Op + "." + round).
// An answer is taken only for the picture that is waiting now, once; a cancel names the operation it means. So a late
// answer, a second tap, or the cleanup of an older dialog cannot touch a newer renewal.
//
// States of an operation:
//
//	idle -> starting -> waiting_for_captcha -> submitting -> verifying -> completed
//	                         ^                                   |
//	                         +------ additional_challenge <------+      (Fastly asked again)
//	any running state -> failed | cancelled | timed_out
//
// "verifying" lasts from the moment the answer is handed to the challenge flow until the flow ends: the post-back to
// Fastly, the probe, the cookie carried over, and the original refresh sent again. A local "answer accepted" proves none
// of that. A new picture after an answer is "additional_challenge": Fastly does not say whether the last answer was wrong,
// so neither does this program; only a refusal Fastly states itself (an HTTP 4xx to the post-back) is reported as one.

const (
	reauthIdle       = "idle"
	reauthStarting   = "starting"
	reauthWaiting    = "waiting_for_captcha"
	reauthSubmitting = "submitting"
	reauthVerifying  = "verifying"
	reauthAdditional = "additional_challenge"
	reauthCompleted  = "completed"
	reauthFailed     = "failed"
	reauthCancelled  = "cancelled"
	reauthTimedOut   = "timed_out"

	reauthMaxCaptchas  = 6  // pictures one operation shows before it gives up
	reauthMaxAnswerLen = 64 // characters of one answer
)

// reauthTimeLimit is the time one operation has, from its start. A variable only so a test can make it short.
var reauthTimeLimit = 4 * time.Minute

// Why a picture is an additional one (reauthView.Cause).
const (
	reauthCauseMore  = "more_rounds" // Fastly answered the post-back with another round
	reauthCauseAgain = "asked_again" // the challenge was accepted, but the original request got HTTP 406 again
	reauthCauseHost  = "other_host"  // the flow on one host ended, and the next host asked its own picture
)

// Why an operation failed (reauthView.Code).
const (
	reauthCodeTooMany     = "too_many_captchas"
	reauthCodeStill406    = "refresh_still_challenged"
	reauthCodePersist     = "persist_failed"
	reauthCodeSignIn      = "sign_in_required"
	reauthCodeRejected    = "answer_rejected" // Fastly itself refused the post-back (HTTP 4xx)
	reauthCodePostBack    = "post_back_failed"
	reauthCodeNotAccepted = "challenge_not_accepted" // the probe still met the challenge: cookie not accepted on this connection
	reauthCodeNoCookies   = "session_cookies_missing"
	reauthCodeRounds      = "challenge_rounds_exceeded"
	reauthCodeRefresh     = "refresh_failed" // the challenge was solved, then the original request failed
	reauthCodeChallenge   = "challenge_failed"
	reauthCodeNetwork     = "network"
	reauthCodeTimeout     = "timeout"
)

// reauthView is what the API shows of the renewal.
type reauthView struct {
	State   string `json:"state"`
	Op      string `json:"op"`      // names the operation; "" while idle
	ID      string `json:"id"`      // names the picture in Image, to be sent back with the answer
	Image   string `json:"image"`   // a data: URL while a picture waits, else ""
	Round   int    `json:"round"`   // pictures this operation has shown (the one waiting is Round)
	Cause   string `json:"cause"`   // additional_challenge: why another picture (reauthCause...)
	Error   string `json:"error"`   // why it ended without success (a short English text, never a secret)
	Code    string `json:"code"`    // the same as a fixed word (reauthCode...)
	HTTP    int    `json:"http"`    // the HTTP status behind a failure, 0 when none
	Renewed bool   `json:"renewed"` // completed: the token was renewed (false: it was still good)
}

// reauthError is an answer the API gives to a request it refuses.
type reauthError struct {
	status int
	code   string
	msg    string
}

func (e *reauthError) Error() string { return e.msg }

var (
	errReauthStale          = &reauthError{409, "stale_operation", "that renewal is no longer the current one"}
	errReauthNoChallenge    = &reauthError{409, "no_challenge", "no CAPTCHA is waiting for an answer"}
	errReauthStaleChallenge = &reauthError{409, "stale_challenge", "that picture is no longer the one waiting"}
	errReauthDuplicate      = &reauthError{409, "already_submitted", "that answer was already sent"}
	errReauthBusy           = &reauthError{409, "busy", "another account is being renewed"}
	errReauthEmpty          = &reauthError{400, "empty_answer", "the answer is empty"}
	errReauthTooLong        = &reauthError{400, "answer_too_long", "the answer is too long"}
	errReauthOp             = &reauthError{400, "missing_operation", "the operation id is missing"}

	// errTooManyCaptchas ends an operation whose pictures keep coming (the solver's own bound, below Fastly's).
	errTooManyCaptchas = errors.New("Fastly keeps asking for CAPTCHAs; giving up")
	// errReauthSuperseded is what a picture request of an operation that is no longer current gets.
	errReauthSuperseded = errors.New("this renewal is no longer the current one")
)

// reauthTrace is what the events of the running operation told, for the failure's code and for the log.
type reauthTrace struct {
	attempt   int    // the try of the original request (fxaDo)
	postBack  string // result of the last post-back: success|more|rejected|error
	postBackH int    // its HTTP status
	probe     string // accepted|still_challenged
	cookies   string // installed|missing
	failure   string // the last host failure: probe|cookies|rounds|cancelled|other
	solved    bool   // a challenge flow completed
	reply     int    // the status of the original request sent again after a solved challenge
	cause     string // why the next picture is an additional one
	alt       string // the other ways the refresh was sent and what each was answered, "app:406,page:406"
}

type reauthJob struct {
	mu      sync.Mutex
	view    reauthView
	account string
	lastID  string // the picture answered last (its id is gone from view once answered)
	answer  chan string
	cancel  context.CancelFunc
	trace   reauthTrace
}

// msReauth is the one renewal of this process; a second start for the same account while it runs joins it.
var msReauth = &reauthJob{view: reauthView{State: reauthIdle}}

// reauthRun does the renewal. solve is the CAPTCHA question to put in the context it uses; note is the observer of the
// challenge flow (fxa.WithChallengeObserver). It reports whether a refresh was needed.
type reauthRun func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error)

func reauthActive(state string) bool {
	switch state {
	case reauthStarting, reauthWaiting, reauthSubmitting, reauthVerifying, reauthAdditional:
		return true
	}
	return false
}

func newReauthOp() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("op%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func (j *reauthJob) snapshot() reauthView {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.view
}

// start begins a renewal of account, or returns the one in progress when it is the same account. A renewal of another
// account that is still running is not joined: the caller gets errReauthBusy and the view of the one running.
func (j *reauthJob) start(account string, run reauthRun) (reauthView, error) {
	j.mu.Lock()
	if reauthActive(j.view.State) {
		view := j.view
		same := j.account == account
		j.mu.Unlock()
		if same {
			return view, nil
		}
		return view, errReauthBusy
	}
	op := newReauthOp()
	ctx, cancel := context.WithTimeout(context.Background(), reauthTimeLimit)
	j.account, j.cancel, j.answer, j.lastID = account, cancel, nil, ""
	j.trace = reauthTrace{}
	j.view = reauthView{State: reauthStarting, Op: op}
	started := j.view
	j.mu.Unlock()
	logx.Info("renewal started op=%s", op)
	go func() {
		defer cancel()
		renewed, err := run(ctx, j.solver(op), func(ev fxa.ChallengeEvent) { j.observe(op, ev) })
		j.finish(op, ctx, renewed, err)
	}()
	return started, nil
}

// observe takes one event of the challenge flow of operation op: for the log (fixed words, numbers and Mozilla's host
// names only) and for the facts finish needs. It runs on the flow's goroutine and only takes the lock.
func (j *reauthJob) observe(op string, ev fxa.ChallengeEvent) {
	j.mu.Lock()
	if j.view.Op != op || !reauthActive(j.view.State) {
		j.mu.Unlock()
		return
	}
	t := &j.trace
	switch ev.Kind {
	case fxa.EvAttempt:
		t.attempt = ev.Attempt
		if t.solved {
			t.cause = reauthCauseAgain
		}
	case fxa.EvHost:
		t.postBack, t.postBackH, t.probe, t.cookies, t.failure = "", 0, "", "", ""
	case fxa.EvPostBack:
		t.postBack, t.postBackH = ev.Result, ev.Status
		if ev.Result == "more" {
			t.cause = reauthCauseMore
		}
	case fxa.EvProbe:
		t.probe = ev.Result
	case fxa.EvCookies:
		t.cookies = ev.Result
	case fxa.EvFailed:
		t.failure = ev.Result
		t.cause = reauthCauseHost
	case fxa.EvSolved:
		t.solved = true
	case fxa.EvReply:
		t.reply = ev.Status
	case fxa.EvAlternate:
		if len(t.alt) < 120 { // bounded: two rounds of three ways
			if t.alt != "" {
				t.alt += ","
			}
			t.alt += fmt.Sprintf("%s:%d", ev.Result, ev.Status)
		}
	}
	round, state := j.view.Round, j.view.State
	j.mu.Unlock()
	logx.Info("renewal event op=%s state=%s kind=%s attempt=%d round=%d challenge_round=%d host=%s status=%d result=%s kinds=%s",
		op, state, ev.Kind, ev.Attempt, round, ev.Round, ev.Host, ev.Status, ev.Result, strings.Join(ev.Kinds, ","))
}

// solver is the CaptchaSolver of operation op: shows the picture and waits for the characters.
func (j *reauthJob) solver(op string) fxa.CaptchaSolver {
	return func(ctx context.Context, image string) (string, error) {
		j.mu.Lock()
		if j.view.Op != op || !reauthActive(j.view.State) {
			j.mu.Unlock()
			return "", errReauthSuperseded
		}
		if j.view.Round >= reauthMaxCaptchas {
			j.mu.Unlock()
			return "", errTooManyCaptchas
		}
		round := j.view.Round + 1
		ch := make(chan string, 1)
		j.answer = ch
		state, cause := reauthWaiting, ""
		if round > 1 {
			state, cause = reauthAdditional, j.trace.cause
			if cause == "" {
				cause = reauthCauseMore
			}
		}
		j.trace.cause = ""
		id := fmt.Sprintf("%s.%d", op, round)
		j.view = reauthView{State: state, Op: op, ID: id, Image: image, Round: round, Cause: cause}
		j.mu.Unlock()
		logx.Info("renewal picture op=%s challenge=%s round=%d state=%s cause=%s", op, id, round, state, cause)

		select {
		case text := <-ch:
			j.mu.Lock()
			if j.view.Op == op && j.view.State == reauthSubmitting {
				j.view.State, j.view.ID, j.view.Image = reauthVerifying, "", ""
			}
			j.mu.Unlock()
			logx.Info("renewal verifying op=%s challenge=%s", op, id)
			return text, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

// deliver gives the characters read from the picture id of operation op. Only the picture waiting now takes an answer,
// and only one answer: the first wins, a repeat gets errReauthDuplicate, an old picture errReauthStaleChallenge.
func (j *reauthJob) deliver(op, id, text string) error {
	text = strings.TrimSpace(text)
	j.mu.Lock()
	defer j.mu.Unlock()
	if op == "" {
		return errReauthOp
	}
	if op != j.view.Op {
		return errReauthStale
	}
	switch j.view.State {
	case reauthWaiting, reauthAdditional:
	case reauthSubmitting, reauthVerifying:
		if id != "" && id == j.lastID {
			return errReauthDuplicate
		}
		return errReauthStaleChallenge
	default:
		return errReauthNoChallenge
	}
	if id == "" || id != j.view.ID || j.answer == nil {
		return errReauthStaleChallenge
	}
	if text == "" {
		return errReauthEmpty
	}
	if utf8.RuneCountInString(text) > reauthMaxAnswerLen {
		return errReauthTooLong
	}
	j.answer <- text // buffered, one answer per picture
	j.answer = nil
	j.lastID = id
	j.view.State = reauthSubmitting
	return nil
}

// stop cancels operation op. A cancel that names another operation changes nothing (errReauthStale); one for an
// operation that already ended is accepted and does nothing.
func (j *reauthJob) stop(op string) error {
	j.mu.Lock()
	if op == "" {
		j.mu.Unlock()
		return errReauthOp
	}
	if op != j.view.Op {
		j.mu.Unlock()
		return errReauthStale
	}
	if !reauthActive(j.view.State) {
		j.mu.Unlock()
		return nil
	}
	cancel := j.cancel
	phase := j.view.State
	j.answer = nil
	j.view = reauthView{State: reauthCancelled, Op: op, Round: j.view.Round, Code: "cancelled"}
	j.mu.Unlock()
	logx.Info("renewal cancelled op=%s phase=%s", op, phase)
	if cancel != nil {
		cancel()
	}
	return nil
}

// finish records how operation op ended. An operation that is no longer current, or already ended (cancelled), says
// nothing: whatever it was doing cannot change what a newer one shows.
func (j *reauthJob) finish(op string, ctx context.Context, renewed bool, err error) {
	j.mu.Lock()
	if j.view.Op != op || !reauthActive(j.view.State) {
		j.mu.Unlock()
		return
	}
	phase := j.view.State
	round := j.view.Round
	j.answer = nil
	view := reauthView{Op: op, Round: round}
	switch {
	case err == nil:
		view.State, view.Renewed = reauthCompleted, renewed
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		// the operation's own time ran out (a request's own timeout is a failure below, not this)
		view.State, view.Code = reauthTimedOut, reauthCodeTimeout
		view.Error = "no answer in time"
		if phase == reauthSubmitting || phase == reauthVerifying {
			view.Error = "Mozilla did not confirm in time"
		}
	case errors.Is(ctx.Err(), context.Canceled):
		view.State, view.Code = reauthCancelled, "cancelled"
	default:
		view.State = reauthFailed
		view.Code, view.HTTP = j.classify(err)
		view.Error = fxa.Message(err)
	}
	j.view = view
	t := j.trace
	j.mu.Unlock()
	logx.Info("renewal ended op=%s state=%s code=%s http=%d round=%d phase=%s renewed=%v attempt=%d post_back=%s probe=%s cookies=%s reply=%d alt=%s err=%s",
		op, view.State, view.Code, view.HTTP, round, phase, view.Renewed, t.attempt, t.postBack, t.probe, t.cookies, t.reply, t.alt, logx.Err(err))
}

// classify names why err ended the operation, from the error and from what the events told. Called with the lock held.
func (j *reauthJob) classify(err error) (string, int) {
	t := j.trace
	var persist interface{ PersistFailed() bool }
	switch {
	case errors.Is(err, errTooManyCaptchas):
		return reauthCodeTooMany, 0
	case errors.As(err, &persist) && persist.PersistFailed():
		return reauthCodePersist, 0
	case errors.Is(err, fxa.ErrChallengeStillRefused):
		return reauthCodeStill406, 406
	case errors.Is(err, fxa.ErrReauthRequired):
		return reauthCodeSignIn, 0
	}
	switch t.failure {
	case "probe":
		return reauthCodeNotAccepted, 0
	case "cookies":
		return reauthCodeNoCookies, 0
	case "rounds":
		return reauthCodeRounds, 0
	case "other":
		switch t.postBack {
		case "rejected":
			return reauthCodeRejected, t.postBackH
		case "error":
			return reauthCodePostBack, t.postBackH
		}
		return reauthCodeChallenge, 0
	}
	if t.solved {
		return reauthCodeRefresh, t.reply
	}
	return reauthCodeNetwork, 0
}
