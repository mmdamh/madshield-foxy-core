package fxa

import (
	"context"
	"errors"
)

// MadShield: what the Fastly challenge flow tells a watcher (patch 0003).
//
// The flow in challenge.go and fxaDo knows things the caller cannot see from the final error alone: whether Fastly
// answered a CAPTCHA with a new round, refused the post-back, accepted the cookie on the probe, or answered the original
// request with HTTP 406 again after a solved challenge. A caller that wants them puts an observer in the context
// (WithChallengeObserver); without one nothing is reported and nothing changes.
//
// An event never holds a CAPTCHA answer, a token, a cookie (name or value), a header or an account detail: only fixed
// words, counts, HTTP statuses and host names of Mozilla's servers.

// ChallengeEvent is one step of the challenge flow.
type ChallengeEvent struct {
	Kind    string   // one of the Ev constants
	Attempt int      // the try of the original request (1-based), on the events of fxaDo; 0 on the others
	Round   int      // the post-back round (1-based) inside one challenge flow, 0 when not in a round
	Host    string   // the host the flow runs on, without the scheme
	Status  int      // an HTTP status, where the event carries one
	Result  string   // a short fixed word
	Kinds   []string // the challenge types asked in the round ("pow", "pat", "clientmetrics", "captcha")
}

const (
	EvAttempt   = "attempt"           // the account server answered 406 to try Attempt; the challenge is about to be solved
	EvHost      = "host"              // the flow begins on Host
	EvNoPage    = "no_challenge_page" // Host served a normal page: nothing to solve there
	EvRound     = "round"             // Fastly asked Kinds in post-back round Round
	EvPostBack  = "post_back"         // the post-back of the round was answered: Status, Result success|more|rejected|error
	EvProbe     = "probe"             // the probe after "success": Result accepted|still_challenged
	EvCookies   = "cookies"           // the solved cookie moved into the control plane's jar: Result installed|missing
	EvSolved    = "solved"            // the flow on Host is complete
	EvFailed    = "failed"            // the flow on Host ended with an error: Result probe|cookies|rounds|cancelled|other
	EvRetry     = "retry"             // the original request is sent again after a solved challenge (Attempt is the new try)
	EvReply     = "reply"             // the answer to a retried request: Status
	EvGiveUp    = "give_up"           // every try was answered with 406 again
	EvAlternate = "alternate"         // the refresh was sent another way (Result app|page|oauth_host); Status is the answer, 0 for none
)

type challengeObserverKey struct{}

// WithChallengeObserver reports the steps of the challenge flows run with the returned context (and of the requests that
// fxaDo retries) to obs. obs runs on the flow's goroutine: it must be quick and must not call back into this package.
func WithChallengeObserver(ctx context.Context, obs func(ChallengeEvent)) context.Context {
	return context.WithValue(ctx, challengeObserverKey{}, obs)
}

func emitChallenge(ctx context.Context, ev ChallengeEvent) {
	if obs, _ := ctx.Value(challengeObserverKey{}).(func(ChallengeEvent)); obs != nil {
		obs(ev)
	}
}

// ErrChallengeStillRefused is the error of a request the account server kept answering with HTTP 406 even though every
// challenge was solved (fxaDo gave up after its tries). Its text is the one this error always had.
var ErrChallengeStillRefused = errors.New("Fastly anti-bot challenge still failing")
