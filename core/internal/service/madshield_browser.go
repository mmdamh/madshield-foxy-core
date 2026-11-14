package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/fxa"
	"github.com/mmdamh/madshield-foxy-core/core/internal/logx"
)

// MadShield hook: the sign-in of an account whose password the app never sees. The app's
// browser view shows Mozilla's own sign-in page and hands over the session token the page ends with; this runs the rest
// like the password sign-in does (the same session registry, the same polling), asking Mozilla for the tokens with
// fxa.BrowserTokens and storing the account without a password.

const (
	signInBlocked        = "blocked"         // Mozilla's edge refused every way of getting the tokens (the error text lists the steps)
	signInWaitingConfirm = "waiting_confirm" // working, not failed: the page still asks for a code or a link
	browserPollEvery     = 4 * time.Second
)

var sessionTokenForm = regexp.MustCompile(`^[0-9a-f]{64}$`)

// startBrowser begins a sign-in for the session token a browser view captured for email.
func (r *signInRegistry) startBrowser(email, sessionToken string) (signInView, error) {
	email = fxa.NormalizeEmail(email)
	sessionToken = strings.ToLower(strings.TrimSpace(sessionToken))
	if email == "" || !sessionTokenForm.MatchString(sessionToken) {
		return signInView{}, errors.New("an email and a session token are required")
	}
	var idBytes [12]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return signInView{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), signInTimeout)
	s := &signIn{
		view:   signInView{ID: hex.EncodeToString(idBytes[:]), Email: email, Step: stepWorking, Message: "Signing in", Updated: time.Now()},
		input:  make(chan string),
		cancel: cancel,
	}
	r.mu.Lock()
	r.pruneLocked()
	r.sessions[s.view.ID] = s
	r.mu.Unlock()
	go s.runBrowser(ctx, r.d, email, sessionToken)
	return s.snapshot(), nil
}

func (s *signIn) runBrowser(ctx context.Context, d *Daemon, email, sessionToken string) {
	defer s.cancel()
	accountID, err := s.browserSignIn(ctx, d, email, sessionToken)
	switch {
	case errors.Is(err, errSignInCancelled):
		s.set(stepCancelled, "Sign-in cancelled", signInProblem{}, "")
	case err != nil:
		logx.Warn("browser sign-in failed email=%s err=%s", logx.Email(email), fxa.Message(err))
		s.set(stepFailed, "The account was not added.", browserFailure(err), "")
	default:
		s.mu.Lock()
		s.view.AccountID = accountID
		s.mu.Unlock()
		s.set(stepDone, "Account added", signInProblem{}, "")
	}
}

func (s *signIn) browserSignIn(ctx context.Context, d *Daemon, email, sessionToken string) (string, error) {
	s.set(stepWorking, "Getting the account token", signInProblem{}, "")
	var token *fxa.TokenResponse
	for token == nil {
		t, err := fxa.BrowserTokens(ctx, sessionToken)
		if err == nil {
			token = t
			break
		}
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return "", errSignInCancelled
			}
			return "", errSignInTimedOut
		}
		// The page still asks for a code or a link: the session is not confirmed. Ask again soon; nothing is lost.
		if n := fxa.Errno(err); n != fxa.ErrnoUnverifiedAccount && n != fxa.ErrnoUnverifiedSession {
			return "", err
		}
		s.set(stepWorking, "Waiting for the sign-in to be confirmed", signInProblem{code: signInWaitingConfirm}, "")
		select {
		case <-ctx.Done():
		case <-time.After(browserPollEvery):
		}
	}
	s.set(stepWorking, "Saving the account", signInProblem{}, "")
	acc, err := d.addSignedInAccount(email, "", token)
	if err != nil {
		return "", err
	}
	// The sign-in session is not needed once the tokens exist (left alive it shows as "unknown" in the account's connected
	// services). Ending it can take long when the edge is slow, so it must not hold the sign-in up.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := fxa.DestroySession(ctx, sessionToken); err != nil {
			logx.Warn("ending the sign-in session failed email=%s err=%s", logx.Email(email), logx.Err(err))
		}
	}()
	return acc.ID, nil
}

func browserFailure(err error) signInProblem {
	var steps *fxa.StepsError
	if errors.As(err, &steps) {
		return signInProblem{signInBlocked, steps.Error()}
	}
	return signInFailure(err)
}

func (s *dashboardServer) handleBrowserSignIn(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email        string `json:"email"`
		SessionToken string `json:"session_token"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	view, err := s.d.signins.startBrowser(in.Email, in.SessionToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, view)
}
