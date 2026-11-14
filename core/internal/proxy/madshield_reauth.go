package proxy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/accounts"
	"github.com/mmdamh/madshield-foxy-core/core/internal/fxa"
)

// ErrRenewSuperseded is returned when the account's credentials were replaced (or the account was forgotten) while a
// renewal was waiting on Mozilla: what it obtained is dropped, so it cannot overwrite anything newer.
var ErrRenewSuperseded = errors.New("the account's sign-in changed while it was being renewed")

// RenewPersistError says the renewed tokens could not be saved to the account's file. InUse reports whether they are used
// from memory anyway: that is so when Mozilla rotated the refresh token, because the old one may no longer work and the
// new one must not be lost. Otherwise the stored sign-in stays as it was, and it is still good.
type RenewPersistError struct {
	Err   error
	InUse bool
}

func (e *RenewPersistError) Error() string {
	if e.InUse {
		return fmt.Sprintf("the renewed sign-in works for now but could not be saved: %v", e.Err)
	}
	return fmt.Sprintf("the renewed sign-in could not be saved; the stored one is unchanged: %v", e.Err)
}
func (e *RenewPersistError) Unwrap() error { return e.Err }

// PersistFailed lets the dashboard name this failure without importing this package's type.
func (e *RenewPersistError) PersistFailed() bool { return true }

// RenewAccessToken makes the account's access token fresh (MadShield: an account page asked for it, and a person is
// waiting to answer Fastly's image CAPTCHA, so the usual 15 s limit of a background refresh does not apply: ctx sets
// the time). It reports whether a refresh was needed; a token that is still good is left alone.
//
// The new tokens replace the old ones in one step: written to the account's file first, then put in the pool's memory,
// both under the pool's lock and only if the pool still holds the credentials the refresh started from. So a failed
// renewal changes nothing, a renewal that ended (cancelled, timed out) installs nothing, and one that lost a race with a
// newer refresh does not overwrite it.
func (p *AccountPool) RenewAccessToken(ctx context.Context, acc accounts.Account) (bool, error) {
	return p.renewAccessToken(ctx, acc, fxa.RefreshToken)
}

func (p *AccountPool) renewAccessToken(ctx context.Context, acc accounts.Account, refresh func(context.Context, string) (*fxa.TokenResponse, error)) (bool, error) {
	auth, err := p.AuthFor(acc)
	if err != nil {
		return false, err
	}
	if auth.accessTokenValid(time.Now()) {
		return false, nil
	}
	if auth.Token == nil || auth.Token.RefreshToken == "" {
		return false, fmt.Errorf("%w: no refresh token stored", fxa.ErrReauthRequired)
	}
	token, err := refresh(ctx, auth.Token.RefreshToken)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err // the renewal ended while the answer was on its way: nothing is installed
	}
	if token.RefreshToken == "" {
		token.RefreshToken = auth.Token.RefreshToken // a refresh may not rotate it (fxa.RefreshToken already keeps it)
	}
	renewed := &runtimeAuth{Token: token, ObtainedAt: time.Now(), persist: auth.persist, accountID: auth.accountID}
	return p.installRenewed(auth, renewed)
}

// installRenewed puts next in place of prev, which the refresh started from. It reports true when the account holds
// fresh credentials afterwards.
func (p *AccountPool) installRenewed(prev, next *runtimeAuth) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur, ok := p.auths[next.accountID]
	if !ok {
		return false, ErrRenewSuperseded // the account was forgotten meanwhile
	}
	if cur != prev {
		// Credentials were installed after the refresh began (a background refresh): they are newer, keep them.
		if cur.accessTokenValid(time.Now()) {
			return true, nil
		}
		return false, ErrRenewSuperseded
	}
	err := p.store.SaveCredentials(next.accountID, &fxa.SavedTokens{
		AccessToken:  next.Token.AccessToken,
		RefreshToken: next.Token.RefreshToken,
		Scope:        next.Token.Scope,
		ObtainedAt:   next.ObtainedAt,
		ExpiresIn:    next.Token.ExpiresIn,
	})
	if err != nil {
		rotated := next.Token.RefreshToken != prev.Token.RefreshToken
		if rotated {
			p.auths[next.accountID] = next
		}
		return true, &RenewPersistError{Err: err, InUse: rotated}
	}
	p.auths[next.accountID] = next
	return true, nil
}
