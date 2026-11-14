package proxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/accounts"
	"github.com/mmdamh/madshield-foxy-core/core/internal/fxa"
)

// MadShield (patch 0003): what a renewal does to the account's credentials, against the real account store.

type renewFixture struct {
	t     *testing.T
	pool  *AccountPool
	store *accounts.Store
	acc   accounts.Account
	dir   string
}

// newRenewFixture stores an account whose access token has expired (its refresh token is "old-refresh").
func newRenewFixture(t *testing.T) *renewFixture {
	t.Helper()
	dir := t.TempDir()
	store, err := accounts.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	acc, _, err := store.Add("renew@example.invalid", &fxa.SavedTokens{
		AccessToken: "old-access", RefreshToken: "old-refresh", Scope: "s", ExpiresIn: 3600,
		ObtainedAt: time.Now().Add(-2 * time.Hour),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &renewFixture{t: t, pool: NewAccountPool(store, nil), store: store, acc: acc, dir: dir}
}

func (f *renewFixture) stored() *fxa.SavedTokens {
	f.t.Helper()
	creds, err := f.store.Credentials(f.acc.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return creds
}

func (f *renewFixture) cached() *runtimeAuth {
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	return f.pool.auths[f.acc.ID]
}

func (f *renewFixture) breakStore() {
	f.t.Helper()
	matches, _ := filepath.Glob(filepath.Join(f.dir, "*", f.acc.ID))
	if len(matches) != 1 {
		f.t.Fatalf("account dir not found: %v", matches)
	}
	if err := os.RemoveAll(matches[0]); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(matches[0], []byte("not a directory"), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func refreshing(refresh, access string) func(context.Context, string) (*fxa.TokenResponse, error) {
	return func(context.Context, string) (*fxa.TokenResponse, error) {
		return &fxa.TokenResponse{AccessToken: access, RefreshToken: refresh, ExpiresIn: 3600, Scope: "s", TokenType: "bearer"}, nil
	}
}

// Refresh-token rotation: the new refresh token replaces the old one in memory and on disk, together.
func TestMadShieldRenewRotatesTheRefreshToken(t *testing.T) {
	f := newRenewFixture(t)
	renewed, err := f.pool.renewAccessToken(context.Background(), f.acc, refreshing("new-refresh", "new-access"))
	if err != nil || !renewed {
		t.Fatalf("renewed=%v err=%v", renewed, err)
	}
	if got := f.stored(); got.RefreshToken != "new-refresh" || got.AccessToken != "new-access" {
		t.Fatalf("stored: %+v", got)
	}
	if c := f.cached(); c.Token.RefreshToken != "new-refresh" || !c.accessTokenValid(time.Now()) {
		t.Fatalf("cached: %+v", c.Token)
	}
}

// A refresh that does not rotate keeps the stored refresh token.
func TestMadShieldRenewKeepsTheRefreshTokenWhenNotRotated(t *testing.T) {
	f := newRenewFixture(t)
	if _, err := f.pool.renewAccessToken(context.Background(), f.acc, refreshing("", "new-access")); err != nil {
		t.Fatal(err)
	}
	if got := f.stored(); got.RefreshToken != "old-refresh" || got.AccessToken != "new-access" {
		t.Fatalf("stored: %+v", got)
	}
}

// A token that is still good is not refreshed.
func TestMadShieldRenewLeavesAValidTokenAlone(t *testing.T) {
	f := newRenewFixture(t)
	if err := f.store.SaveCredentials(f.acc.ID, &fxa.SavedTokens{AccessToken: "good", RefreshToken: "r", ExpiresIn: 3600, ObtainedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	called := false
	renewed, err := f.pool.renewAccessToken(context.Background(), f.acc, func(context.Context, string) (*fxa.TokenResponse, error) {
		called = true
		return nil, errors.New("must not be called")
	})
	if renewed || err != nil || called {
		t.Fatalf("renewed=%v err=%v called=%v", renewed, err, called)
	}
}

// A failed renewal changes nothing: the previous session stays valid in memory and on disk.
func TestMadShieldFailedRenewalKeepsThePreviousSession(t *testing.T) {
	f := newRenewFixture(t)
	before := f.stored()
	_, err := f.pool.renewAccessToken(context.Background(), f.acc, func(context.Context, string) (*fxa.TokenResponse, error) {
		return nil, errors.New("Fastly anti-bot challenge still failing")
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := f.stored(); *got != *before {
		t.Fatalf("stored credentials changed: %+v -> %+v", before, got)
	}
	if c := f.cached(); c == nil || c.Token.RefreshToken != "old-refresh" || c.Token.AccessToken != "old-access" {
		t.Fatalf("cached credentials changed: %+v", c)
	}
}

// A renewal that ended (cancelled / timed out) while Mozilla's answer was on its way installs nothing.
func TestMadShieldCancelledRenewalInstallsNothing(t *testing.T) {
	f := newRenewFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	_, err := f.pool.renewAccessToken(ctx, f.acc, func(context.Context, string) (*fxa.TokenResponse, error) {
		cancel() // the person cancels just as the token arrives
		return &fxa.TokenResponse{AccessToken: "new", RefreshToken: "new-refresh", ExpiresIn: 3600}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if got := f.stored(); got.RefreshToken != "old-refresh" || f.cached().Token.AccessToken != "old-access" {
		t.Fatalf("a cancelled renewal wrote credentials: %+v", got)
	}
}

// Persistence failure, refresh token not rotated: surfaced; the stored session stays as it was (still good).
func TestMadShieldPersistFailureWithoutRotationKeepsTheOldSession(t *testing.T) {
	f := newRenewFixture(t)
	if _, err := f.pool.AuthFor(f.acc); err != nil { // load into memory before the store breaks
		t.Fatal(err)
	}
	f.breakStore()
	renewed, err := f.pool.renewAccessToken(context.Background(), f.acc, refreshing("", "new-access"))
	var pe *RenewPersistError
	if !errors.As(err, &pe) || !pe.PersistFailed() || pe.InUse || !renewed {
		t.Fatalf("renewed=%v err=%v", renewed, err)
	}
	if c := f.cached(); c.Token.AccessToken != "old-access" || c.Token.RefreshToken != "old-refresh" {
		t.Fatalf("memory must keep the stored session: %+v", c.Token)
	}
}

// Persistence failure after rotation: the new refresh token is the only good one, so memory keeps it, and the error says so.
func TestMadShieldPersistFailureAfterRotationKeepsTheNewTokenInMemory(t *testing.T) {
	f := newRenewFixture(t)
	if _, err := f.pool.AuthFor(f.acc); err != nil {
		t.Fatal(err)
	}
	f.breakStore()
	_, err := f.pool.renewAccessToken(context.Background(), f.acc, refreshing("rotated", "new-access"))
	var pe *RenewPersistError
	if !errors.As(err, &pe) || !pe.InUse {
		t.Fatalf("err=%v", err)
	}
	if c := f.cached(); c.Token.RefreshToken != "rotated" {
		t.Fatalf("the rotated refresh token was lost: %+v", c.Token)
	}
}

// A renewal that lost a race with a newer refresh does not overwrite it.
func TestMadShieldStaleRenewalDoesNotOverwriteNewerCredentials(t *testing.T) {
	f := newRenewFixture(t)
	inFlight, proceed := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	var renewed bool
	go func() {
		var err error
		renewed, err = f.pool.renewAccessToken(context.Background(), f.acc, func(context.Context, string) (*fxa.TokenResponse, error) {
			close(inFlight)
			<-proceed
			return &fxa.TokenResponse{AccessToken: "slow-access", RefreshToken: "slow-refresh", ExpiresIn: 3600}, nil
		})
		done <- err
	}()
	<-inFlight
	// meanwhile a background refresh installs newer credentials the way the pool does
	newer := &runtimeAuth{Token: &fxa.TokenResponse{AccessToken: "fast-access", RefreshToken: "fast-refresh", ExpiresIn: 3600}, ObtainedAt: time.Now(), persist: f.pool.persist, accountID: f.acc.ID}
	if err := newer.save(); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if err := <-done; err != nil || !renewed {
		t.Fatalf("renewed=%v err=%v", renewed, err)
	}
	if got := f.stored(); got.AccessToken != "fast-access" || got.RefreshToken != "fast-refresh" {
		t.Fatalf("the stale renewal overwrote the newer credentials on disk: %+v", got)
	}
	if c := f.cached(); c != newer {
		t.Fatalf("the stale renewal replaced the newer credentials in memory: %+v", c.Token)
	}
}

// If the newer credentials are not usable either, the renewal says it was superseded instead of pretending.
func TestMadShieldSupersededRenewalIsReportedWhenNothingFreshRemains(t *testing.T) {
	f := newRenewFixture(t)
	_, err := f.pool.renewAccessToken(context.Background(), f.acc, func(context.Context, string) (*fxa.TokenResponse, error) {
		stale := &runtimeAuth{Token: &fxa.TokenResponse{AccessToken: "x", RefreshToken: "y", ExpiresIn: 1}, ObtainedAt: time.Now().Add(-time.Hour), persist: f.pool.persist, accountID: f.acc.ID}
		_ = stale.save()
		return &fxa.TokenResponse{AccessToken: "n", RefreshToken: "m", ExpiresIn: 3600}, nil
	})
	if !errors.Is(err, ErrRenewSuperseded) {
		t.Fatalf("got %v", err)
	}
}

// An account forgotten while it was being renewed is not brought back.
func TestMadShieldRenewalOfAForgottenAccountInstallsNothing(t *testing.T) {
	f := newRenewFixture(t)
	_, err := f.pool.renewAccessToken(context.Background(), f.acc, func(context.Context, string) (*fxa.TokenResponse, error) {
		f.pool.Forget(f.acc.ID)
		return &fxa.TokenResponse{AccessToken: "n", RefreshToken: "m", ExpiresIn: 3600}, nil
	})
	if !errors.Is(err, ErrRenewSuperseded) {
		t.Fatalf("got %v", err)
	}
	if f.cached() != nil || f.stored().RefreshToken != "old-refresh" {
		t.Fatal("a forgotten account was written back")
	}
}

// Concurrent renewals (and a concurrent reader) end with memory and disk saying the same thing.
func TestMadShieldConcurrentRenewalsEndConsistent(t *testing.T) {
	f := newRenewFixture(t)
	var calls int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.pool.renewAccessToken(context.Background(), f.acc, func(context.Context, string) (*fxa.TokenResponse, error) {
				n := atomic.AddInt32(&calls, 1)
				time.Sleep(time.Millisecond)
				return &fxa.TokenResponse{AccessToken: "a", RefreshToken: "r" + string(rune('0'+n)), ExpiresIn: 3600}, nil
			})
			if err != nil {
				t.Errorf("renewal: %v", err)
			}
			_, _ = f.pool.AuthFor(f.acc)
		}()
	}
	wg.Wait()
	if c, s := f.cached(), f.stored(); c.Token.RefreshToken != s.RefreshToken || c.Token.AccessToken != s.AccessToken {
		t.Fatalf("memory %q and disk %q disagree", c.Token.RefreshToken, s.RefreshToken)
	}
}

// With no refresh token stored the answer is "sign in again", as before.
func TestMadShieldRenewWithoutARefreshTokenAsksForSignIn(t *testing.T) {
	f := newRenewFixture(t)
	if err := f.store.SaveCredentials(f.acc.ID, &fxa.SavedTokens{AccessToken: "a", ExpiresIn: 1, ObtainedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	_, err := f.pool.renewAccessToken(context.Background(), f.acc, refreshing("x", "y"))
	if !errors.Is(err, fxa.ErrReauthRequired) {
		t.Fatalf("got %v", err)
	}
}
