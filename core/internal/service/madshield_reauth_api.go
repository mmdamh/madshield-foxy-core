package service

import (
	"context"
	"errors"
	"net/http"

	"github.com/mmdamh/madshield-foxy-core/core/internal/fxa"
)

// MadShield: the dashboard routes of the renewal (see madshield_reauth.go). Errors carry a fixed "code" next to the text
// so the app can tell a stale picture from a finished operation without reading prose.

func writeReauthError(w http.ResponseWriter, err error) {
	var re *reauthError
	if errors.As(err, &re) {
		writeJSON(w, re.status, map[string]any{"error": re.msg, "code": re.code})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error(), "code": "internal"})
}

func (s *dashboardServer) handleReauthStart(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AccountID string `json:"account_id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	acc, err := s.d.store.Get(in.AccountID)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown account")
		return
	}
	view, err := msReauth.start(acc.ID, func(ctx context.Context, solve fxa.CaptchaSolver, note func(fxa.ChallengeEvent)) (bool, error) {
		return s.d.pool.RenewAccessToken(fxa.WithChallengeObserver(fxa.WithCaptchaSolver(ctx, solve), note), acc)
	})
	if err != nil {
		writeReauthError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, view)
}

func (s *dashboardServer) handleReauthGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, msReauth.snapshot())
}

func (s *dashboardServer) handleReauthAnswer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Op     string `json:"op"`
		ID     string `json:"id"`
		Answer string `json:"answer"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := msReauth.deliver(in.Op, in.ID, in.Answer); err != nil {
		writeReauthError(w, err)
		return
	}
	// 200 says only that the answer was handed to the challenge flow; whether Fastly accepts it is shown by the state.
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": msReauth.snapshot().State})
}

func (s *dashboardServer) handleReauthCancel(w http.ResponseWriter, r *http.Request) {
	if err := msReauth.stop(r.URL.Query().Get("op")); err != nil {
		writeReauthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
