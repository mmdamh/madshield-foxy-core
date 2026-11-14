package fxa

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// MadShield: the other ways a refresh is sent (patch 0003).
//
// A refresh the edge answers with HTTP 406 is not always about a missing cookie: the same request can be refused again
// after any number of solved challenges when what the edge dislikes is the way the request presents itself. Then another
// CAPTCHA is asked for nothing. So, before a challenge is solved, the refresh is sent the other ways this program already
// presents itself to the account server for the browser sign-in (see madshield_browser.go): as the app (its own
// User-Agent, Go's own TLS, HTTP/2 where the server takes it), as Firefox's page (origin and fetch metadata), and to the
// OAuth server's own host. The first answer that is not a refusal wins. Nothing here weakens a check: a request that is
// refused is only sent differently, never without the credentials it needs, and the challenge stays the way through.

// alternateAttempts is how many answers of 406 (counted from the first) are followed by the other ways before the challenge.
const alternateAttempts = 2

// The words of EvAlternate's Result.
const (
	altApp       = "app"
	altPage      = "page"
	altOAuthHost = "oauth_host"
)

// refreshAlternate sends the refresh body the other ways. It returns nil, nil when every way was refused (406), failed, or
// answered with something that is not the account server's own word (an edge's page).
func refreshAlternate(body []byte) func(ctx context.Context, attempt int) (*http.Response, error) {
	return func(ctx context.Context, attempt int) (*http.Response, error) {
		for _, way := range []struct {
			name   string
			target string
			who    int
		}{
			{altApp, fxaAuthServer + "/oauth/token", asApp},
			{altPage, fxaAuthServer + "/oauth/token", asFirefoxPage},
			{altOAuthHost, browserOAuthTokenURL, asFirefox},
		} {
			a, err := send(ctx, http.MethodPost, way.target, body, "", nil, way.who)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err != nil {
				emitChallenge(ctx, ChallengeEvent{Kind: EvAlternate, Attempt: attempt, Result: way.name})
				continue
			}
			emitChallenge(ctx, ChallengeEvent{Kind: EvAlternate, Attempt: attempt, Result: way.name, Status: a.status})
			if a.status == http.StatusOK || isAccountServerAnswer(a.body) {
				return &http.Response{
					StatusCode: a.status,
					Status:     http.StatusText(a.status),
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(bytes.NewReader(a.body)),
				}, nil
			}
		}
		return nil, nil
	}
}

// isAccountServerAnswer reports whether body is an error the account server itself wrote (it carries an errno): an
// answer to the credentials, as opposed to the edge's refusal (406, an HTML page, an empty body).
func isAccountServerAnswer(body []byte) bool {
	var e struct {
		Errno int `json:"errno"`
	}
	return json.Unmarshal(body, &e) == nil && e.Errno > 0
}
