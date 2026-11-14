package fxa

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/controlplane"
)

// MadShield hook: the account's tokens for a session the app's browser view signed in.
//
// Mozilla's edge (Fastly) refuses the "fxa-credentials" grant from many clients with HTTP 406. This file asks for the
// tokens by every route the account server offers, one at a time, and keeps what each one answered, so a failure says
// which step was refused instead of one general message:
//
//	token      POST /v1/oauth/token                     (grant fxa-credentials, the session's Hawk signature)
//	code       POST /v1/oauth/authorization             (session-signed, PKCE) then
//	           POST oauth.accounts.firefox.com/v1/token (the code and its verifier; no signature)
//	challenge  the edge's own client challenge, solved (challenge.go), then token and code once more
//
// Each route is tried as two different clients: first as MadShield itself, the way an app of Mozilla's own says who it is
// (a short product User-Agent, plain Go TLS and HTTP/2, no browser headers), then as Firefox (its User-Agent, its TLS
// hello, with and without the headers its page adds). The edge may judge a client by how well its parts agree, and which
// of the two agrees is not known, so the error keeps what every try answered.
//
// Nothing here solves a challenge or retries without the caller knowing: fxaDo, which does, is not used.

const (
	// browserOAuthTokenURL is the OAuth server's own token endpoint, a different host from the account API.
	browserOAuthTokenURL = "https://oauth.accounts.firefox.com/v1/token"

	// FxA errnos of a session that is not confirmed yet (a code or link the page still asks for).
	ErrnoUnverifiedAccount = 104
	ErrnoUnverifiedSession = 138
)

// ErrEdgeRefused is the cause of a [StepsError] when no route got past Mozilla's edge.
var ErrEdgeRefused = errors.New("Mozilla's edge refused every way of getting the account's tokens")

// StepsError is the failure of [BrowserTokens]: what each step answered, in order.
type StepsError struct {
	Steps []string
	Err   error
}

func (e *StepsError) Error() string { return strings.Join(e.Steps, " | ") }
func (e *StepsError) Unwrap() error { return e.Err }

// appUserAgent names MadShield the way Mozilla's own apps name themselves: product, version, system. The Android release
// is not known to this program, so the common one is named.
const appUserAgent = "MozillaVPN/2.24.0 (sys:android 14)"

// How a request presents itself.
const (
	asApp         = iota // the app User-Agent, Go's own TLS (HTTP/2 when the server takes it)
	asFirefox            // Firefox's User-Agent and TLS hello
	asFirefoxPage        // Firefox, with the origin and fetch metadata its own page sends
)

var appClient = func() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: appTransport()}
}

// appTransport is the control plane's own transport (its resolver, its relay if one is set) without the Firefox TLS hello,
// so Go's own handshake runs and net/http can speak HTTP/2.
func appTransport() http.RoundTripper {
	base := controlplane.Transport()
	if t, ok := base.(*http.Transport); ok {
		c := t.Clone()
		c.DialTLSContext = nil
		c.ForceAttemptHTTP2 = true
		return c
	}
	return base
}

// hexHawk is set when the server refused the base64 signature and took the hex one (this program's older form).
var hexHawk atomic.Bool

type grantBody struct {
	ClientID   string `json:"client_id"`
	GrantType  string `json:"grant_type"`
	Scope      string `json:"scope"`
	AccessType string `json:"access_type"`
}

type authorizationBody struct {
	ClientID            string `json:"client_id"`
	ResponseType        string `json:"response_type"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	AccessType          string `json:"access_type"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type codeBody struct {
	ClientID     string `json:"client_id"`
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

// answer is one HTTP answer: its status, a bounded body, and a few headers that say who answered.
type answer struct {
	status int
	body   []byte
	from   string
}

// send sends body (JSON, may be empty) to target, signed with the session's Hawk credentials when hawkID is not empty.
// who says how the request presents itself (asApp, asFirefox, asFirefoxPage).
func send(ctx context.Context, method, target string, body []byte, hawkID string, hawkKey []byte, who int) (*answer, error) {
	flip := false
	for {
		req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		if who == asApp {
			req.Header.Set("User-Agent", appUserAgent)
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Accept-Encoding", "identity")
		} else {
			controlplane.ApplyFirefoxHeaders(req)
		}
		if who == asFirefoxPage {
			req.Header.Set("Origin", "https://accounts.firefox.com")
			req.Header.Set("Referer", "https://accounts.firefox.com/")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Sec-Fetch-Dest", "empty")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Site", "same-site")
		}
		if hawkID != "" {
			var header string
			if hexHawk.Load() != flip {
				header, err = hawkHeader(method, target, hawkID, hawkKey, string(body))
			} else {
				header, err = hawkHeaderBase64(method, target, hawkID, hawkKey, body)
			}
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", header)
		}
		var resp *http.Response
		if who == asApp {
			resp, err = appClient().Do(req)
		} else {
			resp, err = controlplane.Do(req)
		}
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		a := &answer{status: resp.StatusCode, body: data, from: resp.Header.Get("X-Served-By")}
		// The signature was refused (401): the server may take the other way of writing it. Tried once; the form that
		// is not refused is kept for the next calls.
		if a.status == http.StatusUnauthorized && hawkID != "" && !flip {
			flip = true
			continue
		}
		if flip && a.status != http.StatusUnauthorized {
			hexHawk.Store(!hexHawk.Load())
		}
		return a, nil
	}
}

// hawkHeaderBase64 signs as the Hawk specification does (and Firefox): the payload hash and the MAC are base64.
func hawkHeaderBase64(method, rawURL, id string, key, payload []byte) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	nonceBytes := make([]byte, 6)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	port := u.Port()
	if port == "" {
		port = "443"
	}
	hash := ""
	if len(payload) > 0 {
		h := sha256.New()
		h.Write([]byte("hawk.1.payload\napplication/json\n"))
		h.Write(payload)
		h.Write([]byte("\n"))
		hash = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}
	normalized := strings.Join([]string{"hawk.1.header", ts, nonce, strings.ToUpper(method), u.RequestURI(), u.Hostname(), port, hash, "", ""}, "\n")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(normalized))
	header := fmt.Sprintf(`Hawk id="%s", ts="%s", nonce="%s", mac="%s"`, id, ts, nonce, base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	if hash != "" {
		header += fmt.Sprintf(`, hash="%s"`, hash)
	}
	return header, nil
}

// route is one way of getting the tokens. It returns the tokens; or refused (the edge answered 406); or an error.
type route func(ctx context.Context, hawkID string, hawkKey []byte, note func(string)) (tok *TokenResponse, refused bool, err error)

func as(r func(context.Context, string, []byte, func(string), int) (*TokenResponse, bool, error), who int) route {
	return func(ctx context.Context, id string, key []byte, note func(string)) (*TokenResponse, bool, error) {
		return r(ctx, id, key, note, who)
	}
}

// whoLabel is how a step of the error names the client it was sent as.
func whoLabel(who int) string {
	switch who {
	case asApp:
		return "app "
	case asFirefoxPage:
		return "page "
	}
	return ""
}

func readTokens(a *answer) (*TokenResponse, error) {
	var tok TokenResponse
	if err := json.Unmarshal(a.body, &tok); err != nil || tok.AccessToken == "" {
		return nil, errors.New("the answer holds no access token")
	}
	return &tok, nil
}

func describe(a *answer) string {
	s := fmt.Sprintf("%d", a.status)
	if a.from != "" {
		s += " (" + a.from + ")"
	}
	return s
}

// tokenRoute is POST /v1/oauth/token with the fxa-credentials grant.
func tokenRoute(ctx context.Context, hawkID string, hawkKey []byte, note func(string), who int) (*TokenResponse, bool, error) {
	label := whoLabel(who) + "token"
	body, _ := json.Marshal(grantBody{ClientID: firefoxClientID, GrantType: "fxa-credentials", Scope: oauthScope, AccessType: "offline"})
	a, err := send(ctx, http.MethodPost, fxaAuthServer+"/oauth/token", body, hawkID, hawkKey, who)
	if err != nil {
		note(label + ": " + networkText(err))
		return nil, false, nil
	}
	note(label + " " + describe(a))
	switch {
	case a.status == http.StatusOK:
		tok, err := readTokens(a)
		return tok, false, err
	case a.status == http.StatusNotAcceptable:
		return nil, true, nil
	}
	return nil, false, newFxaAPIError(a.status, a.body)
}

// codeRoute asks the account API for an authorization code (PKCE, S256) and exchanges it at the OAuth server.
func codeRoute(ctx context.Context, hawkID string, hawkKey []byte, note func(string), who int) (*TokenResponse, bool, error) {
	label := whoLabel(who) + "authorization"
	var secret [32]byte
	var stateBytes [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, false, err
	}
	if _, err := rand.Read(stateBytes[:]); err != nil {
		return nil, false, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(secret[:])
	sum := sha256.Sum256([]byte(verifier))
	state := hex.EncodeToString(stateBytes[:])

	body, _ := json.Marshal(authorizationBody{
		ClientID: firefoxClientID, ResponseType: "code", Scope: oauthScope, State: state, AccessType: "offline",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), CodeChallengeMethod: "S256",
	})
	a, err := send(ctx, http.MethodPost, fxaAuthServer+"/oauth/authorization", body, hawkID, hawkKey, who)
	if err != nil {
		note(label + ": " + networkText(err))
		return nil, false, nil
	}
	note(label + " " + describe(a))
	switch {
	case a.status == http.StatusNotAcceptable:
		return nil, true, nil
	case a.status != http.StatusOK:
		return nil, false, newFxaAPIError(a.status, a.body)
	}
	var granted struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if json.Unmarshal(a.body, &granted) != nil || granted.Code == "" || granted.State != state {
		return nil, false, errors.New("the authorization answer holds no matching code")
	}

	body, _ = json.Marshal(codeBody{ClientID: firefoxClientID, GrantType: "authorization_code", Code: granted.Code, CodeVerifier: verifier})
	a, err = send(ctx, http.MethodPost, browserOAuthTokenURL, body, "", nil, who)
	if err != nil {
		note(whoLabel(who) + "code exchange: " + networkText(err))
		return nil, false, nil
	}
	note(whoLabel(who) + "code exchange " + describe(a))
	switch {
	case a.status == http.StatusOK:
		tok, err := readTokens(a)
		return tok, false, err
	case a.status == http.StatusNotAcceptable:
		return nil, true, nil
	}
	return nil, false, newFxaAPIError(a.status, a.body)
}

// networkText is a network error without the URL (it may hold a token) and short.
func networkText(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	s := err.Error()
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// BrowserTokens gets the account's OAuth tokens for sessionToken, the session a browser view signed in (confirmed or
// not). An answer of the account server that is not the edge's refusal comes back as it is (an unconfirmed session is
// errno [ErrnoUnverifiedAccount] or [ErrnoUnverifiedSession], see [Errno]); when every route is refused or cannot be
// reached the error is a [*StepsError].
func BrowserTokens(ctx context.Context, sessionToken string) (*TokenResponse, error) {
	hawkID, hawkKey, err := deriveHawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return nil, fmt.Errorf("deriving hawk credentials: %w", err)
	}
	var steps []string
	note := func(s string) { steps = append(steps, s) }
	for round := 0; round < 2; round++ {
		if round == 1 {
			// Both routes were refused: the edge's own challenge, solved the way a browser would, then every route once more.
			if err := solveFastlyChallenge(ctx); err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				note("challenge failed: " + networkText(err))
				break
			}
			note("challenge solved")
		}
		for _, r := range []route{as(tokenRoute, asApp), as(codeRoute, asApp), as(tokenRoute, asFirefox), as(codeRoute, asFirefox), as(tokenRoute, asFirefoxPage), as(codeRoute, asFirefoxPage)} {
			tok, refused, err := r(ctx, hawkID, hawkKey, note)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err != nil {
				return nil, err
			}
			if tok != nil {
				return tok, nil
			}
			_ = refused // a refusal or a network failure: the next route is tried
		}
	}
	probeRefusals(ctx, hawkID, hawkKey, note)
	return nil, &StepsError{Steps: steps, Err: ErrEdgeRefused}
}

// probeRefusals says what the edge looks at, by sending requests that differ from the refused one in one thing each
// (none of them gets a token the program keeps): whether any signed request passes, whether the body matters, and
// whether the VPN scope or the client is what is refused. The answers go into the error the person can report.
func probeRefusals(ctx context.Context, hawkID string, hawkKey []byte, note func(string)) {
	probe := func(name, method, path string, body []byte) {
		if ctx.Err() != nil {
			return
		}
		a, err := send(ctx, method, fxaAuthServer+path, body, hawkID, hawkKey, asFirefoxPage)
		if err != nil {
			note("probe " + name + ": " + networkText(err))
			return
		}
		note("probe " + name + " " + describe(a))
	}
	// The same two as the app: whether the app's way of presenting itself is let through anywhere at all.
	for _, p := range []struct{ name, path string }{{"app session status", "/session/status"}, {"app empty grant", "/oauth/token"}} {
		method, body := http.MethodGet, []byte(nil)
		if p.path == "/oauth/token" {
			method, body = http.MethodPost, []byte("{}")
		}
		if a, err := send(ctx, method, fxaAuthServer+p.path, body, hawkID, hawkKey, asApp); err != nil {
			note("probe " + p.name + ": " + networkText(err))
		} else {
			note("probe " + p.name + " " + describe(a))
		}
	}
	probe("session status", http.MethodGet, "/session/status", nil)
	probe("empty grant", http.MethodPost, "/oauth/token", []byte("{}"))
	other, _ := json.Marshal(grantBody{ClientID: "0000000000000000", GrantType: "fxa-credentials", Scope: oauthScope, AccessType: "offline"})
	probe("grant, other client", http.MethodPost, "/oauth/token", other)
	plain, _ := json.Marshal(struct {
		ClientID  string `json:"client_id"`
		GrantType string `json:"grant_type"`
		Scope     string `json:"scope"`
	}{firefoxClientID, "fxa-credentials", "profile"})
	probe("grant, profile scope", http.MethodPost, "/oauth/token", plain)
}
