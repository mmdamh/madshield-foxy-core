package fxa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mmdamh/madshield-foxy-core/core/internal/controlplane"
)

// MadShield (MadShield CAPTCHA renewal): the real RefreshToken -> fxaDo -> solveFastlyChallenge path against a scripted stand-in for
// Mozilla's edge (Fastly), reached through the control plane's transport seam. Nothing here touches the network.

const testCaptchaImage = "data:image/png;base64,AQID"

// fakeEdge answers like the edge in front of Mozilla's account server, as far as the solver and fxaDo can tell.
type fakeEdge struct {
	t      *testing.T
	cookie string // the cookie value the edge accepts (unique per test: the control plane's jar outlives a test)

	// plan says how the edge answers the post-back of round `round` (1-based) of flow number `flow` (1-based, counted from
	// each challenge script fetched): "more" (asks a CAPTCHA round), "success", "success-nocookie", "reject" (HTTP 403),
	// "error" (HTTP 500), "hang" (never answers).
	plan func(flow, round int) string
	// probeAccepts: the cookie is accepted on the solver's probe. apiAccepts: and on the account server's request.
	probeAccepts bool
	probeAlways  bool // the probe passes even without the cookie (a Fastly that said "success" and sent none)
	apiAccepts   bool
	// token answers the accepted refresh: status and body
	tokenStatus int
	tokenBody   string
	// altAccepts: the way of sending the refresh the edge lets through without any cookie: "app" (the app's User-Agent),
	// "page" (the Origin of Firefox's page) or "oauth_host" (the OAuth server's own host); "" for none.
	altAccepts string

	mu      sync.Mutex
	flow    int
	round   int
	solved  bool     // the current flow's post-back said "success"
	answers []string // the CAPTCHA answers that reached a post-back (to prove delivery, never logged)
	calls   []string
	primary []string // the Accept-Encoding of each refresh sent the first way (Firefox's User-Agent, the account host)
}

func newFakeEdge(t *testing.T) *fakeEdge {
	e := &fakeEdge{
		t: t, cookie: fmt.Sprintf("ok-%s-%d", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano()),
		plan:         func(flow, round int) string { return map[int]string{1: "more", 2: "success"}[round] },
		probeAccepts: true, apiAccepts: true,
		tokenStatus: 200, tokenBody: `{"access_token":"A1","refresh_token":"","expires_in":3600,"scope":"s","token_type":"bearer"}`,
	}
	controlplane.SetTransport(e)
	t.Cleanup(func() { controlplane.SetTransport(nil) })
	return e
}

func (e *fakeEdge) hasCookie(r *http.Request, valid bool) bool {
	return valid && strings.Contains(r.Header.Get("Cookie"), "fst="+e.cookie)
}

func reply(r *http.Request, status int, body string, hdr map[string]string) *http.Response {
	h := http.Header{"Content-Type": {"text/html"}}
	for k, v := range hdr {
		h.Add(k, v)
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: h,
		Body: io.NopCloser(strings.NewReader(body)), Request: r, ProtoMajor: 1, ProtoMinor: 1}
}

func powChallenge() string {
	sum := sha256.Sum256([]byte("bXk"))
	return fmt.Sprintf(`{"ty":"pow","data":{"base":"b","expires":"1","hmac":"h","hash":"%s"}}`, hex.EncodeToString(sum[:]))
}

func captchaChallenge() string {
	return `{"ty":"captcha","data":{"image_b64":"` + testCaptchaImage + `"}}`
}

func (e *fakeEdge) RoundTrip(r *http.Request) (*http.Response, error) {
	e.mu.Lock()
	e.calls = append(e.calls, r.Method+" "+r.URL.Host+r.URL.Path)
	e.mu.Unlock()
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && path == "/" && r.URL.Host == "api.accounts.firefox.com":
		return reply(r, 200, `{"ok":true}`, nil), nil // the API host serves no challenge page
	case r.Method == http.MethodGet && path == "/":
		e.mu.Lock()
		afterSuccess := e.solved
		e.mu.Unlock()
		if (e.probeAlways && afterSuccess) || e.hasCookie(r, e.probeAccepts) {
			return reply(r, 200, "<html>Firefox Accounts</html>", nil), nil
		}
		return reply(r, 200, `<html>Client Challenge <script src="/_fs-ch-abc/script.js"></script></html>`, nil), nil
	case strings.HasSuffix(path, "/script.js"):
		e.mu.Lock()
		e.flow++
		e.round = 0
		e.solved = false
		e.mu.Unlock()
		return reply(r, 200, `;init([`+powChallenge()+`], "tok1", "/_fs-ch-abc", true);`, nil), nil
	case strings.HasSuffix(path, "/fst-post-back"):
		var pb fastlyPostBack
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &pb)
		e.mu.Lock()
		e.round++
		flow, round := e.flow, e.round
		for _, d := range pb.Data {
			if m, ok := d.(map[string]interface{}); ok && m["ty"] == "captcha" {
				e.answers = append(e.answers, fmt.Sprint(m["answer"]))
			}
		}
		e.mu.Unlock()
		switch e.plan(flow, round) {
		case "more":
			return reply(r, 200, fmt.Sprintf(`{"status":"challenge","ch":[%s],"tok":"tok%d"}`, captchaChallenge(), round+1), nil), nil
		case "success":
			e.mu.Lock()
			e.solved = true
			e.mu.Unlock()
			return reply(r, 200, `{"status":"success"}`, map[string]string{"Set-Cookie": "fst=" + e.cookie + "; Domain=firefox.com; Path=/"}), nil
		case "success-nocookie":
			e.mu.Lock()
			e.solved = true
			e.mu.Unlock()
			return reply(r, 200, `{"status":"success"}`, nil), nil
		case "reject":
			return reply(r, 403, `{"error":"denied"}`, nil), nil
		case "error":
			return reply(r, 500, `oops`, nil), nil
		case "hang":
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		e.t.Fatalf("no plan for flow %d round %d", flow, round)
	case r.Method == http.MethodPost && path == "/v1/token" && r.URL.Host == "oauth.accounts.firefox.com":
		if e.altAccepts != "oauth_host" && !e.hasCookie(r, e.apiAccepts) {
			return reply(r, 406, "", nil), nil
		}
		return reply(r, e.tokenStatus, e.tokenBody, map[string]string{"Content-Type": "application/json"}), nil
	case r.Method == http.MethodPost && path == "/v1/oauth/token":
		ua := r.Header.Get("User-Agent")
		switch {
		case strings.HasPrefix(ua, "MozillaVPN") && e.altAccepts == "app",
			r.Header.Get("Origin") != "" && e.altAccepts == "page":
			return reply(r, e.tokenStatus, e.tokenBody, map[string]string{"Content-Type": "application/json"}), nil
		}
		if r.Header.Get("Origin") == "" && !strings.HasPrefix(ua, "MozillaVPN") {
			e.mu.Lock()
			e.primary = append(e.primary, r.Header.Get("Accept-Encoding"))
			e.mu.Unlock()
		}
		if !e.hasCookie(r, e.apiAccepts) {
			return reply(r, 406, "", nil), nil
		}
		return reply(r, e.tokenStatus, e.tokenBody, map[string]string{"Content-Type": "application/json"}), nil
	}
	e.t.Fatalf("unexpected request %s %s", r.Method, r.URL)
	return nil, nil
}

// watch collects the events of a flow.
type watch struct {
	mu     sync.Mutex
	events []ChallengeEvent
}

func (w *watch) note(ev ChallengeEvent) {
	w.mu.Lock()
	w.events = append(w.events, ev)
	w.mu.Unlock()
}

func (w *watch) kinds() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var parts []string
	for _, ev := range w.events {
		s := ev.Kind
		if ev.Result != "" {
			s += ":" + ev.Result
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func (w *watch) first(kind string) (ChallengeEvent, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, ev := range w.events {
		if ev.Kind == kind {
			return ev, true
		}
	}
	return ChallengeEvent{}, false
}

// refresh runs the real refresh with a CAPTCHA solver that answers `answer` and counts its calls.
func refresh(t *testing.T, ctx context.Context, w *watch, answer string) (*TokenResponse, int, error) {
	t.Helper()
	calls := 0
	solver := func(ctx context.Context, image string) (string, error) {
		calls++
		if image != testCaptchaImage {
			t.Errorf("the solver got another picture: %q", image)
		}
		return answer, nil
	}
	ctx = WithCaptchaSolver(ctx, solver)
	if w != nil {
		ctx = WithChallengeObserver(ctx, w.note)
	}
	tok, err := RefreshToken(ctx, "old-refresh")
	return tok, calls, err
}

func requireKinds(t *testing.T, w *watch, want string) {
	t.Helper()
	// the other ways of sending the refresh (EvAlternate) have tests of their own
	var kept []string
	for _, k := range strings.Fields(w.kinds()) {
		if !strings.HasPrefix(k, EvAlternate) {
			kept = append(kept, k)
		}
	}
	if got := strings.Join(kept, " "); got != want {
		t.Fatalf("events:\n got  %s\n want %s", got, want)
	}
}

// A CAPTCHA answered, Fastly accepts, the original refresh is sent again and succeeds.
func TestMadShieldChallengeSuccessfulCaptchaAndRefresh(t *testing.T) {
	edge := newFakeEdge(t)
	w := &watch{}
	tok, calls, err := refresh(t, context.Background(), w, "k7Q2")
	if err != nil || tok == nil || tok.AccessToken != "A1" {
		t.Fatalf("refresh: %v %+v", err, tok)
	}
	if tok.RefreshToken != "old-refresh" {
		t.Fatalf("a refresh that does not rotate keeps the refresh token, got %q", tok.RefreshToken)
	}
	if calls != 1 || len(edge.answers) != 1 || edge.answers[0] != "k7Q2" {
		t.Fatalf("the answer must reach the post-back: solver calls=%d answers=%d", calls, len(edge.answers))
	}
	requireKinds(t, w, "attempt host no_challenge_page host round post_back:more round post_back:success probe:accepted cookies:installed solved retry reply")
	if ev, _ := w.first(EvReply); ev.Attempt != 2 || ev.Status != 200 {
		t.Fatalf("the retried request: %+v", ev)
	}
	// the events must never carry what the person typed
	if fmt.Sprintf("%+v", w.events) != strings.ReplaceAll(fmt.Sprintf("%+v", w.events), "k7Q2", "") {
		t.Fatal("an event holds the CAPTCHA answer")
	}
}

// A valid-looking answer followed by another round is "more", not a rejection; rounds are counted.
func TestMadShieldChallengeAdditionalAndConsecutiveRounds(t *testing.T) {
	edge := newFakeEdge(t)
	edge.plan = func(flow, round int) string {
		return map[int]string{1: "more", 2: "more", 3: "more", 4: "success"}[round]
	}
	w := &watch{}
	_, calls, err := refresh(t, context.Background(), w, "abcd")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("three CAPTCHA rounds: solver called %d times", calls)
	}
	if got := strings.Count(w.kinds(), "post_back:more"); got != 3 {
		t.Fatalf("post_back:more x%d, events: %s", got, w.kinds())
	}
}

// Fastly itself refusing the post-back (HTTP 4xx) is reported as a refusal, with its status.
func TestMadShieldChallengeRejectedPostBack(t *testing.T) {
	edge := newFakeEdge(t)
	edge.plan = func(flow, round int) string { return map[int]string{1: "more", 2: "reject"}[round] }
	w := &watch{}
	_, _, err := refresh(t, context.Background(), w, "nope")
	if err == nil {
		t.Fatal("a refused post-back must fail the refresh")
	}
	pb := w.events[indexOfKind(w, EvPostBack, "rejected")]
	if pb.Status != 403 || pb.Round != 2 {
		t.Fatalf("post-back event: %+v", pb)
	}
	if !strings.Contains(w.kinds(), "failed:other") || strings.Contains(w.kinds(), "solved") {
		t.Fatalf("events: %s", w.kinds())
	}
}

func indexOfKind(w *watch, kind, result string) int {
	for i, ev := range w.events {
		if ev.Kind == kind && ev.Result == result {
			return i
		}
	}
	panic("no event " + kind + ":" + result + " in " + w.kinds())
}

// A post-back that fails on the server (HTTP 5xx) is an error, not a refusal.
func TestMadShieldChallengeFailedPostBack(t *testing.T) {
	edge := newFakeEdge(t)
	edge.plan = func(flow, round int) string { return "error" }
	w := &watch{}
	_, _, err := refresh(t, context.Background(), w, "x")
	if err == nil {
		t.Fatal("expected an error")
	}
	if ev := w.events[indexOfKind(w, EvPostBack, "error")]; ev.Status != 500 {
		t.Fatalf("post-back event: %+v", ev)
	}
}

// Fastly says "success" but no cookie reaches the jar: missing session cookies.
func TestMadShieldChallengeMissingSessionCookies(t *testing.T) {
	edge := newFakeEdge(t)
	edge.plan = func(flow, round int) string { return map[int]string{1: "more", 2: "success-nocookie"}[round] }
	edge.probeAlways = true // so the flow reaches the step that carries the cookie over
	w := &watch{}
	_, _, err := refresh(t, context.Background(), w, "x")
	if err == nil {
		t.Fatal("expected an error")
	}
	got := w.kinds()
	if !strings.Contains(got, "cookies:missing") || !strings.Contains(got, "failed:cookies") || strings.Contains(got, "solved") {
		t.Fatalf("events: %s", got)
	}
	if !errors.Is(err, errChallengeNoCookies) {
		t.Fatalf("the error must say no cookie was issued, got %v", err)
	}
}

// The cookie is not accepted on the probe (another exit IP / transport): the flow says so and fails, it does not retry
// the original request as if the challenge were solved.
func TestMadShieldChallengeExitChangeFailsTheProbe(t *testing.T) {
	edge := newFakeEdge(t)
	edge.probeAccepts = false
	w := &watch{}
	_, _, err := refresh(t, context.Background(), w, "x")
	if !errors.Is(err, errChallengeNotAccepted) {
		t.Fatalf("want errChallengeNotAccepted, got %v", err)
	}
	got := w.kinds()
	if !strings.Contains(got, "probe:still_challenged") || !strings.Contains(got, "failed:probe") || strings.Contains(got, "retry") {
		t.Fatalf("events: %s", got)
	}
}

// The challenge completes and the probe passes, but the account server keeps answering 406 to the original request: every
// try is a new flow with a new CAPTCHA, the tries are bounded, and the end is the distinct "still refused" error.
func TestMadShieldChallengeSolvedButRefreshStillRefused(t *testing.T) {
	edge := newFakeEdge(t)
	edge.apiAccepts = false
	w := &watch{}
	_, calls, err := refresh(t, context.Background(), w, "abcd")
	if !errors.Is(err, ErrChallengeStillRefused) {
		t.Fatalf("want ErrChallengeStillRefused, got %v", err)
	}
	if calls != maxChallengeAttempts {
		t.Fatalf("one CAPTCHA per try: %d calls, want %d", calls, maxChallengeAttempts)
	}
	if _, ok := w.first(EvGiveUp); !ok || strings.Count(w.kinds(), "retry") != maxChallengeAttempts-1 {
		t.Fatalf("events: %s", w.kinds())
	}
	if !strings.Contains(err.Error(), "406") {
		t.Fatalf("the error keeps its old text, got %q", err)
	}
}

// The challenge completes but the original refresh then fails with an account-server error (not a 406).
func TestMadShieldChallengeSolvedThenRefreshFails(t *testing.T) {
	edge := newFakeEdge(t)
	edge.tokenStatus, edge.tokenBody = 401, `{"errno":110,"message":"Invalid token"}`
	w := &watch{}
	_, _, err := refresh(t, context.Background(), w, "abcd")
	if err == nil || errors.Is(err, ErrChallengeStillRefused) {
		t.Fatalf("want an account-server error, got %v", err)
	}
	if ev, ok := w.first(EvReply); !ok || ev.Status != 401 {
		t.Fatalf("reply event: %+v (%s)", ev, w.kinds())
	}
	if Message(err) != "Invalid token" {
		t.Fatalf("message: %q", Message(err))
	}
}

// Cancelling while the post-back is in flight ends the flow promptly with the context's error.
func TestMadShieldChallengeCancelDuringVerification(t *testing.T) {
	edge := newFakeEdge(t)
	edge.plan = func(flow, round int) string { return map[int]string{1: "more", 2: "hang"}[round] }
	w := &watch{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, _, err := refresh(t, ctx, w, "abcd"); done <- err }()
	waitFor(t, func() bool { edge.mu.Lock(); defer edge.mu.Unlock(); return len(edge.answers) == 1 })
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the flow did not stop on cancel")
	}
	if !strings.Contains(w.kinds(), "failed:cancelled") {
		t.Fatalf("events: %s", w.kinds())
	}
}

// A deadline that passes while the post-back is in flight ends the flow with the context's deadline error.
func TestMadShieldChallengeTimeoutDuringSubmission(t *testing.T) {
	edge := newFakeEdge(t)
	edge.plan = func(flow, round int) string { return map[int]string{1: "more", 2: "hang"}[round] }
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := refresh(t, ctx, &watch{}, "abcd")
	// fxaDo works on a context it derived (contextWithMinDeadline), so the parent's expiry reaches the request as a
	// cancellation: the caller must read its own context to tell a timeout from a cancel (the renewal job does).
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the context's error, got %v", err)
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("the caller's own context must report the deadline, got %v", ctx.Err())
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the deadline was not honoured")
	}
}

// Without an observer the flow behaves as before.
func TestMadShieldChallengeWorksWithoutObserver(t *testing.T) {
	newFakeEdge(t)
	tok, calls, err := refresh(t, context.Background(), nil, "abcd")
	if err != nil || tok == nil || calls != 1 {
		t.Fatalf("refresh: %v %+v calls=%d", err, tok, calls)
	}
}

// A CAPTCHA with no solver in the context keeps its old, plain error.
func TestMadShieldChallengeWithoutSolverStillSaysSignInFromTheDashboard(t *testing.T) {
	newFakeEdge(t)
	_, err := RefreshToken(context.Background(), "old-refresh")
	if err == nil || !strings.Contains(err.Error(), "Fastly requires an image CAPTCHA") {
		t.Fatalf("got %v", err)
	}
}

// Rotation: a refresh that returns a new refresh token passes it on.
func TestMadShieldRefreshTokenRotationIsPassedOn(t *testing.T) {
	edge := newFakeEdge(t)
	edge.tokenBody = `{"access_token":"A2","refresh_token":"new-refresh","expires_in":3600,"scope":"s","token_type":"bearer"}`
	tok, _, err := refresh(t, context.Background(), nil, "abcd")
	if err != nil || tok.RefreshToken != "new-refresh" {
		t.Fatalf("got %v %+v", err, tok)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// altResults are the Result and Status of the EvAlternate events, "app:406 page:406 oauth_host:406".
func altResults(w *watch) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var parts []string
	for _, ev := range w.events {
		if ev.Kind == EvAlternate {
			parts = append(parts, fmt.Sprintf("%s:%d", ev.Result, ev.Status))
		}
	}
	return strings.Join(parts, " ")
}

// The edge refuses the refresh the usual way, however many challenges are solved, and lets the app's way through: no
// CAPTCHA may be asked.
func TestMadShieldRefreshOtherWaysBeforeAnyCaptcha(t *testing.T) {
	for _, way := range []string{"app", "page", "oauth_host"} {
		t.Run(way, func(t *testing.T) {
			edge := newFakeEdge(t)
			edge.altAccepts = way
			edge.apiAccepts = false // no cookie ever opens the usual way
			w := &watch{}
			tok, calls, err := refresh(t, context.Background(), w, "k7Q2")
			if err != nil || tok == nil || tok.AccessToken != "A1" {
				t.Fatalf("refresh: %v %+v", err, tok)
			}
			if calls != 0 || len(edge.answers) != 0 {
				t.Fatalf("a CAPTCHA was asked although another way works: calls=%d", calls)
			}
			if _, solved := w.first(EvSolved); solved {
				t.Fatal("a challenge was solved although another way works")
			}
			got := altResults(w)
			if !strings.HasSuffix(got, way+":200") {
				t.Fatalf("alternates: %s", got)
			}
		})
	}
}

// When no other way is let through either, the challenge still runs as before, and the other ways were tried once for
// each of the first answers of 406.
func TestMadShieldRefreshOtherWaysRefusedThenChallenge(t *testing.T) {
	edge := newFakeEdge(t)
	w := &watch{}
	tok, calls, err := refresh(t, context.Background(), w, "k7Q2")
	if err != nil || tok == nil || calls != 1 {
		t.Fatalf("refresh: %v %+v calls=%d", err, tok, calls)
	}
	if got := altResults(w); got != "app:406 page:406 oauth_host:406" {
		t.Fatalf("alternates: %s", got)
	}
	_ = edge
}

// Every try refused: the other ways are tried for the first alternateAttempts answers only, not after every challenge.
func TestMadShieldRefreshOtherWaysAreBounded(t *testing.T) {
	edge := newFakeEdge(t)
	edge.apiAccepts = false
	w := &watch{}
	_, _, err := refresh(t, context.Background(), w, "k7Q2")
	if !errors.Is(err, ErrChallengeStillRefused) {
		t.Fatalf("want ErrChallengeStillRefused, got %v", err)
	}
	if n := strings.Count(altResults(w), "app:"); n != alternateAttempts {
		t.Fatalf("the other ways were tried %d times, want %d", n, alternateAttempts)
	}
}

// The refresh sent the usual way does not carry net/http's own gzip.
func TestMadShieldRefreshAsksForNoCompression(t *testing.T) {
	edge := newFakeEdge(t)
	if _, _, err := refresh(t, context.Background(), nil, "k7Q2"); err != nil {
		t.Fatal(err)
	}
	if len(edge.primary) == 0 {
		t.Fatal("no refresh was sent the usual way")
	}
	for _, enc := range edge.primary {
		if enc != "identity" {
			t.Fatalf("Accept-Encoding %q, want identity", enc)
		}
	}
}

// What the edge says about an answer that is not the account server's own (an HTML page, an edge error) is not taken as
// the answer to the refresh: the next way, then the challenge, follow.
func TestMadShieldAccountServerAnswerIsToldFromTheEdge(t *testing.T) {
	if !isAccountServerAnswer([]byte(`{"code":400,"errno":107,"error":"Invalid parameter"}`)) {
		t.Fatal("an errno body is the account server's")
	}
	for _, body := range []string{"", "<html>blocked</html>", `{"error":"denied"}`, `{"errno":0}`} {
		if isAccountServerAnswer([]byte(body)) {
			t.Fatalf("%q is not the account server's", body)
		}
	}
}

// The solved cookie must be installed for the OAuth server's host too (it comes out of the solver's jar without its
// Domain, so each host needs its own copy).
func TestMadShieldSolvedCookieReachesTheOAuthHost(t *testing.T) {
	newFakeEdge(t)
	if _, _, err := refresh(t, context.Background(), nil, "k7Q2"); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, browserOAuthTokenURL, strings.NewReader("{}"))
	resp, err := controlplane.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the OAuth host answered %d: the challenge cookie did not reach it", resp.StatusCode)
	}
}
