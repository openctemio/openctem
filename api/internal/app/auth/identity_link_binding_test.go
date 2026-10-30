package auth

// Account linking takes the same single-use, browser-bound PKCE record as
// sign-in (storeBoundVerifier / claimBoundVerifier). Threats covered here:
//   - login CSRF on linking: a victim's browser is made to finish a link the
//     attacker started (or the attacker's callback URL leaks to the victim);
//     the binding secret lives only in the starting browser's cookie;
//   - replay of a used state (and its code), e.g. from a log or Referer;
//   - completion after the state expired.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

const linkRedirect = "https://app.example/auth/callback/github"

// githubMock is a GitHub authorization server enforcing PKCE, with the two
// userinfo endpoints the link reads.
type githubMock struct {
	mu         sync.Mutex
	challenge  string
	tokenCalls int
	srv        *httptest.Server
}

func newGitHubMock(t *testing.T) *githubMock {
	t.Helper()
	m := &githubMock{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/access_token"):
			_ = r.ParseForm()
			m.tokenCalls++
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != m.challenge {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer"}`))
		case r.URL.Path == "/user":
			_, _ = w.Write([]byte(`{"id":4242,"login":"octo","name":"Octo"}`))
		case r.URL.Path == "/user/emails":
			_, _ = w.Write([]byte(`[{"email":"octo@users.example","primary":true,"verified":true}]`))
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

type linkBindingFixture struct {
	*linkFixture
	gh   *githubMock
	acct *userdom.User
}

func newLinkBindingFixture(t *testing.T) *linkBindingFixture {
	t.Helper()
	acct := verifiedPasswordAccount(t, "p@acme.example")
	f := newLinkFixture(t, acct)
	f.svc.config.StateSecret = "state-secret-for-tests-0123456789"
	f.svc.config.StateDuration = 5 * time.Minute
	f.svc.config.GitHub = config.OAuthProviderConfig{Enabled: true, ClientID: "cid", ClientSecret: "csecret"}
	gh := newGitHubMock(t)
	target, _ := url.Parse(gh.srv.URL)
	f.svc.httpClient = &http.Client{Transport: redirectTransport{target: target}, Timeout: 5 * time.Second}
	return &linkBindingFixture{linkFixture: f, gh: gh, acct: acct}
}

// start runs StartLink and returns the state and the browser binding.
func (f *linkBindingFixture) start(t *testing.T) (state, binding string) {
	t.Helper()
	res, err := f.svc.StartLink(context.Background(), LinkStartInput{
		UserID: f.acct.ID().String(), SessionID: "s-1", Provider: OAuthProviderGitHub, RedirectURI: linkRedirect,
		Proof: goodProof,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.BrowserBinding == "" {
		t.Fatal("StartLink returned no browser binding")
	}
	u, err := url.Parse(res.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	f.gh.mu.Lock()
	f.gh.challenge = u.Query().Get("code_challenge")
	f.gh.mu.Unlock()
	return res.State, res.BrowserBinding
}

func (f *linkBindingFixture) complete(state, binding, code string) (*SignInMethod, error) {
	return f.svc.CompleteLink(context.Background(), LinkCompleteInput{
		UserID: f.acct.ID().String(), SessionID: "s-1", Provider: OAuthProviderGitHub,
		Code: code, State: state, RedirectURI: linkRedirect, BrowserBinding: binding,
	})
}

func (f *linkBindingFixture) assertNotLinked(t *testing.T) {
	t.Helper()
	if n := len(f.idents.keysOf(f.acct.ID())); n != 0 {
		t.Fatalf("identity linked anyway (%d)", n)
	}
	if len(f.notifier.linked) != 0 {
		t.Fatal("link notice sent for a refused link")
	}
}

// The browser that started the link finishes it: the identity is bound.
func TestCompleteLink_SameBrowserLinks(t *testing.T) {
	f := newLinkBindingFixture(t)
	state, binding := f.start(t)
	m, err := f.complete(state, binding, "code-1")
	if err != nil || m == nil || m.Provider != "github" {
		t.Fatalf("link: %+v %v", m, err)
	}
	if keys := f.idents.keysOf(f.acct.ID()); len(keys) != 1 || keys[0].Issuer != githubIssuer || keys[0].Subject != "4242" {
		t.Fatalf("bound keys %+v", keys)
	}
	if f.gh.tokenCalls != 1 {
		t.Fatalf("token calls %d", f.gh.tokenCalls)
	}
}

// Code + state reaching another browser (or a browser made to post them)
// are refused before the code exchange, and spend the record: the starting
// browser cannot be raced afterwards either.
func TestCompleteLink_OtherBrowserRefused(t *testing.T) {
	for name, presented := range map[string]string{"foreign binding": "someone-elses-binding", "no binding": ""} {
		t.Run(name, func(t *testing.T) {
			f := newLinkBindingFixture(t)
			state, binding := f.start(t)
			if _, err := f.complete(state, presented, "code-1"); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("want ErrInvalidState, got %v", err)
			}
			if f.gh.tokenCalls != 0 {
				t.Fatalf("a foreign browser reached the token endpoint (%d calls)", f.gh.tokenCalls)
			}
			if _, err := f.complete(state, binding, "code-1"); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("record not spent by the refused attempt: %v", err)
			}
			f.assertNotLinked(t)
		})
	}
}

// A used state is refused, even with the right binding and a fresh code.
func TestCompleteLink_ReplayedStateRefused(t *testing.T) {
	f := newLinkBindingFixture(t)
	state, binding := f.start(t)
	if _, err := f.complete(state, binding, "code-1"); err != nil {
		t.Fatalf("first completion: %v", err)
	}
	if _, err := f.complete(state, binding, "intercepted-code"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("replayed state: want ErrInvalidState, got %v", err)
	}
	if f.gh.tokenCalls != 1 {
		t.Fatalf("replayed state reached the token endpoint (%d calls)", f.gh.tokenCalls)
	}
}

// An expired link is refused: once the stored record lapsed, and when the
// signed state itself is past its expiry even with a live record.
func TestCompleteLink_ExpiredStateRefused(t *testing.T) {
	t.Run("record expired", func(t *testing.T) {
		f := newLinkBindingFixture(t)
		f.svc.config.StateDuration = 20 * time.Millisecond
		state, binding := f.start(t)
		time.Sleep(60 * time.Millisecond)
		if _, err := f.complete(state, binding, "code-1"); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("want ErrInvalidState, got %v", err)
		}
		if f.gh.tokenCalls != 0 {
			t.Fatal("expired record reached the token endpoint")
		}
		f.assertNotLinked(t)
	})
	t.Run("signed expiry passed", func(t *testing.T) {
		f := newLinkBindingFixture(t)
		raw, _ := json.Marshal(map[string]any{
			"provider": string(OAuthProviderGitHub), "final_redirect": "", "random": "r",
			"exp": time.Now().Add(-time.Minute).Unix(), "purpose": statePurposeLink,
			"uid": f.acct.ID().String(), "sid": "s-1",
		})
		body := base64.URLEncoding.EncodeToString(raw)
		state := body + "." + f.svc.signState(body)
		binding, err := f.svc.storeBoundVerifier(context.Background(), state, "verifier-verifier-verifier-verifier-0123")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.complete(state, binding, "code-1"); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("want ErrInvalidState, got %v", err)
		}
		if f.gh.tokenCalls != 0 {
			t.Fatal("expired state reached the token endpoint")
		}
		f.assertNotLinked(t)
	})
}

// A sign-in's binding does not complete a link and a link's binding does not
// sign in: each record is claimed only by its own state.
func TestCompleteLink_SignInBindingDoesNotCompleteLink(t *testing.T) {
	f := newLinkBindingFixture(t)
	state, _ := f.start(t)
	login, err := f.svc.GetAuthorizationURL(context.Background(), AuthorizationURLInput{
		Provider: OAuthProviderGitHub, RedirectURI: linkRedirect, FinalRedirect: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.complete(state, login.BrowserBinding, "code-1"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("want ErrInvalidState, got %v", err)
	}
	f.assertNotLinked(t)
}

// A link start needs the proof typed for it: without one (or with a wrong
// one) nothing is minted. A link whose start was never proved (a state signed
// and stored without the proof record) does not complete.
func TestStartLink_NeedsProof(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		proof StepUpProof
		want  error
	}{
		"no proof":    {StepUpProof{}, ErrLinkProofRequired},
		"wrong proof": {StepUpProof{TOTP: "000000"}, ErrLinkProofFailed},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLinkBindingFixture(t)
			res, err := f.svc.StartLink(ctx, LinkStartInput{
				UserID: f.acct.ID().String(), SessionID: "s-1", Provider: OAuthProviderGitHub, RedirectURI: linkRedirect, Proof: tc.proof,
			})
			if !errors.Is(err, tc.want) || res != nil {
				t.Fatalf("want %v, got %+v %v", tc.want, res, err)
			}
			if got := f.proof.purposes; len(got) != 1 || got[0] != LinkProofLinkStart {
				t.Fatalf("purposes %v", got)
			}
		})
	}
	t.Run("no verifier wired (fail closed)", func(t *testing.T) {
		f := newLinkBindingFixture(t)
		f.svc.SetLinkProofVerifier(nil)
		if _, err := f.svc.StartLink(ctx, LinkStartInput{
			UserID: f.acct.ID().String(), SessionID: "s-1", Provider: OAuthProviderGitHub, RedirectURI: linkRedirect, Proof: goodProof,
		}); !errors.Is(err, ErrLinkProofUnavailable) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("start never proved does not complete", func(t *testing.T) {
		f := newLinkBindingFixture(t)
		state, verifier, err := f.svc.generateState(OAuthProviderGitHub, "", &linkBinding{UserID: f.acct.ID().String(), SessionID: "s-1"})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := f.svc.storeBoundVerifier(ctx, state, verifier)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.complete(state, binding, "code-1"); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("want ErrInvalidState, got %v", err)
		}
		if f.gh.tokenCalls != 0 {
			t.Fatal("an unproved link reached the token endpoint")
		}
		f.assertNotLinked(t)
	})
}
