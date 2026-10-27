package platformsociallogin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	clientID = "1234567890-abc.apps.googleusercontent.com"
	secret   = "GOCSPX-super-secret-value-123"
)

func newSvc(t *testing.T, env config.OAuthConfig) (*Service, *cst.Repo, *cst.Audit, *cst.Notifier) {
	t.Helper()
	env.Enabled = true
	env.FrontendCallbackURL = "https://ctem.example.com/auth/callback"
	repo, audit, n := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}
	return NewService(repo, cst.Cipher(t), cst.Recorder(audit, n), env, nil), repo, audit, n
}

func enable(t *testing.T, s *Service, provider string, version int) {
	t.Helper()
	_, err := s.Update(context.Background(), cst.SuperAdmin(t), provider,
		Input{Enabled: true, ClientID: clientID, Secret: cst.Strp(secret), Reason: "offer Google sign-in"}, version, "203.0.113.5", "test")
	if err != nil {
		t.Fatal(err)
	}
}

// The secret is encrypted at rest, never returned, never in the audit row or
// the notice; the change is critical, carries the reason and is told to every
// administrator; and it is live at once (the OAuth service reads it).
func TestSecretIsWriteOnlyAndApplies(t *testing.T) {
	s, repo, audit, n := newSvc(t, config.OAuthConfig{})
	ctx := context.Background()
	if cfgOn(s.OAuthProvider(ctx, Google)) {
		t.Fatal("nothing is stored yet")
	}
	enable(t, s, Google, 0)
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	g := got.Providers[0]
	if g.Provider != Google || !g.Enabled || !g.SecretSet || g.ClientID != clientID || g.Source != SourceConsole || !g.Active || g.LockedByEnvironment {
		t.Fatalf("google = %+v", g)
	}
	if g.RedirectURI != "https://ctem.example.com/auth/callback/google" || got.JavaScriptOrigin != "https://ctem.example.com" {
		t.Fatalf("redirect = %q origin = %q", g.RedirectURI, got.JavaScriptOrigin)
	}
	if strings.Contains(repo.Raw(SettingKey), secret) {
		t.Fatal("the secret is stored in clear text")
	}
	if strings.Contains(audit.JSON(t), secret) || strings.Contains(n.All(), secret) {
		t.Fatal("the secret leaked into the audit log or the notice")
	}
	if len(audit.Entries) != 1 || audit.Entries[0].Action != ActionChanged || !strings.Contains(audit.JSON(t), "offer Google sign-in") || n.Count() != 1 {
		t.Fatalf("audit = %s notices = %d", audit.JSON(t), n.Count())
	}
	cfg := s.OAuthProvider(ctx, Google)
	if !cfgOn(cfg) || cfg.ClientSecret != secret || strings.Join(cfg.Scopes, " ") != "openid email profile" {
		t.Fatalf("the provider in force = %+v", cfg)
	}
	if cfgOn(s.OAuthProvider(ctx, GitHub)) || !s.Offered(ctx, Google) || s.Offered(ctx, GitHub) {
		t.Fatal("only Google is on")
	}
}

// A second replica reads the change within the cache time, and a change made
// through one service value is read by another sharing the table.
func TestAnotherReplicaSeesTheChange(t *testing.T) {
	a, repo, _, _ := newSvc(t, config.OAuthConfig{})
	b := NewService(repo, cst.Cipher(t), cst.Recorder(&cst.Audit{}, &cst.Notifier{}), a.env, nil)
	ctx := context.Background()
	if b.Offered(ctx, Google) {
		t.Fatal("off at first")
	}
	enable(t, a, Google, 0)
	if b.Offered(ctx, Google) {
		t.Fatal("b serves its cached value inside the cache time")
	}
	b.store.SetClock(func() time.Time { return time.Now().Add(2 * consolesetting.CacheTTL) })
	if !b.Offered(ctx, Google) {
		t.Fatal("the other replica did not see the change after the cache time")
	}
}

func TestEnvironmentPinsAProvider(t *testing.T) {
	env := config.OAuthConfig{Google: config.OAuthProviderConfig{Enabled: true, ClientID: "env-client-id", ClientSecret: "env-client-secret"}}
	s, _, _, _ := newSvc(t, env)
	ctx := context.Background()
	_, err := s.Update(ctx, cst.SuperAdmin(t), Google, Input{Enabled: false, Reason: "off"}, 0, "", "")
	if !errors.Is(err, ErrLockedByEnvironment) {
		t.Fatalf("err = %v, want locked", err)
	}
	got, _ := s.Get(ctx)
	g := got.Providers[0]
	if !g.LockedByEnvironment || g.Source != SourceEnvironment || g.EnvVar != "OAUTH_GOOGLE_CLIENT_SECRET" || !g.SecretSet || !g.Active {
		t.Fatalf("google = %+v", g)
	}
	if !cfgOn(s.OAuthProvider(ctx, Google)) {
		t.Fatal("the environment values are in force")
	}
	// Another provider is still manageable.
	enable(t, s, GitHub, 0)
}

func TestMasterSwitchOffTurnsEverythingOff(t *testing.T) {
	s, _, _, _ := newSvc(t, config.OAuthConfig{})
	enable(t, s, Google, 0)
	s.env.Enabled = false
	if s.Offered(context.Background(), Google) {
		t.Fatal("OAUTH_ENABLED=false must win over the console")
	}
	got, _ := s.Get(context.Background())
	if got.MasterEnabled || got.Providers[0].Active {
		t.Fatalf("got = %+v", got)
	}
}

func TestValidation(t *testing.T) {
	s, _, _, _ := newSvc(t, config.OAuthConfig{})
	ctx := context.Background()
	a := cst.SuperAdmin(t)
	for name, in := range map[string]Input{
		"no reason":              {ClientID: clientID, Secret: cst.Strp(secret)},
		"enabled without client": {Enabled: true, Reason: "r"},
		"id without secret":      {ClientID: clientID, Reason: "r"},
		"secret without id":      {Secret: cst.Strp(secret), Reason: "r"},
		"bad client id":          {ClientID: "has space", Secret: cst.Strp(secret), Reason: "r"},
		"bad secret":             {ClientID: clientID, Secret: cst.Strp("short"), Reason: "r"},
		"scopes without openid":  {ClientID: clientID, Secret: cst.Strp(secret), Scopes: []string{"email"}, Reason: "r"},
		"bad scope":              {ClientID: clientID, Secret: cst.Strp(secret), Scopes: []string{"openid", "email", "a b"}, Reason: "r"},
	} {
		if _, err := s.Update(ctx, a, Google, in, 0, "", ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := s.Update(ctx, a, "gitlab", Input{Reason: "r"}, 0, "", ""); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown provider: %v", err)
	}
	if _, err := s.Update(ctx, nil, Google, Input{Reason: "r"}, 0, "", ""); !errors.Is(err, ErrNoActor) {
		t.Errorf("no actor: %v", err)
	}
	if _, err := s.Update(ctx, a, Google, Input{ClientID: clientID, Secret: cst.Strp(secret), Scopes: []string{"openid", "email"}, Reason: "r"}, 0, "", ""); err != nil {
		t.Errorf("valid custom scopes: %v", err)
	}
}

func TestStaleVersionAndReplaceKeepAndRemove(t *testing.T) {
	s, _, _, _ := newSvc(t, config.OAuthConfig{})
	ctx := context.Background()
	a := cst.SuperAdmin(t)
	enable(t, s, Google, 0)
	if _, err := s.Update(ctx, a, Google, Input{ClientID: clientID, Reason: "r"}, 0, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	// Keep the secret (nil), change only the on/off switch.
	if _, err := s.Update(ctx, a, Google, Input{Enabled: false, ClientID: clientID, Reason: "pause"}, 1, "", ""); err != nil {
		t.Fatal(err)
	}
	if s.Offered(ctx, Google) || s.OAuthProvider(ctx, Google).ClientSecret != secret {
		t.Fatal("paused, secret kept")
	}
	// Remove both.
	if _, err := s.Update(ctx, a, Google, Input{ClientID: clientID, Secret: cst.Strp(""), Reason: "remove"}, 2, "", ""); err == nil {
		t.Fatal("removing only the secret must be refused")
	}
	got, err := s.Update(ctx, a, Google, Input{ClientID: "", Secret: cst.Strp(""), Reason: "remove"}, 2, "", "")
	if err != nil || got.Providers[0].SecretSet || got.Providers[0].ClientID != "" {
		t.Fatalf("removed: %+v %v", got, err)
	}
}

// A secret that no longer decrypts (key rotated without rekey) turns the
// provider off rather than failing open or crashing.
func TestUndecryptableSecretFailsClosed(t *testing.T) {
	s, repo, _, _ := newSvc(t, config.OAuthConfig{})
	enable(t, s, Google, 0)
	other := NewService(repo, cst.OtherCipher(t), cst.Recorder(&cst.Audit{}, &cst.Notifier{}), s.env, nil)
	ctx := context.Background()
	if other.Offered(ctx, Google) {
		t.Fatal("an undecryptable secret must not start a sign-in")
	}
	got, _ := other.Get(ctx)
	if !got.Providers[0].Undecryptable || !got.Providers[0].SecretSet || got.Providers[0].Active {
		t.Fatalf("google = %+v", got.Providers[0])
	}
}

func TestNoStoreMeansNothingOffered(t *testing.T) {
	s := NewService(nil, cst.Cipher(t), nil, config.OAuthConfig{Enabled: true}, nil)
	if s.Offered(context.Background(), Google) {
		t.Fatal("nothing stored")
	}
	if _, err := s.Update(context.Background(), cst.SuperAdmin(t), Google, Input{Reason: "r"}, 0, "", ""); err == nil {
		t.Fatal("a write without a store must fail")
	}
}

// The check sends the secret only to the provider's token endpoint and
// reduces the answer to a verdict; nothing the provider says is passed on.
func TestCheckVerdicts(t *testing.T) {
	var gotSecret, gotClient string
	answer := `{"error":"invalid_grant","error_description":"Bad Request"}`
	status := http.StatusBadRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotSecret, gotClient = r.Form.Get("client_secret"), r.Form.Get("client_id")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	s, _, _, _ := newSvc(t, config.OAuthConfig{})
	s.check = &tester{client: srv.Client(), tokenURL: func(string) string { return srv.URL }}
	ctx := context.Background()

	if _, err := s.Check(ctx, cst.SuperAdmin(t), Google, "", "", "", ""); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("nothing to check: %v", err)
	}
	for _, c := range []struct {
		status int
		body   string
		want   Result
	}{
		{400, `{"error":"invalid_grant","error_description":"Bad Request"}`, ResultValid},
		{400, `{"error":"bad_verification_code"}`, ResultValid},
		{401, `{"error":"invalid_client","error_description":"Unauthorized"}`, ResultInvalid},
		{200, `{"error":"incorrect_client_credentials"}`, ResultInvalid},
		{400, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`, ResultInvalid},
		{400, `{"error":"invalid_request","error_description":"AADSTS700016: Application not found"}`, ResultInvalid},
		{400, `{"error":"invalid_grant","error_description":"AADSTS50011: The redirect URI does not match"}`, ResultRedirectMismatch},
		{400, `{"error":"redirect_uri_mismatch"}`, ResultRedirectMismatch},
		{503, `down`, ResultUnreachable},
		{200, `<html>`, ResultUnknown},
	} {
		status, answer = c.status, c.body
		got, err := s.Check(ctx, cst.SuperAdmin(t), Google, clientID, secret, "", "")
		if err != nil || got != c.want {
			t.Errorf("%s: got %q %v, want %q", c.body, got, err, c.want)
		}
		if gotSecret != secret || gotClient != clientID {
			t.Errorf("the candidate was not the one sent: %q %q", gotClient, gotSecret)
		}
	}

	// A stored secret is used when none is given, and a bad shape never leaves.
	enable(t, s, Google, 0)
	status, answer = 400, `{"error":"invalid_grant"}`
	gotSecret = ""
	if r, err := s.Check(ctx, cst.SuperAdmin(t), Google, "", "", "", ""); err != nil || r != ResultValid || gotSecret != secret {
		t.Fatalf("stored: %q %v %q", r, err, gotSecret)
	}
	gotSecret = ""
	if r, _ := s.Check(ctx, cst.SuperAdmin(t), Google, clientID, "bad secret with spaces", "", ""); r != ResultInvalid || gotSecret != "" {
		t.Fatalf("a malformed secret must not be sent: %q", r)
	}
	if _, err := s.Check(ctx, cst.SuperAdmin(t), "gitlab", clientID, secret, "", ""); err == nil {
		t.Fatal("unknown provider")
	}
}

func cfgOn(c config.OAuthProviderConfig) bool { return c.IsConfigured() }

// The redirect URI is per provider and is the one the web sends
// (${APP_URL}/auth/callback/<provider>); the check uses that same address.
func TestRedirectURIIsPerProviderAndUsedByTheCheck(t *testing.T) {
	var gotRedirect string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotRedirect = r.Form.Get("redirect_uri")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	s, _, _, _ := newSvc(t, config.OAuthConfig{})
	s.check = &tester{client: srv.Client(), tokenURL: func(string) string { return srv.URL }}
	got, _ := s.Get(context.Background())
	for _, p := range got.Providers {
		if want := "https://ctem.example.com/auth/callback/" + p.Provider; p.RedirectURI != want {
			t.Errorf("%s redirect = %q, want %q", p.Provider, p.RedirectURI, want)
		}
	}
	if _, err := s.Check(context.Background(), cst.SuperAdmin(t), Microsoft, clientID, secret, "", ""); err != nil {
		t.Fatal(err)
	}
	if gotRedirect != "https://ctem.example.com/auth/callback/microsoft" {
		t.Fatalf("the check used %q", gotRedirect)
	}
}

// Credentials reads the stored client even while the provider is not offered
// (the internal path for pinned organization connections); OAuthProvider
// keeps answering empty then.
func TestCredentialsIgnoreTheOfferSwitch(t *testing.T) {
	s, _, _, _ := newSvc(t, config.OAuthConfig{})
	ctx := context.Background()
	if _, ok := s.Credentials(ctx, Google); ok {
		t.Fatal("nothing stored")
	}
	a := cst.SuperAdmin(t)
	if _, err := s.Update(ctx, a, Google, Input{Enabled: false, ClientID: clientID, Secret: cst.Strp(secret), Reason: "store only"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	c, ok := s.Credentials(ctx, Google)
	if !ok || c.ClientID != clientID || c.ClientSecret != secret {
		t.Fatalf("credentials = %+v %v", c, ok)
	}
	if cfgOn(s.OAuthProvider(ctx, Google)) || s.Offered(ctx, Google) {
		t.Fatal("a provider that is not offered must not sign anyone in")
	}
	if _, ok := s.Credentials(ctx, "gitlab"); ok {
		t.Fatal("unknown provider")
	}
}

// The stored secret belongs to the stored client ID: changing the ID without
// entering a secret is refused, and the stored pair stays as it was.
func TestNewClientIDNeedsANewSecret(t *testing.T) {
	s, _, _, _ := newSvc(t, config.OAuthConfig{})
	ctx := context.Background()
	enable(t, s, Google, 0)
	a := cst.SuperAdmin(t)

	_, err := s.Update(ctx, a, Google, Input{Enabled: true, ClientID: "other-" + clientID, Reason: "swap the client"}, 1, "", "")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("new client ID with the stored secret: %v", err)
	}
	if cfg := s.OAuthProvider(ctx, Google); cfg.ClientID != clientID || cfg.ClientSecret != secret {
		t.Fatalf("the stored pair changed: %q", cfg.ClientID)
	}
	// The same ID keeps its secret; a new ID with a new secret is accepted.
	if _, err := s.Update(ctx, a, Google, Input{Enabled: true, ClientID: clientID, Reason: "turn it on again"}, 1, "", ""); err != nil {
		t.Fatalf("same client ID without a secret: %v", err)
	}
	if _, err := s.Update(ctx, a, Google, Input{Enabled: true, ClientID: "other-" + clientID, Secret: cst.Strp("another-" + secret), Reason: "swap the client"}, 2, "", ""); err != nil {
		t.Fatalf("new client ID with a new secret: %v", err)
	}
}

// A check never sends the stored secret with a client ID the caller chose, and
// every check is audited without the secret.
func TestCheckNeverPairsTheStoredSecretWithAnotherClientID(t *testing.T) {
	var gotSecret, gotClient string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		calls++
		gotSecret, gotClient = r.Form.Get("client_secret"), r.Form.Get("client_id")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	s, _, audit, _ := newSvc(t, config.OAuthConfig{})
	s.check = &tester{client: srv.Client(), tokenURL: func(string) string { return srv.URL }}
	enable(t, s, Google, 0)
	ctx, a := context.Background(), cst.SuperAdmin(t)
	before := len(audit.Entries)

	if _, err := s.Check(ctx, a, Google, "other-"+clientID, "", "203.0.113.5", "test"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another client ID with the stored secret: %v", err)
	}
	if calls != 0 || gotSecret != "" {
		t.Fatalf("the stored secret was sent for another client ID (%d calls)", calls)
	}
	// The stored pair, and a client ID with its own secret, are fine.
	if _, err := s.Check(ctx, a, Google, clientID, "", "203.0.113.5", "test"); err != nil || gotSecret != secret {
		t.Fatalf("stored pair: %v", err)
	}
	if _, err := s.Check(ctx, a, Google, "other-"+clientID, "candidate-"+secret, "203.0.113.5", "test"); err != nil || gotClient != "other-"+clientID {
		t.Fatalf("candidate pair: %v", err)
	}
	if got := audit.Entries[before:]; len(got) != 2 || got[0].Action != ActionChecked {
		t.Fatalf("audit rows = %d", len(got))
	}
	if strings.Contains(audit.JSON(t), secret) {
		t.Fatal("a secret leaked into the audit log")
	}
	if _, err := s.Check(ctx, nil, Google, clientID, secret, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
}
