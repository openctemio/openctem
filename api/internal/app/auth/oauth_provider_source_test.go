package auth

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// liveProviders is a ProviderSource a test changes while the service runs.
type liveProviders struct {
	mu  sync.Mutex
	cfg map[string]config.OAuthProviderConfig
}

func (l *liveProviders) OAuthProvider(_ context.Context, p string) config.OAuthProviderConfig {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cfg[p]
}

func (l *liveProviders) set(p string, c config.OAuthProviderConfig) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cfg[p] = c
}

// The console's provider setting is read on every authorize: turning a
// provider on, changing its client and turning it off take effect without
// rebuilding the service, and the start-up configuration no longer decides.
func TestOAuthProviderSource_AppliesWithoutRestart(t *testing.T) {
	startup := config.OAuthConfig{Enabled: true, StateSecret: "state-secret-for-tests-0123456789",
		Google: config.OAuthProviderConfig{Enabled: true, ClientID: "startup-id", ClientSecret: "startup-secret"}}
	s := NewOAuthService(nil, nil, nil, startup, config.AuthConfig{JWTSecret: "jwt-secret-for-tests-0123456789abcdef"}, logger.NewNop())
	src := &liveProviders{cfg: map[string]config.OAuthProviderConfig{}}
	s.SetProviderSource(src)
	ctx := context.Background()
	in := AuthorizationURLInput{Provider: OAuthProviderGitHub, RedirectURI: "https://app.example/auth/callback", FinalRedirect: "/"}

	if _, err := s.GetAuthorizationURL(ctx, in); !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("off in the console: err = %v", err)
	}
	if _, err := s.GetAuthorizationURL(ctx, AuthorizationURLInput{Provider: OAuthProviderGoogle, RedirectURI: "https://app.example/auth/callback"}); !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("the start-up Google config must not apply once the console owns it: err = %v", err)
	}

	src.set("github", config.OAuthProviderConfig{Enabled: true, ClientID: "console-id-1", ClientSecret: "console-secret-1", Scopes: []string{"read:user", "user:email"}})
	res, err := s.GetAuthorizationURL(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if got := clientIDOf(t, res.AuthorizationURL); got != "console-id-1" {
		t.Fatalf("client id = %q", got)
	}
	if s.GetAvailableProviders()[1].Enabled != true {
		t.Fatal("GetAvailableProviders must follow the source")
	}

	src.set("github", config.OAuthProviderConfig{Enabled: true, ClientID: "console-id-2", ClientSecret: "console-secret-2"})
	res, err = s.GetAuthorizationURL(ctx, in)
	if err != nil || clientIDOf(t, res.AuthorizationURL) != "console-id-2" {
		t.Fatalf("a changed client must apply at once: %v", err)
	}

	src.set("github", config.OAuthProviderConfig{})
	if _, err := s.GetAuthorizationURL(ctx, in); !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("turned off: err = %v", err)
	}
}

func clientIDOf(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("client_id")
}
