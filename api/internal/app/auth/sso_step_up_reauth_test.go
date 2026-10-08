package auth

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/crypto"
	identityproviderdom "github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Step-up for SSO accounts (docs/architecture/step-up-reauth.md): the
// re-sign-in asks the provider to authenticate the user again, the callback
// checks auth_time, and only a recent provider authentication opens the
// session's step-up window.

// stampSessionRepo records the step-up stamps the SSO flow makes.
type stampSessionRepo struct {
	cbSessionRepo
	stamps []time.Time
}

func (r *stampSessionRepo) MarkStepUp(_ context.Context, _, _ shared.ID, at time.Time) (bool, error) {
	r.stamps = append(r.stamps, at)
	return true, nil
}

func (r *stampSessionRepo) RecentAuthAt(context.Context, shared.ID, shared.ID) (time.Time, error) {
	return time.Time{}, nil
}

// runOktaReauth runs authorize + callback for an existing member against a
// mock Okta org whose id_token carries authTime (nil: no auth_time claim).
func runOktaReauth(t *testing.T, reauth bool, authTime *time.Time) (*url.URL, *stampSessionRepo, error) {
	t.Helper()
	const email = "member@corp.com"
	idp := mockOkta(t, email, idTokenValid)
	if authTime != nil {
		idp.authTime = jwtv5.NewNumericDate(*authTime)
	}
	tn, _ := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	enc := crypto.NewNoOpEncryptor()
	secret, _ := enc.EncryptString("client-secret")
	ip := identityproviderdom.New(shared.NewID().String(), tn.ID().String(), identityproviderdom.ProviderOkta, "Okta", "client-id", secret)
	ip.SetTenantIdentifier(idp.srv.URL)
	ip.SetScopes([]string{"openid", "email", "profile"})

	users := &cbUserRepo{byEmail: map[string]*userdom.User{}}
	members := &cbMembers{created: map[string]*tenantdom.Membership{}}
	sessions := &stampSessionRepo{}
	cfg := config.AuthConfig{
		JWTSecret: "cb-test-secret-0123456789abcdef0123456789abcdef", JWTIssuer: "t",
		AccessTokenDuration: time.Minute, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
		AllowedRedirectURIs: []string{"https://app.example.com/auth/sso/callback"},
	}
	svc := NewSSOService(cbIPRepo{ip: ip}, cbTenantRepo{t: tn}, users, sessions, cbRefreshRepo{}, enc, cfg, logger.NewNop())
	svc.httpClient = idp.srv.Client()
	svc.oidcVerifier = newOIDCVerifier(idp.srv.Client(), logger.NewNop())
	svc.SetTenantMemberRepo(members)
	svc.SetIdentityRepo(newMemIdentities())
	svc.SetDomainVerifier(&fakeDomainVerifier{verified: map[string]bool{"corp.com": true}})
	ip.SetAutoProvision(true)

	auth, err := svc.GenerateAuthorizeURL(context.Background(), SSOAuthorizeInput{
		OrgSlug: "acme", Provider: string(identityproviderdom.ProviderOkta),
		RedirectURI: "https://app.example.com/auth/sso/callback", ForceReauth: reauth,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	u, _ := url.Parse(auth.AuthorizationURL)
	idp.nonce = u.Query().Get("nonce")
	_, err = svc.HandleCallback(context.Background(), SSOCallbackInput{
		Provider: string(identityproviderdom.ProviderOkta), Code: "the-code", State: auth.State,
		RedirectURI: "https://app.example.com/auth/sso/callback",
	})
	return u, sessions, err
}

func TestSSOReauth_AuthorizeAsksForAFreshAuthentication(t *testing.T) {
	now := time.Now()
	u, _, err := runOktaReauth(t, true, &now)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("prompt") != "login" || u.Query().Get("max_age") != "0" {
		t.Fatalf("re-authentication must send prompt=login and max_age=0: %s", u.RawQuery)
	}
	plain, _, err := runOktaReauth(t, false, &now)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Query().Has("prompt") || plain.Query().Has("max_age") {
		t.Fatalf("an ordinary sign-in must not force re-authentication: %s", plain.RawQuery)
	}
}

func TestSSOReauth_CallbackChecksAuthTime(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	if _, _, err := runOktaReauth(t, true, &old); !errors.Is(err, ErrSSOInvalidIDToken) {
		t.Fatalf("a re-authentication answered with an hour-old auth_time must be refused, got %v", err)
	}
	if _, _, err := runOktaReauth(t, true, nil); !errors.Is(err, ErrSSOInvalidIDToken) {
		t.Fatalf("a re-authentication answered without auth_time must be refused, got %v", err)
	}
	fresh := time.Now().Add(-30 * time.Second)
	_, sessions, err := runOktaReauth(t, true, &fresh)
	if err != nil {
		t.Fatalf("a fresh re-authentication was refused: %v", err)
	}
	if len(sessions.stamps) != 1 || !sessions.stamps[0].Equal(fresh.Truncate(time.Second)) {
		t.Fatalf("the session must record the provider's authentication time, got %v", sessions.stamps)
	}
}

// An ordinary sign-in is admitted whatever auth_time says, but only a recent
// provider authentication opens the step-up window.
func TestSSOSignIn_OnlyARecentProviderAuthenticationOpensTheWindow(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	_, sessions, err := runOktaReauth(t, false, &old)
	if err != nil {
		t.Fatalf("an ordinary sign-in with an old auth_time must be admitted: %v", err)
	}
	if len(sessions.stamps) != 0 {
		t.Fatalf("a silent provider sign-in opened the step-up window: %v", sessions.stamps)
	}
	_, sessions, err = runOktaReauth(t, false, nil)
	if err != nil || len(sessions.stamps) != 0 {
		t.Fatalf("no auth_time: err=%v stamps=%v", err, sessions.stamps)
	}
	recent := time.Now().Add(-2 * time.Minute)
	if _, sessions, err = runOktaReauth(t, false, &recent); err != nil || len(sessions.stamps) != 1 {
		t.Fatalf("a recent provider authentication: err=%v stamps=%v", err, sessions.stamps)
	}
	future := time.Now().Add(time.Hour)
	if _, sessions, _ = runOktaReauth(t, false, &future); len(sessions.stamps) != 0 {
		t.Fatalf("an auth_time in the future opened the window: %v", sessions.stamps)
	}
}

// The re-authentication flag rides in the signed state: a forged or edited
// state is refused before anything else.
func TestSSOReauth_FlagIsSigned(t *testing.T) {
	svc := &SSOService{authConfig: config.AuthConfig{JWTSecret: "s-0123456789abcdef0123456789abcdef"}, encryptor: crypto.NewNoOpEncryptor()}
	state, _, _, err := svc.generateState("acme", "okta", true)
	if err != nil {
		t.Fatal(err)
	}
	st, err := svc.validateState(state)
	if err != nil || !st.reauth {
		t.Fatalf("reauth flag lost: %+v %v", st, err)
	}
	plain, _, _, _ := svc.generateState("acme", "okta", false)
	if st, _ := svc.validateState(plain); st.reauth {
		t.Fatal("an ordinary state reads as a re-authentication")
	}
}
