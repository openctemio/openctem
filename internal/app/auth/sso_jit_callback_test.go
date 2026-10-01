package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/crypto"
	identityproviderdom "github.com/openctemio/api/pkg/domain/identityprovider"
	sessiondom "github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
)

// End-to-end OIDC callback against a mock identity provider (httptest TLS
// server standing in for an Okta org): state + PKCE, code exchange, userinfo,
// then the RFC-025 admission rule decides whether a first-time user is admitted.

type cbIPRepo struct {
	identityproviderdom.Repository
	ip *identityproviderdom.IdentityProvider
}

func (r cbIPRepo) GetByTenantAndProvider(_ context.Context, _ string, _ identityproviderdom.Provider) (*identityproviderdom.IdentityProvider, error) {
	return r.ip, nil
}

type cbTenantRepo struct {
	tenantdom.Repository
	t *tenantdom.Tenant
}

func (r cbTenantRepo) GetBySlug(_ context.Context, slug string) (*tenantdom.Tenant, error) {
	if slug == r.t.Slug() {
		return r.t, nil
	}
	return nil, shared.ErrNotFound
}

type cbUserRepo struct {
	userdom.Repository
	byEmail map[string]*userdom.User
}

func (r *cbUserRepo) GetByEmail(_ context.Context, email string) (*userdom.User, error) {
	if u, ok := r.byEmail[email]; ok {
		return u, nil
	}
	return nil, shared.ErrNotFound
}
func (r *cbUserRepo) Create(_ context.Context, u *userdom.User) error {
	r.byEmail[u.Email()] = u
	return nil
}
func (r *cbUserRepo) Update(_ context.Context, _ *userdom.User) error { return nil }

type cbSessionRepo struct{ sessiondom.Repository }

func (cbSessionRepo) Create(context.Context, *sessiondom.Session) error { return nil }

type cbRefreshRepo struct {
	sessiondom.RefreshTokenRepository
}

func (cbRefreshRepo) Create(context.Context, *sessiondom.RefreshToken) error { return nil }

type cbMembers struct {
	created map[string]*tenantdom.Membership
}

func (m *cbMembers) GetMembership(_ context.Context, userID, _ shared.ID) (*tenantdom.Membership, error) {
	if ms, ok := m.created[userID.String()]; ok {
		return ms, nil
	}
	return nil, shared.ErrNotFound
}
func (m *cbMembers) CreateMembership(_ context.Context, ms *tenantdom.Membership) error {
	m.created[ms.UserID().String()] = ms
	return nil
}

// mockOkta serves the token and userinfo endpoints for one email.
func mockOkta(t *testing.T, email string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/default/v1/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code") != "the-code" || r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600})
	})
	mux.HandleFunc("/oauth2/default/v1/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"email": email, "email_verified": true, "name": "JIT Person"})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func runOktaCallback(t *testing.T, email string, verified map[string]bool, autoProvision bool) (*SSOCallbackResult, error, *cbUserRepo, *cbMembers) {
	t.Helper()
	idpSrv := mockOkta(t, email)
	tn, _ := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())

	enc := crypto.NewNoOpEncryptor()
	secret, _ := enc.EncryptString("client-secret")
	ip := identityproviderdom.New(shared.NewID().String(), tn.ID().String(), identityproviderdom.ProviderOkta, "Okta", "client-id", secret)
	ip.SetTenantIdentifier(idpSrv.URL) // mock org URL (validation of the URL is the create path's job)
	ip.SetScopes([]string{"openid", "email", "profile"})
	ip.SetAutoProvision(autoProvision)

	users := &cbUserRepo{byEmail: map[string]*userdom.User{}}
	members := &cbMembers{created: map[string]*tenantdom.Membership{}}
	cfg := config.AuthConfig{
		JWTSecret: "cb-test-secret-0123456789abcdef0123456789abcdef", JWTIssuer: "t",
		AccessTokenDuration: time.Minute, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
		AllowedRedirectURIs: []string{"https://app.example.com/auth/sso/callback"},
		AllowRegistration:   false, // SSO admission must not depend on self-registration
	}
	svc := NewSSOService(cbIPRepo{ip: ip}, cbTenantRepo{t: tn}, users, cbSessionRepo{}, cbRefreshRepo{}, enc, cfg, logger.NewNop())
	svc.httpClient = idpSrv.Client() // trust the mock's TLS cert (SafeHTTPClient refuses loopback)
	svc.oidcVerifier = newOIDCVerifier(idpSrv.Client(), logger.NewNop())
	svc.SetTenantMemberRepo(members)
	svc.SetDomainVerifier(&fakeDomainVerifier{verified: verified})

	auth, err := svc.GenerateAuthorizeURL(context.Background(), SSOAuthorizeInput{
		OrgSlug: "acme", Provider: string(identityproviderdom.ProviderOkta), RedirectURI: "https://app.example.com/auth/sso/callback",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	u, _ := url.Parse(auth.AuthorizationURL)
	if u.Query().Get("code_challenge") == "" {
		t.Fatal("PKCE challenge expected")
	}
	res, err := svc.HandleCallback(context.Background(), SSOCallbackInput{
		Provider: string(identityproviderdom.ProviderOkta), Code: "the-code", State: auth.State,
		RedirectURI: "https://app.example.com/auth/sso/callback",
	})
	return res, err, users, members
}

func TestOIDCCallback_JIT_VerifiedDomainAdmittedAsViewer(t *testing.T) {
	res, err, users, members := runOktaCallback(t, "new@corp.com", map[string]bool{"corp.com": true}, true)
	if err != nil {
		t.Fatalf("verified-domain JIT must be admitted (registration off), got %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a session")
	}
	u := users.byEmail["new@corp.com"]
	if u == nil {
		t.Fatal("JIT must create the account")
	}
	if m := members.created[u.ID().String()]; m == nil || m.Role() != tenantdom.RoleViewer {
		t.Fatalf("JIT member must get the least-privileged default role, got %+v", m)
	}
}

func TestOIDCCallback_JIT_UnverifiedDomainRefusedNothingCreated(t *testing.T) {
	_, err, users, members := runOktaCallback(t, "new@other.com", map[string]bool{"corp.com": true}, true)
	if !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("unverified domain must be refused, got %v", err)
	}
	if len(users.byEmail) != 0 || len(members.created) != 0 {
		t.Fatal("a refused login must leave no account or membership")
	}
}

func TestOIDCCallback_JIT_AutoProvisionOffRefused(t *testing.T) {
	_, err, users, _ := runOktaCallback(t, "new@corp.com", map[string]bool{"corp.com": true}, false)
	if !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("auto-provision off must refuse a new person, got %v", err)
	}
	if len(users.byEmail) != 0 {
		t.Fatal("no account may be created")
	}
}
