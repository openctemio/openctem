package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/crypto"
	identityproviderdom "github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
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

// cbSessionRepo records the sessions the callback creates (when created is
// non-nil) so a test can inspect how they were stamped.
type cbSessionRepo struct {
	sessiondom.Repository
	created *[]*sessiondom.Session
}

func (r cbSessionRepo) Create(_ context.Context, s *sessiondom.Session) error {
	if r.created != nil {
		*r.created = append(*r.created, s)
	}
	return nil
}

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

// idTokenMode selects what the mock Okta token endpoint returns as id_token.
type idTokenMode int

const (
	idTokenValid       idTokenMode = iota // signed, right issuer/audience/nonce
	idTokenNone                           // no id_token (provider without "openid")
	idTokenWrongIssuer                    // signed by the org's keys but another issuer
)

// mockOktaIdP is a mock Okta org: token, userinfo and JWKS endpoints. nonce
// is the authorize request's nonce, set by the test before the callback.
type mockOktaIdP struct {
	srv   *httptest.Server
	nonce string
}

// mockOkta serves the token, userinfo and JWKS endpoints for one email.
func mockOkta(t *testing.T, email string, mode idTokenMode) *mockOktaIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	idp := &mockOktaIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/default/v1/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code") != "the-code" || r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		resp := map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600}
		if mode != idTokenNone {
			iss := idp.srv.URL + "/oauth2/default"
			if mode == idTokenWrongIssuer {
				iss = "https://evil.example.com/oauth2/default"
			}
			resp["id_token"] = signIDToken(t, key, oidcClaims{
				Nonce: idp.nonce,
				Email: email,
				RegisteredClaims: jwtv5.RegisteredClaims{
					Issuer:    iss,
					Subject:   "okta-sub-" + email,
					Audience:  jwtv5.ClaimStrings{"client-id"},
					ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  jwtv5.NewNumericDate(time.Now()),
				},
			})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/oauth2/default/v1/keys", func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": testKID, "use": "sig", "n": n, "e": e},
		}})
	})
	mux.HandleFunc("/oauth2/default/v1/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"email": email, "email_verified": true, "name": "JIT Person"})
	})
	idp.srv = httptest.NewTLSServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func runOktaCallback(t *testing.T, email string, verified map[string]bool, autoProvision bool) (*SSOCallbackResult, *cbUserRepo, *cbMembers, error) {
	t.Helper()
	return runOktaCallbackRecording(t, email, verified, autoProvision, nil)
}

// runOktaCallbackRecording is runOktaCallback that also appends every session
// the callback creates to sessions (when non-nil).
func runOktaCallbackRecording(t *testing.T, email string, verified map[string]bool, autoProvision bool, sessions *[]*sessiondom.Session) (*SSOCallbackResult, *cbUserRepo, *cbMembers, error) {
	t.Helper()
	return runOktaCallbackWith(t, email, verified, autoProvision, sessions, idTokenValid, []string{"openid", "email", "profile"})
}

// runOktaCallbackWith runs the full authorize + callback flow against a mock
// Okta org that returns the given id_token mode, with the provider saved with
// the given scopes.
func runOktaCallbackWith(t *testing.T, email string, verified map[string]bool, autoProvision bool, sessions *[]*sessiondom.Session, mode idTokenMode, scopes []string) (*SSOCallbackResult, *cbUserRepo, *cbMembers, error) {
	t.Helper()
	idp := mockOkta(t, email, mode)
	idpSrv := idp.srv
	tn, _ := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())

	enc := crypto.NewNoOpEncryptor()
	secret, _ := enc.EncryptString("client-secret")
	ip := identityproviderdom.New(shared.NewID().String(), tn.ID().String(), identityproviderdom.ProviderOkta, "Okta", "client-id", secret)
	ip.SetTenantIdentifier(idpSrv.URL) // mock org URL (validation of the URL is the create path's job)
	ip.SetScopes(scopes)
	ip.SetAutoProvision(autoProvision)

	users := &cbUserRepo{byEmail: map[string]*userdom.User{}}
	members := &cbMembers{created: map[string]*tenantdom.Membership{}}
	cfg := config.AuthConfig{
		JWTSecret: "cb-test-secret-0123456789abcdef0123456789abcdef", JWTIssuer: "t",
		AccessTokenDuration: time.Minute, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
		AllowedRedirectURIs: []string{"https://app.example.com/auth/sso/callback"},
		AllowRegistration:   false, // SSO admission must not depend on self-registration
	}
	svc := NewSSOService(cbIPRepo{ip: ip}, cbTenantRepo{t: tn}, users, cbSessionRepo{created: sessions}, cbRefreshRepo{}, enc, cfg, logger.NewNop())
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
	if !strings.Contains(" "+u.Query().Get("scope")+" ", " openid ") {
		t.Fatalf("authorize request must ask for the openid scope, got %q", u.Query().Get("scope"))
	}
	idp.nonce = u.Query().Get("nonce")
	res, err := svc.HandleCallback(context.Background(), SSOCallbackInput{
		Provider: string(identityproviderdom.ProviderOkta), Code: "the-code", State: auth.State,
		RedirectURI: "https://app.example.com/auth/sso/callback",
	})
	return res, users, members, err
}

func TestOIDCCallback_JIT_VerifiedDomainAdmittedAsViewer(t *testing.T) {
	res, users, members, err := runOktaCallback(t, "new@corp.com", map[string]bool{"corp.com": true}, true)
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
	_, users, members, err := runOktaCallback(t, "new@other.com", map[string]bool{"corp.com": true}, true)
	if !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("unverified domain must be refused, got %v", err)
	}
	if len(users.byEmail) != 0 || len(members.created) != 0 {
		t.Fatal("a refused login must leave no account or membership")
	}
}

func TestOIDCCallback_JIT_AutoProvisionOffRefused(t *testing.T) {
	_, users, _, err := runOktaCallback(t, "new@corp.com", map[string]bool{"corp.com": true}, false)
	if !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("auto-provision off must refuse a new person, got %v", err)
	}
	if len(users.byEmail) != 0 {
		t.Fatal("no account may be created")
	}
}

// A provider that returns no id_token is refused, and no account is created:
// the federated identity that binds the account comes only from it.
func TestOIDCCallback_NoIDTokenRefused(t *testing.T) {
	_, users, members, err := runOktaCallbackWith(t, "new@corp.com", map[string]bool{"corp.com": true}, true, nil, idTokenNone, []string{"openid", "email", "profile"})
	if !errors.Is(err, ErrSSOInvalidIDToken) {
		t.Fatalf("expected ErrSSOInvalidIDToken, got %v", err)
	}
	if len(users.byEmail) != 0 || len(members.created) != 0 {
		t.Fatalf("nothing may be created without a verified id_token (users=%d members=%d)", len(users.byEmail), len(members.created))
	}
}

// An id_token from another issuer is refused even when its signature checks
// out against the org's keys.
func TestOIDCCallback_WrongIssuerRefused(t *testing.T) {
	_, users, _, err := runOktaCallbackWith(t, "new@corp.com", map[string]bool{"corp.com": true}, true, nil, idTokenWrongIssuer, []string{"openid", "email", "profile"})
	if !errors.Is(err, ErrSSOInvalidIDToken) {
		t.Fatalf("expected ErrSSOInvalidIDToken, got %v", err)
	}
	if len(users.byEmail) != 0 {
		t.Fatal("no user may be created from a wrong-issuer id_token")
	}
}

// A provider saved before "openid" was required (scopes without it) still
// signs in: the authorize request adds the scope (asserted in the runner) and
// the issued id_token is verified and bound.
func TestOIDCCallback_LegacyScopesWithoutOpenIDStillSignIn(t *testing.T) {
	res, users, _, err := runOktaCallbackWith(t, "new@corp.com", map[string]bool{"corp.com": true}, true, nil, idTokenValid, []string{"email", "profile"})
	if err != nil {
		t.Fatalf("expected sign-in to succeed, got %v", err)
	}
	if res == nil || res.AccessToken == "" {
		t.Fatal("expected a session")
	}
	u := users.byEmail["new@corp.com"]
	if u == nil {
		t.Fatal("expected the user to be provisioned")
	}
}
