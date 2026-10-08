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
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// Google Workspace SSO must check the id_token "hd" claim. A consumer Google
// account registered with a company address (alice@acme.com) has a verified
// email but no "hd": it must never be admitted to the organization, whether as
// a JIT newcomer or as the existing member with that address.

// tlsRedirectTransport sends every request to the mock server, whatever host the
// production code addresses (accounts.google.com, oauth2.googleapis.com, ...).
type tlsRedirectTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (r tlsRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme = r.target.Scheme
	out.URL.Host = r.target.Host
	out.Host = r.target.Host
	return r.base.RoundTrip(out)
}

type mockGoogleIdP struct {
	srv   *httptest.Server
	nonce string
}

// mockGoogle serves Google's token, userinfo and JWKS endpoints for one
// account. hd is the id_token "hd" claim ("" = consumer account).
func mockGoogle(t *testing.T, email, hd string) *mockGoogleIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	idp := &mockGoogleIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code") != "the-code" || r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": signIDToken(t, key, oidc.Claims{
				Nonce:         idp.nonce,
				Email:         email,
				EmailVerified: true,
				HD:            hd,
				RegisteredClaims: jwtv5.RegisteredClaims{
					Issuer:    "https://accounts.google.com",
					Subject:   "google-sub-" + email,
					Audience:  jwtv5.ClaimStrings{"client-id"},
					ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  jwtv5.NewNumericDate(time.Now()),
				},
			}),
		})
	})
	mux.HandleFunc("/oauth2/v3/certs", func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": testKID, "use": "sig", "n": n, "e": e},
		}})
	})
	mux.HandleFunc("/oauth2/v3/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body := map[string]any{"email": email, "email_verified": true, "name": "Google Person"}
		if hd != "" {
			body["hd"] = hd
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	idp.srv = httptest.NewTLSServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

type googleCase struct {
	email          string
	hd             string
	allowedDomains []string
	verified       map[string]bool
	verifierErr    error
	existing       *userdom.User // an existing member with this email
}

func runGoogleCallback(t *testing.T, c googleCase) (*SSOCallbackResult, *cbUserRepo, *cbMembers, error) {
	t.Helper()
	idp := mockGoogle(t, c.email, c.hd)
	target, _ := url.Parse(idp.srv.URL)
	client := &http.Client{Transport: tlsRedirectTransport{target: target, base: idp.srv.Client().Transport}}

	tn, _ := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	enc := crypto.NewNoOpEncryptor()
	secret, _ := enc.EncryptString("client-secret")
	ip := identityproviderdom.New(shared.NewID().String(), tn.ID().String(), identityproviderdom.ProviderGoogleWorkspace, "Google", "client-id", secret)
	ip.SetScopes([]string{"openid", "email", "profile"})
	ip.SetAutoProvision(true)
	if len(c.allowedDomains) > 0 {
		ip.SetAllowedDomains(c.allowedDomains)
	}

	users := &cbUserRepo{byEmail: map[string]*userdom.User{}}
	members := &cbMembers{created: map[string]*tenantdom.Membership{}}
	if c.existing != nil {
		users.byEmail[c.existing.Email()] = c.existing
		ms, _ := tenantdom.NewMembership(c.existing.ID(), tn.ID(), tenantdom.RoleAdmin, nil)
		members.created[c.existing.ID().String()] = ms
	}
	cfg := config.AuthConfig{
		JWTSecret: "cb-test-secret-0123456789abcdef0123456789abcdef", JWTIssuer: "t",
		AccessTokenDuration: time.Minute, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
		AllowedRedirectURIs: []string{"https://app.example.com/auth/sso/callback"},
	}
	svc := NewSSOService(cbIPRepo{ip: ip}, cbTenantRepo{t: tn}, users, cbSessionRepo{}, cbRefreshRepo{}, enc, cfg, logger.NewNop())
	svc.httpClient = client
	svc.oidcVerifier = newOIDCVerifier(client, logger.NewNop())
	svc.SetTenantMemberRepo(members)
	svc.SetIdentityRepo(newMemIdentities())
	svc.SetDomainVerifier(&fakeDomainVerifier{verified: c.verified, err: c.verifierErr})

	auth, err := svc.GenerateAuthorizeURL(context.Background(), SSOAuthorizeInput{
		OrgSlug: "acme", Provider: string(identityproviderdom.ProviderGoogleWorkspace), RedirectURI: "https://app.example.com/auth/sso/callback",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	u, _ := url.Parse(auth.AuthorizationURL)
	idp.nonce = u.Query().Get("nonce")
	res, err := svc.HandleCallback(context.Background(), SSOCallbackInput{
		Provider: string(identityproviderdom.ProviderGoogleWorkspace), Code: "the-code", State: auth.State,
		RedirectURI: "https://app.example.com/auth/sso/callback",
	})
	return res, users, members, err
}

func TestGoogleWorkspaceSSO_WorkspaceAccountOnVerifiedDomainAdmitted(t *testing.T) {
	res, users, members, err := runGoogleCallback(t, googleCase{
		email: "new@acme.com", hd: "acme.com", verified: map[string]bool{"acme.com": true},
	})
	if err != nil {
		t.Fatalf("a Workspace account of the verified domain must be admitted, got %v", err)
	}
	if res == nil || res.AccessToken == "" {
		t.Fatal("expected a session")
	}
	if u := users.byEmail["new@acme.com"]; u == nil || members.created[u.ID().String()] == nil {
		t.Fatal("JIT must create the account and its membership")
	}
}

// The hd claim is compared case-insensitively with the configured domains.
func TestGoogleWorkspaceSSO_AllowedDomainsMatchIgnoresCase(t *testing.T) {
	_, _, _, err := runGoogleCallback(t, googleCase{
		email: "new@acme.com", hd: "ACME.com", allowedDomains: []string{"acme.com"},
		verified: map[string]bool{"acme.com": true},
	})
	if err != nil {
		t.Fatalf("expected admission, got %v", err)
	}
}

func TestGoogleWorkspaceSSO_Refusals(t *testing.T) {
	alice, err := userdom.NewFederatedUser("alice@acme.com", "Alice", "", userdom.AuthProviderGoogle)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	cases := map[string]googleCase{
		// The motivating case: a personal Google account opened with a
		// company address, on a domain the organization verified.
		"consumer account, verified domain, JIT": {
			email: "bob@acme.com", hd: "", verified: map[string]bool{"acme.com": true},
		},
		// The same personal account must not reach the existing member either.
		"consumer account with an existing member's address": {
			email: "alice@acme.com", hd: "", verified: map[string]bool{"acme.com": true}, existing: alice,
		},
		"another Workspace": {
			email: "bob@acme.com", hd: "evil.com", verified: map[string]bool{"acme.com": true},
		},
		"hd not on the provider's allowed domains": {
			email: "bob@acme.com", hd: "acme-old.com", allowedDomains: []string{"acme.com"},
			verified: map[string]bool{"acme.com": true, "acme-old.com": true},
		},
		"hd not verified for the organization": {
			email: "bob@acme.com", hd: "acme.com", verified: map[string]bool{},
		},
		"verified-domain lookup fails": {
			email: "bob@acme.com", hd: "acme.com", verifierErr: errors.New("db down"),
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			res, users, members, err := runGoogleCallback(t, c)
			if !errors.Is(err, ErrSSODomainNotAllowed) {
				t.Fatalf("expected ErrSSODomainNotAllowed, got res=%v err=%v", res, err)
			}
			if res != nil {
				t.Fatal("no session may be issued")
			}
			wantUsers, wantMembers := 0, 0
			if c.existing != nil {
				wantUsers, wantMembers = 1, 1
			}
			if len(users.byEmail) != wantUsers || len(members.created) != wantMembers {
				t.Fatalf("a refused login must write nothing (users=%d members=%d)", len(users.byEmail), len(members.created))
			}
		})
	}
}

// Without a verified-domain checker wired, the check refuses (fail-closed).
func TestGoogleWorkspaceDomainRefusal_NoVerifierFailsClosed(t *testing.T) {
	tn, _ := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	svc := &SSOService{logger: logger.NewNop()}
	rp := &resolvedProvider{provider: identityproviderdom.ProviderGoogleWorkspace}
	if reason := svc.googleWorkspaceDomainRefusal(context.Background(), tn, rp, "acme.com"); reason == "" {
		t.Fatal("expected a refusal without a domain verifier")
	}
}
