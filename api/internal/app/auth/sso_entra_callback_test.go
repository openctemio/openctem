package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// End-to-end organization SSO against a mock Microsoft Entra ID: the real
// authorize URL, state, PKCE and nonce, the code exchange at the directory's
// token endpoint and the id_token verified against the directory's JWKS, with
// Entra-shaped issuers (https://login.microsoftonline.com/{tid}/v2.0). The
// mock answers at login.microsoftonline.com through the HTTP transport, so the
// production endpoint construction is what the test exercises.

const (
	entraOrgDir   = "aaaaaaaa-1111-2222-3333-444444444444" // the organization's directory
	entraOtherDir = "bbbbbbbb-5555-6666-7777-888888888888" // somebody else's directory
	entraClientID = "entra-client-id"
	entraRedirect = "https://app.example.com/auth/sso/callback/entra_id"
)

// entraToken describes the id_token the mock directory issues.
type entraToken struct {
	tid     string // tid claim (and the directory in iss unless issTID is set)
	issTID  string // directory in iss when it must differ from tid
	email   string
	edov    bool
	oid     string
	noEmail bool
	nonce   string // overrides the authorize nonce when set
	aud     string // overrides the client id when set
}

// mockEntra serves /{tid}/oauth2/v2.0/token and /{tid}/discovery/v2.0/keys of
// login.microsoftonline.com.
type mockEntra struct {
	t        *testing.T
	key      *rsa.PrivateKey
	nonce    string // the authorize request's nonce
	tok      entraToken
	redeemed map[string]bool // codes already redeemed (one use)
	gotPKCE  string
	gotRedir string
	tokenDir string // the directory whose token endpoint was called
}

func newMockEntra(t *testing.T, tok entraToken) *mockEntra {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return &mockEntra{t: t, key: key, tok: tok, redeemed: map[string]bool{}}
}

func (m *mockEntra) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "login.microsoftonline.com" {
		return nil, errors.New("unexpected host " + req.URL.Host)
	}
	rec := httptest.NewRecorder()
	parts := strings.SplitN(strings.TrimPrefix(req.URL.Path, "/"), "/", 2)
	switch {
	case len(parts) == 2 && parts[1] == "oauth2/v2.0/token":
		m.serveToken(rec, req, parts[0])
	case len(parts) == 2 && parts[1] == "discovery/v2.0/keys":
		n := base64.RawURLEncoding.EncodeToString(m.key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.key.E)).Bytes())
		_ = json.NewEncoder(rec).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": testKID, "use": "sig", "n": n, "e": e},
		}})
	default:
		http.NotFound(rec, req)
	}
	return rec.Result(), nil
}

func (m *mockEntra) serveToken(w http.ResponseWriter, req *http.Request, dir string) {
	body, _ := io.ReadAll(req.Body)
	form, _ := url.ParseQuery(string(body))
	code := form.Get("code")
	if code != "the-code" || m.redeemed[code] || form.Get("client_id") != entraClientID {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	m.redeemed[code] = true
	m.gotPKCE, m.gotRedir, m.tokenDir = form.Get("code_verifier"), form.Get("redirect_uri"), dir

	tk := m.tok
	issTID := tk.tid
	if tk.issTID != "" {
		issTID = tk.issTID
	}
	nonce := m.nonce
	if tk.nonce != "" {
		nonce = tk.nonce
	}
	aud := entraClientID
	if tk.aud != "" {
		aud = tk.aud
	}
	c := oidc.Claims{
		Nonce: nonce, TID: tk.tid, OID: tk.oid, Name: "Entra Person",
		XMSEdov: oidc.FlexBool(tk.edov),
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    "https://login.microsoftonline.com/" + issTID + "/v2.0",
			Subject:   "pairwise-sub-" + tk.oid,
			Audience:  jwtv5.ClaimStrings{aud},
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(time.Now()),
		},
	}
	if !tk.noEmail {
		c.Email = tk.email
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "graph-at", "token_type": "Bearer", "expires_in": 3600,
		"id_token": signIDToken(m.t, m.key, c),
	})
}

// entraFixture is one organization ("acme") with an Entra ID provider.
type entraFixture struct {
	svc     *SSOService
	idp     *mockEntra
	users   *cbUserRepo
	members *cbMembers
}

func entraTestAuthConfig() config.AuthConfig {
	return config.AuthConfig{
		JWTSecret: "entra-test-secret-0123456789abcdef0123456789abcdef", JWTIssuer: "t",
		AccessTokenDuration: time.Minute, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
		AllowedRedirectURIs: []string{"https://app.example.com/auth/sso/callback/"},
	}
}

func wireEntraFixture(svc *SSOService, idp *mockEntra, users *cbUserRepo, verified map[string]bool) *entraFixture {
	client := &http.Client{Transport: idp, Timeout: 5 * time.Second}
	members := &cbMembers{created: map[string]*tenantdom.Membership{}}
	svc.httpClient = client
	svc.oidcVerifier = newOIDCVerifier(client, logger.NewNop())
	svc.SetTenantMemberRepo(members)
	svc.SetIdentityRepo(newMemIdentities())
	svc.SetDomainVerifier(&fakeDomainVerifier{verified: verified})
	return &entraFixture{svc: svc, idp: idp, users: users, members: members}
}

func newEntraFixture(t *testing.T, directory string, tok entraToken, verified map[string]bool) *entraFixture {
	t.Helper()
	tn, _ := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	enc := crypto.NewNoOpEncryptor()
	secret, _ := enc.EncryptString("client-secret")
	ip := identityproviderdom.New(shared.NewID().String(), tn.ID().String(), identityproviderdom.ProviderEntraID, "Contoso", entraClientID, secret)
	ip.SetTenantIdentifier(directory)
	ip.SetAutoProvision(true)
	users := &cbUserRepo{byEmail: map[string]*userdom.User{}}
	svc := NewSSOService(&fakeIPRepo{
		byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{identityproviderdom.ProviderEntraID: ip},
		active:     []*identityproviderdom.IdentityProvider{ip},
	}, cbTenantRepo{t: tn}, users, cbSessionRepo{}, cbRefreshRepo{}, enc, entraTestAuthConfig(), logger.NewNop())
	return wireEntraFixture(svc, newMockEntra(t, tok), users, verified)
}

// authorize runs the authorize step and records the nonce at the mock.
func (f *entraFixture) authorize(t *testing.T) *SSOAuthorizeResult {
	t.Helper()
	res, err := f.svc.GenerateAuthorizeURL(context.Background(), SSOAuthorizeInput{
		OrgSlug: "acme", Provider: string(identityproviderdom.ProviderEntraID), RedirectURI: entraRedirect,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	u, _ := url.Parse(res.AuthorizationURL)
	if u.Query().Get("code_challenge") == "" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("authorize must send a PKCE S256 challenge")
	}
	f.idp.nonce = u.Query().Get("nonce")
	if f.idp.nonce == "" {
		t.Fatal("authorize must send a nonce")
	}
	return res
}

func (f *entraFixture) callback(res *SSOAuthorizeResult, redirectURI string) (*SSOCallbackResult, error) {
	return f.svc.HandleCallback(context.Background(), SSOCallbackInput{
		Provider: string(identityproviderdom.ProviderEntraID), Code: "the-code",
		State: res.State, BrowserBinding: res.BrowserBinding, RedirectURI: redirectURI,
	})
}

func (f *entraFixture) signIn(t *testing.T) (*SSOCallbackResult, error) {
	t.Helper()
	return f.callback(f.authorize(t), entraRedirect)
}

func goodEntraToken() entraToken {
	return entraToken{tid: entraOrgDir, email: "alice@contoso.com", edov: true, oid: "oid-alice"}
}

var contosoVerified = map[string]bool{"contoso.com": true}

func TestEntraSSO_PinnedDirectory_SignsInAndUsesDirectoryEndpoints(t *testing.T) {
	f := newEntraFixture(t, entraOrgDir, goodEntraToken(), contosoVerified)
	res, err := f.signIn(t)
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if res.TenantSlug != "acme" || res.AccessToken == "" {
		t.Fatalf("unexpected result %+v", res)
	}
	if f.idp.tokenDir != entraOrgDir {
		t.Fatalf("code must be redeemed at the organization's directory, got %q", f.idp.tokenDir)
	}
	if f.idp.gotPKCE == "" || f.idp.gotRedir != entraRedirect {
		t.Fatalf("exchange must carry the PKCE verifier and the same redirect_uri, got %q %q", f.idp.gotPKCE, f.idp.gotRedir)
	}
}

func TestEntraSSO_TokenFromAnotherDirectoryRefused(t *testing.T) {
	// A consistent token (iss and tid agree) of another directory: the
	// organization's provider is pinned to its own directory.
	tok := goodEntraToken()
	tok.tid = entraOtherDir
	f := newEntraFixture(t, entraOrgDir, tok, contosoVerified)
	if _, err := f.signIn(t); !errors.Is(err, ErrSSOInvalidIDToken) {
		t.Fatalf("want ErrSSOInvalidIDToken for a foreign directory, got %v", err)
	}
	if len(f.users.byEmail) != 0 || len(f.members.created) != 0 {
		t.Fatal("a refused sign-in must create nothing")
	}
}

func TestEntraSSO_IssuerAndTIDDisagreeRefused(t *testing.T) {
	// tid claims the organization's directory, iss names another one.
	tok := goodEntraToken()
	tok.issTID = entraOtherDir
	f := newEntraFixture(t, entraOrgDir, tok, contosoVerified)
	if _, err := f.signIn(t); !errors.Is(err, ErrSSOInvalidIDToken) {
		t.Fatalf("want ErrSSOInvalidIDToken when iss and tid disagree, got %v", err)
	}
}

func TestEntraSSO_WrongAudienceRefused(t *testing.T) {
	tok := goodEntraToken()
	tok.aud = "another-app"
	f := newEntraFixture(t, entraOrgDir, tok, contosoVerified)
	if _, err := f.signIn(t); !errors.Is(err, ErrSSOInvalidIDToken) {
		t.Fatalf("want ErrSSOInvalidIDToken for another audience, got %v", err)
	}
}

func TestEntraSSO_EmailWithoutDomainOwnerVerificationRefused(t *testing.T) {
	// nOAuth: an email claim alone (no xms_edov) is never an identity.
	tok := goodEntraToken()
	tok.edov = false
	f := newEntraFixture(t, entraOrgDir, tok, contosoVerified)
	if _, err := f.signIn(t); !errors.Is(err, ErrEmailUnverifiedAtIDP) {
		t.Fatalf("want ErrEmailUnverifiedAtIDP, got %v", err)
	}
	if len(f.users.byEmail) != 0 {
		t.Fatal("no account may be created from an unverified email")
	}
}

func TestEntraSSO_NoEmailClaimRefused(t *testing.T) {
	tok := goodEntraToken()
	tok.noEmail = true
	f := newEntraFixture(t, entraOrgDir, tok, contosoVerified)
	if _, err := f.signIn(t); !errors.Is(err, ErrSSOInvalidIDToken) {
		t.Fatalf("want a refusal without an email claim, got %v", err)
	}
}

func TestEntraSSO_SameEmailOtherObjectIDRefused(t *testing.T) {
	// The account is keyed on the directory's object id: another Entra user
	// presenting the same verified email is a different person.
	f := newEntraFixture(t, entraOrgDir, goodEntraToken(), contosoVerified)
	if _, err := f.signIn(t); err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	f.idp.tok.oid = "oid-mallory"
	f.idp.redeemed = map[string]bool{}
	if _, err := f.signIn(t); !errors.Is(err, ErrSSODifferentMethod) {
		t.Fatalf("want ErrSSODifferentMethod for another oid with the same email, got %v", err)
	}
}

func TestEntraSSO_EmailChangeFollowsObjectID(t *testing.T) {
	f := newEntraFixture(t, entraOrgDir, goodEntraToken(), contosoVerified)
	first, err := f.signIn(t)
	if err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	f.idp.tok.email = "alice.new@contoso.com"
	f.idp.redeemed = map[string]bool{}
	second, err := f.signIn(t)
	if err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if first.User.ID() != second.User.ID() {
		t.Fatal("the same oid must resolve to the same account after an email change")
	}
}

func TestEntraSSO_StateReplayRefused(t *testing.T) {
	f := newEntraFixture(t, entraOrgDir, goodEntraToken(), contosoVerified)
	res := f.authorize(t)
	if _, err := f.callback(res, entraRedirect); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	f.idp.redeemed = map[string]bool{} // even if the provider accepted the code again
	if _, err := f.callback(res, entraRedirect); !errors.Is(err, ErrSSOInvalidState) {
		t.Fatalf("a replayed state must be refused, got %v", err)
	}
}

func TestEntraSSO_StateFromAnotherBrowserRefused(t *testing.T) {
	f := newEntraFixture(t, entraOrgDir, goodEntraToken(), contosoVerified)
	res := f.authorize(t)
	other := f.authorize(t)
	res.BrowserBinding = other.BrowserBinding
	if _, err := f.callback(res, entraRedirect); !errors.Is(err, ErrSSOInvalidState) {
		t.Fatalf("a state presented by another browser must be refused, got %v", err)
	}
}

func TestEntraSSO_NonceMismatchRefused(t *testing.T) {
	tok := goodEntraToken()
	tok.nonce = "nonce-of-another-flow"
	f := newEntraFixture(t, entraOrgDir, tok, contosoVerified)
	if _, err := f.signIn(t); !errors.Is(err, ErrSSOInvalidIDToken) {
		t.Fatalf("an id_token with another flow's nonce must be refused, got %v", err)
	}
}

func TestEntraSSO_RedirectURIMustMatchAuthorize(t *testing.T) {
	f := newEntraFixture(t, entraOrgDir, goodEntraToken(), contosoVerified)
	res := f.authorize(t)
	if _, err := f.callback(res, "https://app.example.com/auth/sso/callback/okta"); !errors.Is(err, ErrSSOInvalidState) {
		t.Fatalf("a callback with another redirect_uri must be refused, got %v", err)
	}
	if f.idp.tokenDir != "" {
		t.Fatal("the code must not be redeemed")
	}
}

func TestEntraSSO_UnverifiedDomainNotProvisioned(t *testing.T) {
	f := newEntraFixture(t, entraOrgDir, goodEntraToken(), map[string]bool{})
	if _, err := f.signIn(t); !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("want ErrSSONotAMember for an unverified domain, got %v", err)
	}
}

func TestEntraSSO_ProviderWithoutDirectoryRefused(t *testing.T) {
	// A stored provider on a multi-tenant authority, or with a domain name,
	// would accept any Microsoft directory (or never match tid): refused
	// before anything is sent to Microsoft, and not offered on the login page.
	for _, dir := range []string{"", "common", "organizations", "consumers", "contoso.com"} {
		t.Run("dir="+dir, func(t *testing.T) {
			tok := goodEntraToken()
			tok.tid = entraOtherDir
			f := newEntraFixture(t, dir, tok, contosoVerified)
			_, err := f.svc.GenerateAuthorizeURL(context.Background(), SSOAuthorizeInput{
				OrgSlug: "acme", Provider: string(identityproviderdom.ProviderEntraID), RedirectURI: entraRedirect,
			})
			if !errors.Is(err, ErrSSOProviderMisconfigured) {
				t.Fatalf("want ErrSSOProviderMisconfigured, got %v", err)
			}
			list, err := f.svc.GetProvidersForTenant(context.Background(), "acme")
			if err != nil || len(list) != 0 {
				t.Fatalf("a misconfigured provider must not be offered, got %+v %v", list, err)
			}
		})
	}
}

func TestValidateTenantIdentifier_EntraRequiresDirectoryGUID(t *testing.T) {
	for _, bad := range []string{"", "common", "organizations", "consumers", "contoso.com",
		"contoso.onmicrosoft.com", entraOrgDir + "/../common", "aaaaaaaa-1111-2222-3333-44444444444"} {
		if err := validateTenantIdentifier(identityproviderdom.ProviderEntraID, bad); !errors.Is(err, identityproviderdom.ErrInvalidConfig) {
			t.Errorf("%q: want ErrInvalidConfig, got %v", bad, err)
		}
	}
	if err := validateTenantIdentifier(identityproviderdom.ProviderEntraID, entraOrgDir); err != nil {
		t.Fatalf("a directory GUID must pass: %v", err)
	}
}

func TestEntraSSO_EnvCommonAuthorityNeverProvisions(t *testing.T) {
	// The shared env app on the multi-tenant authority accepts a token of any
	// directory (iss and tid consistent), but never provisions a newcomer.
	tn, _ := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	users := &cbUserRepo{byEmail: map[string]*userdom.User{}}
	cfg := entraTestAuthConfig()
	cfg.EntraSSO = config.EntraSSOConfig{Enabled: true, ClientID: entraClientID, ClientSecret: "s", TenantID: "common",
		AllowedDomains: []string{"contoso.com"}, AutoProvision: true, AllowedTenants: []string{"acme"}}
	svc := NewSSOService(&fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{}},
		cbTenantRepo{t: tn}, users, cbSessionRepo{}, cbRefreshRepo{}, crypto.NewNoOpEncryptor(), cfg, logger.NewNop())
	tok := entraToken{tid: entraOtherDir, email: "bob@contoso.com", edov: true, oid: "oid-bob"}
	f := wireEntraFixture(svc, newMockEntra(t, tok), users, contosoVerified)

	if _, err := f.signIn(t); !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("the multi-tenant env authority must not provision newcomers, got %v", err)
	}
	if f.idp.tokenDir != "common" {
		t.Fatalf("the env authority's token endpoint is common, got %q", f.idp.tokenDir)
	}
}
