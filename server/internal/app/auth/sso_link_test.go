package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/pkg/crypto"
	identityproviderdom "github.com/openctemio/openctem/server/pkg/domain/identityprovider"
	sessiondom "github.com/openctemio/openctem/server/pkg/domain/session"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/server/pkg/domain/user"
	"github.com/openctemio/openctem/server/pkg/domain/useridentity"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Linking an organization's OIDC sign-in to an existing password account
// (sso_link.go), end to end against a mock Okta org.

const (
	ssoLinkRedirect = "https://app.example.com/auth/sso/callback/okta"
	linkEmail       = "owner@corp.com"
	okta            = string(identityproviderdom.ProviderOkta)
)

// linkIPRepo serves acme's one provider.
type linkIPRepo struct {
	cbIPRepo
}

func (r linkIPRepo) ListActiveByTenant(_ context.Context, tenantID string) ([]*identityproviderdom.IdentityProvider, error) {
	if tenantID == r.ip.TenantID() {
		return []*identityproviderdom.IdentityProvider{r.ip}, nil
	}
	return nil, nil
}

func (r linkIPRepo) GetByTenantAndProvider(_ context.Context, tenantID string, _ identityproviderdom.Provider) (*identityproviderdom.IdentityProvider, error) {
	if tenantID == r.ip.TenantID() {
		return r.ip, nil
	}
	return nil, identityproviderdom.ErrNotFound
}

type linkTenants struct {
	tenantdom.Repository
	bySlug map[string]*tenantdom.Tenant
}

func (r *linkTenants) GetBySlug(_ context.Context, slug string) (*tenantdom.Tenant, error) {
	if t, ok := r.bySlug[slug]; ok {
		return t, nil
	}
	return nil, shared.ErrNotFound
}

func (r *linkTenants) ListTenantsByUser(context.Context, shared.ID) ([]*tenantdom.TenantWithRole, error) {
	out := []*tenantdom.TenantWithRole{}
	for _, t := range r.bySlug {
		out = append(out, &tenantdom.TenantWithRole{Tenant: t})
	}
	return out, nil
}

// linkMembers holds memberships per (user, tenant).
type linkMembers struct {
	m map[string]*tenantdom.Membership
}

func (l *linkMembers) GetMembership(_ context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error) {
	if ms, ok := l.m[userID.String()+"/"+tenantID.String()]; ok {
		return ms, nil
	}
	return nil, shared.ErrNotFound
}

func (l *linkMembers) CreateMembership(_ context.Context, ms *tenantdom.Membership) error {
	l.m[ms.UserID().String()+"/"+ms.TenantID().String()] = ms
	return nil
}

func (l *linkMembers) add(t *testing.T, u *userdom.User, tn *tenantdom.Tenant, role tenantdom.Role) *tenantdom.Membership {
	t.Helper()
	ms, err := tenantdom.NewMembership(u.ID(), tn.ID(), role, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.CreateMembership(context.Background(), ms)
	return ms
}

type linkSessions struct {
	cbSessionRepo
	byID map[shared.ID]*sessiondom.Session
}

func (r *linkSessions) GetByID(_ context.Context, id shared.ID) (*sessiondom.Session, error) {
	if s, ok := r.byID[id]; ok {
		return s, nil
	}
	return nil, sessiondom.ErrSessionNotFound
}

func (r *linkSessions) open(t *testing.T, u *userdom.User) string {
	t.Helper()
	s, err := sessiondom.New(u.ID(), "access-"+shared.NewID().String(), "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r.byID[s.ID()] = s
	return s.ID().String()
}

type ssoLinkFixture struct {
	t        *testing.T
	svc      *SSOService
	idp      *mockOktaIdP
	acme     *tenantdom.Tenant
	users    *cbUserRepo
	members  *linkMembers
	sessions *linkSessions
	idents   *memIdentities
	revoker  *fakeRevoker
	notifier *fakeNotifier
	proof    *fakeLinkProof
	owner    *userdom.User
	sid      string
}

// newSSOLinkFixture: a password account owner@corp.com, owner of acme (Okta
// SSO, corp.com DNS-verified) with one open session; another organization
// "other" it is not a member of.
func newSSOLinkFixture(t *testing.T) *ssoLinkFixture {
	t.Helper()
	f := &ssoLinkFixture{t: t}
	f.idp = mockOkta(t, linkEmail, idTokenValid)
	f.acme, _ = tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	other, _ := tenantdom.NewTenant("Other", "other", shared.NewID().String())
	enc := crypto.NewNoOpEncryptor()
	secret, _ := enc.EncryptString("client-secret")
	ip := identityproviderdom.New(shared.NewID().String(), f.acme.ID().String(), identityproviderdom.ProviderOkta, "Acme Okta", "client-id", secret)
	ip.SetTenantIdentifier(f.idp.srv.URL)
	ip.SetScopes([]string{"openid", "email", "profile"})

	f.owner, _ = userdom.NewLocalUser(linkEmail, "Owner", "$2a$10$hash")
	f.users = &cbUserRepo{byEmail: map[string]*userdom.User{linkEmail: f.owner}}
	f.members = &linkMembers{m: map[string]*tenantdom.Membership{}}
	f.members.add(t, f.owner, f.acme, tenantdom.RoleOwner)
	f.sessions = &linkSessions{byID: map[shared.ID]*sessiondom.Session{}}
	f.sid = f.sessions.open(t, f.owner)
	f.idents = newMemIdentities()
	f.revoker = &fakeRevoker{}
	f.notifier = &fakeNotifier{}
	f.proof = &fakeLinkProof{method: StepUpTOTP}

	cfg := config.AuthConfig{
		JWTSecret: "cb-test-secret-0123456789abcdef0123456789abcdef", JWTIssuer: "t",
		AccessTokenDuration: time.Minute, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
		AllowedRedirectURIs: []string{"https://app.example.com/auth/sso/callback/"},
	}
	tenants := &linkTenants{bySlug: map[string]*tenantdom.Tenant{"acme": f.acme, "other": other}}
	f.svc = NewSSOService(linkIPRepo{cbIPRepo{ip: ip}}, tenants, f.users, f.sessions, cbRefreshRepo{}, enc, cfg, logger.NewNop())
	f.svc.httpClient = f.idp.srv.Client()
	f.svc.oidcVerifier = newOIDCVerifier(f.idp.srv.Client(), logger.NewNop())
	f.svc.SetTenantMemberRepo(f.members)
	f.svc.SetIdentityRepo(f.idents)
	f.svc.SetDomainVerifier(&fakeDomainVerifier{verified: map[string]bool{"corp.com": true}})
	f.svc.SetLinkProofVerifier(f.proof)
	f.svc.SetSessionRevoker(f.revoker)
	f.svc.SetIdentityNotifier(f.notifier)
	// The identity provider authenticated the person just now.
	f.idp.authTime = jwtv5.NewNumericDate(time.Now())
	return f
}

func (f *ssoLinkFixture) start(org string, proof StepUpProof) (*SSOAuthorizeResult, error) {
	res, err := f.svc.StartSSOLink(context.Background(), SSOLinkStartInput{
		UserID: f.owner.ID().String(), SessionID: f.sid, OrgSlug: org, Provider: okta,
		RedirectURI: ssoLinkRedirect, Proof: proof,
	})
	if err == nil {
		u, _ := url.Parse(res.AuthorizationURL)
		f.idp.nonce = u.Query().Get("nonce")
	}
	return res, err
}

func (f *ssoLinkFixture) mustStart() *SSOAuthorizeResult {
	f.t.Helper()
	res, err := f.start("acme", goodProof)
	if err != nil {
		f.t.Fatalf("start: %v", err)
	}
	return res
}

func (f *ssoLinkFixture) complete(res *SSOAuthorizeResult, userID, sessionID, binding string) (*SSOLink, error) {
	return f.svc.CompleteSSOLink(context.Background(), SSOLinkCompleteInput{
		UserID: userID, SessionID: sessionID, Provider: okta, Code: "the-code",
		State: res.State, BrowserBinding: binding,
	})
}

func (f *ssoLinkFixture) login() (*SSOCallbackResult, error) {
	auth, err := f.svc.GenerateAuthorizeURL(context.Background(), SSOAuthorizeInput{OrgSlug: "acme", Provider: okta, RedirectURI: ssoLinkRedirect})
	if err != nil {
		f.t.Fatalf("authorize: %v", err)
	}
	u, _ := url.Parse(auth.AuthorizationURL)
	f.idp.nonce = u.Query().Get("nonce")
	return f.svc.HandleCallback(context.Background(), SSOCallbackInput{
		Provider: okta, Code: "the-code", State: auth.State, BrowserBinding: auth.BrowserBinding, RedirectURI: ssoLinkRedirect,
	})
}

func (f *ssoLinkFixture) linkedKeys() []useridentity.Key { return f.idents.keysOf(f.owner.ID()) }

// The bug: a password account could never sign in through its
// organization's SSO. After an explicit, proved link it can.
func TestSSOLink_PasswordAccountLinksThenSignsInThroughSSO(t *testing.T) {
	f := newSSOLinkFixture(t)
	if _, err := f.login(); !errors.Is(err, ErrAccountLinkRequiresVerification) {
		t.Fatalf("before the link the sign-in must ask for the link, got %v", err)
	}

	res := f.mustStart()
	u, _ := url.Parse(res.AuthorizationURL)
	if u.Query().Get("max_age") != "0" || u.Query().Get("prompt") != "login" {
		t.Fatalf("a link must make the identity provider authenticate again, got %q", res.AuthorizationURL)
	}
	link, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if link.OrgSlug != "acme" || link.IdentityID == "" {
		t.Fatalf("unexpected link result %+v", link)
	}
	keys := f.linkedKeys()
	if len(keys) != 1 || keys[0].Subject != "okta-sub-"+linkEmail {
		t.Fatalf("identity not bound: %+v", keys)
	}
	if len(f.revoker.except) != 1 || f.revoker.except[0] != f.sid {
		t.Fatalf("the account's other sessions must be revoked, keeping the linking one: %+v", f.revoker)
	}
	if len(f.notifier.linked) != 1 {
		t.Fatalf("the mailbox must be told: %+v", f.notifier.linked)
	}
	if len(f.proof.purposes) != 1 || f.proof.purposes[0] != LinkProofLinkStart {
		t.Fatalf("the start must be proved once, got %v", f.proof.purposes)
	}

	got, err := f.login()
	if err != nil || got.User.ID() != f.owner.ID() {
		t.Fatalf("after the link the sign-in must reach the same account, got %v", err)
	}
}

func TestSSOLink_StartNeedsAProof(t *testing.T) {
	for name, tc := range map[string]struct {
		proof StepUpProof
		want  error
	}{
		"missing": {StepUpProof{}, ErrLinkProofRequired},
		"wrong":   {StepUpProof{TOTP: "000000"}, ErrLinkProofFailed},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSSOLinkFixture(t)
			if _, err := f.start("acme", tc.proof); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSSOLink_OnlyAnActiveMemberOfTheOrganization(t *testing.T) {
	t.Run("another organization", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		if _, err := f.start("other", goodProof); !errors.Is(err, ErrSSONotAMember) {
			t.Fatalf("got %v", err)
		}
		if len(f.proof.purposes) != 0 {
			t.Fatal("a refused organization must not spend a proof")
		}
	})
	t.Run("unknown organization answers the same", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		if _, err := f.start("nope", goodProof); !errors.Is(err, ErrSSONotAMember) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("offboarded member", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		ms := f.members.add(t, f.owner, f.acme, tenantdom.RoleMember)
		if err := ms.Offboard(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.start("acme", goodProof); !errors.Is(err, ErrSSONotAMember) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("offboarded between start and completion", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		ms := f.members.add(t, f.owner, f.acme, tenantdom.RoleMember)
		res := f.mustStart()
		if err := ms.Offboard(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); !errors.Is(err, ErrSSONotAMember) {
			t.Fatalf("got %v", err)
		}
		if len(f.linkedKeys()) != 0 {
			t.Fatal("nothing may be bound")
		}
	})
}

func TestSSOLink_CompletionIsBoundToAccountSessionBrowserAndOnce(t *testing.T) {
	cases := map[string]func(f *ssoLinkFixture, res *SSOAuthorizeResult) (string, string, string){
		"another account": func(f *ssoLinkFixture, res *SSOAuthorizeResult) (string, string, string) {
			other, _ := userdom.NewLocalUser("mallory@corp.com", "M", "$2a$10$hash")
			f.users.byEmail[other.Email()] = other
			f.members.add(f.t, other, f.acme, tenantdom.RoleMember)
			return other.ID().String(), f.sessions.open(f.t, other), res.BrowserBinding
		},
		"another session of the same account": func(f *ssoLinkFixture, res *SSOAuthorizeResult) (string, string, string) {
			return f.owner.ID().String(), f.sessions.open(f.t, f.owner), res.BrowserBinding
		},
		"another browser": func(f *ssoLinkFixture, _ *SSOAuthorizeResult) (string, string, string) {
			return f.owner.ID().String(), f.sid, "not-the-binding"
		},
	}
	for name, who := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSSOLinkFixture(t)
			res := f.mustStart()
			uid, sid, binding := who(f, res)
			if _, err := f.complete(res, uid, sid, binding); !errors.Is(err, ErrSSOInvalidState) {
				t.Fatalf("got %v", err)
			}
			// The refused attempt spent the state: the owner cannot finish it either.
			if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); !errors.Is(err, ErrSSOInvalidState) {
				t.Fatalf("a spent state must stay refused, got %v", err)
			}
			if len(f.idents.rows) != 0 {
				t.Fatal("nothing may be bound")
			}
		})
	}
	t.Run("replay", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		res := f.mustStart()
		if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); err != nil {
			t.Fatal(err)
		}
		if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); !errors.Is(err, ErrSSOInvalidState) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the session that started it was revoked", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		res := f.mustStart()
		sid, _ := shared.IDFromString(f.sid)
		_ = f.sessions.byID[sid].Revoke()
		if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); !errors.Is(err, ErrSSOInvalidState) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestSSOLink_StateKindsDoNotCross(t *testing.T) {
	t.Run("a link state is not a sign-in", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		res := f.mustStart()
		_, err := f.svc.HandleCallback(context.Background(), SSOCallbackInput{
			Provider: okta, Code: "the-code", State: res.State, BrowserBinding: res.BrowserBinding, RedirectURI: ssoLinkRedirect,
		})
		if !errors.Is(err, ErrSSOInvalidState) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a sign-in state is not a link", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		auth, err := f.svc.GenerateAuthorizeURL(context.Background(), SSOAuthorizeInput{OrgSlug: "acme", Provider: okta, RedirectURI: ssoLinkRedirect, ForceReauth: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.complete(auth, f.owner.ID().String(), f.sid, auth.BrowserBinding); !errors.Is(err, ErrSSOInvalidState) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestSSOLink_IdentityProviderMustAuthenticateNow(t *testing.T) {
	f := newSSOLinkFixture(t)
	f.idp.authTime = jwtv5.NewNumericDate(time.Now().Add(-time.Hour))
	res := f.mustStart()
	if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); !errors.Is(err, ErrSSOInvalidIDToken) {
		t.Fatalf("an old authentication at the provider must be refused, got %v", err)
	}
}

func TestSSOLink_IdentityOfAnotherAccountIsRefused(t *testing.T) {
	f := newSSOLinkFixture(t)
	victim, _ := userdom.NewLocalUser("victim@corp.com", "V", "$2a$10$hash")
	f.users.byEmail[victim.Email()] = victim
	f.idents.bindSSO(victim, f.idp.srv.URL+"/oauth2/default", "okta-sub-"+linkEmail)
	res := f.mustStart()
	if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); !errors.Is(err, ErrIdentityLinkedElsewhere) {
		t.Fatalf("got %v", err)
	}
	if len(f.linkedKeys()) != 0 || len(f.revoker.revoked) != 0 {
		t.Fatal("nothing may change")
	}
}

func TestSSOLink_AccountWithAnotherSubjectAtTheIssuerIsRefused(t *testing.T) {
	f := newSSOLinkFixture(t)
	f.idents.bindSSO(f.owner, f.idp.srv.URL+"/oauth2/default", "okta-sub-someone-else")
	res := f.mustStart()
	if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); !errors.Is(err, ErrProviderAlreadyLinked) {
		t.Fatalf("got %v", err)
	}
}

func TestSSOLink_NotWiredRefusesEverything(t *testing.T) {
	f := newSSOLinkFixture(t)
	f.svc.link = ssoLinkDeps{}
	if _, err := f.start("acme", goodProof); !errors.Is(err, errSSOLinkNotWired) {
		t.Fatalf("got %v", err)
	}
	if err := f.svc.UnlinkSSOIdentity(context.Background(), SSOUnlinkInput{UserID: f.owner.ID().String(), SessionID: f.sid}); !errors.Is(err, errSSOLinkNotWired) {
		t.Fatalf("got %v", err)
	}
}

func TestSSOLink_ListShowsMemberOrganizationsAndTheLink(t *testing.T) {
	f := newSSOLinkFixture(t)
	links, err := f.svc.ListSSOLinks(context.Background(), f.owner.ID().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(links.Organizations) != 1 || links.Organizations[0].OrgSlug != "acme" || links.Organizations[0].Identity != nil {
		t.Fatalf("only acme (not linked) expected, got %+v", links.Organizations)
	}
	if links.Proof != string(StepUpTOTP) {
		t.Fatalf("proof %q", links.Proof)
	}
	res := f.mustStart()
	if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); err != nil {
		t.Fatal(err)
	}
	links, _ = f.svc.ListSSOLinks(context.Background(), f.owner.ID().String())
	got := links.Organizations[0].Identity
	if got == nil || !got.Unlinkable || len(links.Other) != 0 {
		t.Fatalf("acme must show the link, unlinkable for a password account: %+v", links)
	}
}

func TestSSOUnlink(t *testing.T) {
	linked := func(t *testing.T) (*ssoLinkFixture, string) {
		f := newSSOLinkFixture(t)
		res := f.mustStart()
		link, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding)
		if err != nil {
			t.Fatal(err)
		}
		f.revoker.revoked, f.revoker.except = nil, nil
		return f, link.IdentityID
	}
	unlink := func(f *ssoLinkFixture, userID, id string, proof StepUpProof) error {
		return f.svc.UnlinkSSOIdentity(context.Background(), SSOUnlinkInput{UserID: userID, SessionID: f.sid, IdentityID: id, Proof: proof})
	}
	t.Run("password account with a proof", func(t *testing.T) {
		f, id := linked(t)
		if err := unlink(f, f.owner.ID().String(), id, goodProof); err != nil {
			t.Fatal(err)
		}
		if len(f.linkedKeys()) != 0 || len(f.revoker.revoked) != 1 || len(f.notifier.unlinked) != 1 {
			t.Fatalf("unlink must delete, revoke and notify: %+v %+v", f.revoker, f.notifier)
		}
	})
	t.Run("wrong proof changes nothing", func(t *testing.T) {
		f, id := linked(t)
		if err := unlink(f, f.owner.ID().String(), id, StepUpProof{TOTP: "000000"}); !errors.Is(err, ErrLinkProofFailed) {
			t.Fatalf("got %v", err)
		}
		if len(f.linkedKeys()) != 1 || len(f.revoker.revoked) != 0 {
			t.Fatal("nothing may change")
		}
	})
	t.Run("another account's identity", func(t *testing.T) {
		f, id := linked(t)
		other, _ := userdom.NewLocalUser("mallory@corp.com", "M", "$2a$10$hash")
		f.users.byEmail[other.Email()] = other
		if err := unlink(f, other.ID().String(), id, goodProof); !errors.Is(err, ErrIdentityNotFound) {
			t.Fatalf("got %v", err)
		}
		if len(f.linkedKeys()) != 1 {
			t.Fatal("the owner's identity must stay")
		}
	})
	t.Run("social identity is not unlinked here", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		f.idents.bindTo(f.owner, googleIssuer, "g-1")
		rows, _ := f.idents.ListByUser(context.Background(), f.owner.ID())
		if err := unlink(f, f.owner.ID().String(), rows[0].ID.String(), goodProof); !errors.Is(err, ErrIdentityNotFound) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("account without a password stays managed by its organization", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		fed, _ := userdom.NewFederatedUser("fed@corp.com", "F", "", userdom.AuthProviderOIDC)
		f.users.byEmail[fed.Email()] = fed
		f.idents.bindSSO(fed, f.idp.srv.URL+"/oauth2/default", "okta-sub-fed")
		rows, _ := f.idents.ListByUser(context.Background(), fed.ID())
		if err := unlink(f, fed.ID().String(), rows[0].ID.String(), goodProof); !errors.Is(err, ErrIdentityNotUnlinkable) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestIdentityOfProvider(t *testing.T) {
	const dir = "11111111-2222-3333-4444-555555555555"
	sso := func(iss string) *useridentity.Identity {
		return &useridentity.Identity{Key: useridentity.Key{Issuer: iss, Subject: "s"}, Source: useridentity.SourceSSO}
	}
	social := &useridentity.Identity{Key: useridentity.Key{Issuer: "https://login.microsoftonline.com/" + dir + "/v2.0", Subject: "s"}, Source: useridentity.SourceSocial}
	cases := []struct {
		name  string
		p     identityproviderdom.Provider
		tid   string
		ident *useridentity.Identity
		want  bool
	}{
		{"entra same directory", identityproviderdom.ProviderEntraID, dir, sso("https://login.microsoftonline.com/" + dir + "/v2.0"), true},
		{"entra other directory", identityproviderdom.ProviderEntraID, dir, sso("https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0"), false},
		{"entra social identity", identityproviderdom.ProviderEntraID, dir, social, false},
		{"okta same org", identityproviderdom.ProviderOkta, "https://corp.okta.com", sso("https://corp.okta.com/oauth2/default"), true},
		{"okta other org", identityproviderdom.ProviderOkta, "https://corp.okta.com", sso("https://evil.okta.com/oauth2/default"), false},
		{"google", identityproviderdom.ProviderGoogleWorkspace, "", sso("https://accounts.google.com"), true},
	}
	for _, tc := range cases {
		if got := identityOfProvider(tc.p, tc.tid, tc.ident); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

// A linked password account keeps its address: the organization's identity
// provider must not move it (the address is how the account signs in and
// recovers its password, in every organization).
func TestSSOLink_ProviderNeverRewritesAPasswordAccountsAddress(t *testing.T) {
	f := newSSOLinkFixture(t)
	res := f.mustStart()
	if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); err != nil {
		t.Fatal(err)
	}
	ident, err := f.idents.GetByKey(context.Background(), f.linkedKeys()[0])
	if err != nil {
		t.Fatal(err)
	}
	f.svc.returningFederatedUser(context.Background(), f.acme, f.owner, ident, &SSOUserInfo{Email: "someone-else@corp.com"})
	if f.owner.Email() != linkEmail {
		t.Fatalf("the address moved to %q", f.owner.Email())
	}

	// An account without a password (the organization's sign-on created it)
	// still follows its provider on a DNS-verified domain.
	fed, _ := userdom.NewFederatedUser("fed@corp.com", "F", "", userdom.AuthProviderOIDC)
	f.users.byEmail[fed.Email()] = fed
	f.svc.returningFederatedUser(context.Background(), f.acme, fed, nil, &SSOUserInfo{Email: "fed-new@corp.com"})
	if fed.Email() != "fed-new@corp.com" {
		t.Fatalf("an SSO account must follow its provider, got %q", fed.Email())
	}
}

// failingLinkStore delegates to a real store but cannot read link records.
type failingLinkStore struct{ PKCEVerifierStore }

func (f failingLinkStore) GetDel(ctx context.Context, key string) (string, bool, error) {
	if strings.HasPrefix(key, "sso_link:") {
		return "", false, errors.New("state store unavailable")
	}
	return f.PKCEVerifierStore.GetDel(ctx, key)
}

// A state store that cannot say whether a state is a link must not make a
// link state pass as an ordinary sign-in (the callback fails closed), and the
// link completion refuses too.
func TestSSOLink_StoreErrorFailsClosed(t *testing.T) {
	t.Run("sign-in callback", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		res := f.mustStart()
		f.svc.stateStore = failingLinkStore{f.svc.stateStoreOrMemory()}
		_, err := f.svc.HandleCallback(context.Background(), SSOCallbackInput{
			Provider: okta, Code: "the-code", State: res.State, BrowserBinding: res.BrowserBinding, RedirectURI: ssoLinkRedirect,
		})
		if !errors.Is(err, ErrSSOInvalidState) {
			t.Fatalf("got %v", err)
		}
		if len(f.linkedKeys()) != 0 {
			t.Fatal("nothing may be linked")
		}
	})
	t.Run("link completion", func(t *testing.T) {
		f := newSSOLinkFixture(t)
		res := f.mustStart()
		f.svc.stateStore = failingLinkStore{f.svc.stateStoreOrMemory()}
		if _, err := f.complete(res, f.owner.ID().String(), f.sid, res.BrowserBinding); !errors.Is(err, ErrSSOInvalidState) {
			t.Fatalf("got %v", err)
		}
		if len(f.linkedKeys()) != 0 {
			t.Fatal("nothing may be linked")
		}
	})
}

// The redirect_uri check lives in the shared redemption, so the link path
// keeps it: a code is never redeemed for an address other than the one the
// authorize request used.
func TestSSOLink_RedemptionPinsTheAuthorizeRedirectURI(t *testing.T) {
	f := newSSOLinkFixture(t)
	st := ssoState{org: "acme", provider: okta, codeVerifier: "v", redirectURI: ssoLinkRedirect}
	if _, err := f.svc.redeemFederatedIdentity(context.Background(), st, okta, "the-code", "https://evil.example/cb"); !errors.Is(err, ErrSSOInvalidState) {
		t.Fatalf("a different redirect_uri must be refused, got %v", err)
	}
	st.redirectURI = ""
	if _, err := f.svc.redeemFederatedIdentity(context.Background(), st, okta, "the-code", ssoLinkRedirect); !errors.Is(err, ErrSSOInvalidState) {
		t.Fatalf("a state without a redirect_uri must be refused, got %v", err)
	}
}
