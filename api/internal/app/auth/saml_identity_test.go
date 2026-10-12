package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// samlHarness is an SSOService able to finish a SAML login (session included)
// against in-memory users, memberships and identities.
func samlHarness(t *testing.T, verified map[string]bool) (*SSOService, *cbUserRepo, *cbMembers, *memIdentities) {
	t.Helper()
	users := &cbUserRepo{byEmail: map[string]*userdom.User{}}
	members := &cbMembers{created: map[string]*tenantdom.Membership{}}
	ids := newMemIdentities()
	cfg := config.AuthConfig{
		JWTSecret: "saml-test-secret-0123456789abcdef0123456789abcdef", JWTIssuer: "t",
		AccessTokenDuration: time.Minute, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
	}
	svc := NewSSOService(cbIPRepo{}, cbTenantRepo{}, users, cbSessionRepo{}, cbRefreshRepo{}, crypto.NewNoOpEncryptor(), cfg, logger.NewNop())
	svc.SetTenantMemberRepo(members)
	svc.SetIdentityRepo(ids)
	svc.SetDomainVerifier(&fakeDomainVerifier{verified: verified})
	return svc, users, members, ids
}

func samlTenant(t *testing.T, slug string) *tenantdom.Tenant {
	t.Helper()
	tn, err := tenantdom.NewTenant(slug, slug, shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

func samlKey(tn *tenantdom.Tenant, subject string) useridentity.Key {
	id := tn.ID()
	return useridentity.Key{Issuer: "https://idp.corp.com/saml", Subject: subject, ScopeTenantID: &id}
}

// A persistent NameID binds the new account, scoped to the organization.
func TestSAMLLogin_NewUserBindsScopedIdentity(t *testing.T) {
	svc, users, _, ids := samlHarness(t, map[string]bool{"corp.com": true})
	tn := samlTenant(t, "acme")

	res, err := svc.completeFederatedLogin(context.Background(), tn, "new@corp.com", "New", "member", true, federatedBinding{}, samlKey(tn, "nid-1"))
	if err != nil {
		t.Fatalf("JIT login: %v", err)
	}
	keys := ids.keysOf(res.User.ID())
	if len(keys) != 1 || keys[0].Subject != "nid-1" || keys[0].ScopeTenantID == nil || *keys[0].ScopeTenantID != tn.ID() {
		t.Fatalf("expected the identity scoped to the organization, got %+v", keys)
	}
	if users.byEmail["new@corp.com"] == nil {
		t.Fatal("account not created")
	}
}

// The returning person is found by NameID; the IdP's new email replaces the
// old one (domain verified here, address free) instead of a second account.
func TestSAMLLogin_ReturningIdentity_EmailChangeFollows(t *testing.T) {
	svc, users, members, ids := samlHarness(t, map[string]bool{"corp.com": true})
	tn := samlTenant(t, "acme")
	u, _ := userdom.New("old@corp.com", "Person")
	users.byEmail[u.Email()] = u
	m, _ := tenantdom.NewMembership(u.ID(), tn.ID(), tenantdom.RoleMember, nil)
	members.created[u.ID().String()] = m
	ident, _ := useridentity.New(u.ID(), samlKey(tn, "nid-1"))
	_ = ids.Create(context.Background(), ident)

	res, err := svc.completeFederatedLogin(context.Background(), tn, "renamed@corp.com", "Person", "member", false, federatedBinding{}, samlKey(tn, "nid-1"))
	if err != nil {
		t.Fatalf("returning login: %v", err)
	}
	if res.User.ID() != u.ID() || u.Email() != "renamed@corp.com" {
		t.Fatalf("expected the same account with the new email, got %s / %q", res.User.ID(), u.Email())
	}
	if len(users.byEmail) != 1 {
		t.Fatal("no second account may be created")
	}
}

// An offboarded member's identity still exists; it must not sign them in.
func TestSAMLLogin_ReturningIdentity_NotMemberRefused(t *testing.T) {
	svc, users, _, ids := samlHarness(t, map[string]bool{"corp.com": true})
	tn := samlTenant(t, "acme")
	u, _ := userdom.New("gone@corp.com", "Gone")
	users.byEmail[u.Email()] = u
	ident, _ := useridentity.New(u.ID(), samlKey(tn, "nid-1"))
	_ = ids.Create(context.Background(), ident)

	_, err := svc.completeFederatedLogin(context.Background(), tn, "gone@corp.com", "Gone", "member", true, federatedBinding{}, samlKey(tn, "nid-1"))
	if !errors.Is(err, ErrSSOFederatedNotMember) {
		t.Fatalf("expected ErrSSOFederatedNotMember, got %v", err)
	}
}

// Organization B configures the same IdP entity id and NameID as A. Its
// assertion is scoped to B, so it never resolves the account bound in A.
func TestSAMLLogin_SameEntityIDOtherOrganization_DoesNotResolve(t *testing.T) {
	svc, users, members, ids := samlHarness(t, map[string]bool{"corp.com": true})
	a := samlTenant(t, "acme")
	b := samlTenant(t, "evil")
	victim, _ := userdom.New("victim@corp.com", "Victim")
	users.byEmail[victim.Email()] = victim
	ma, _ := tenantdom.NewMembership(victim.ID(), a.ID(), tenantdom.RoleMember, nil)
	members.created[victim.ID().String()] = ma
	ident, _ := useridentity.New(victim.ID(), samlKey(a, "nid-victim"))
	_ = ids.Create(context.Background(), ident)

	// B's assertion, B's scope: not found; the email path then refuses (the
	// victim's membership record is in A, and the fake ignores the tenant,
	// so it is the NameID binding that must not leak).
	key := samlKey(b, "nid-victim")
	if got, _, err := svc.accounts().lookup(context.Background(), key, ""); err != nil || got != nil {
		t.Fatalf("organization B's key must not resolve A's account, got %v / %v", got, err)
	}
	// A key claiming A's scope but presented to B's login is refused outright.
	if _, err := svc.completeFederatedLogin(context.Background(), b, "victim@corp.com", "V", "member", true, federatedBinding{}, samlKey(a, "nid-victim")); !errors.Is(err, ErrSSOFederatedNotMember) {
		t.Fatalf("a key scoped to another organization must be refused, got %v", err)
	}
}

// Another NameID at the same IdP presenting a bound account's email is a
// different person: refused, nothing bound.
func TestSAMLLogin_OtherSubjectSameEmailRefused(t *testing.T) {
	svc, users, members, ids := samlHarness(t, map[string]bool{"corp.com": true})
	tn := samlTenant(t, "acme")
	u, _ := userdom.New("person@corp.com", "Person")
	users.byEmail[u.Email()] = u
	m, _ := tenantdom.NewMembership(u.ID(), tn.ID(), tenantdom.RoleMember, nil)
	members.created[u.ID().String()] = m
	ident, _ := useridentity.New(u.ID(), samlKey(tn, "nid-1"))
	_ = ids.Create(context.Background(), ident)

	_, err := svc.completeFederatedLogin(context.Background(), tn, "person@corp.com", "X", "member", false, federatedBinding{}, samlKey(tn, "nid-2"))
	if !errors.Is(err, ErrFederatedIdentityConflict) {
		t.Fatalf("expected ErrFederatedIdentityConflict, got %v", err)
	}
	if keys := ids.keysOf(u.ID()); len(keys) != 1 || keys[0].Subject != "nid-1" {
		t.Fatalf("binding must stay nid-1, got %+v", keys)
	}
}

// An existing member signing in with a persistent NameID for the first time
// gets it bound (verified email domain + membership, as before).
func TestSAMLLogin_ExistingMemberBoundOnNextLogin(t *testing.T) {
	svc, users, members, ids := samlHarness(t, map[string]bool{"corp.com": true})
	tn := samlTenant(t, "acme")
	u, _ := userdom.New("person@corp.com", "Person")
	users.byEmail[u.Email()] = u
	m, _ := tenantdom.NewMembership(u.ID(), tn.ID(), tenantdom.RoleMember, nil)
	members.created[u.ID().String()] = m

	if _, err := svc.completeFederatedLogin(context.Background(), tn, "person@corp.com", "Person", "member", false, federatedBinding{}, samlKey(tn, "nid-1")); err != nil {
		t.Fatalf("login: %v", err)
	}
	if keys := ids.keysOf(u.ID()); len(keys) != 1 || keys[0].Subject != "nid-1" {
		t.Fatalf("expected nid-1 bound, got %+v", keys)
	}
}

func TestSAMLIdentityKey_PersistentNameIDOnly(t *testing.T) {
	tid := shared.NewID()
	mk := func(format, value string) *saml.Assertion {
		return &saml.Assertion{
			Issuer:  saml.Issuer{Value: "https://idp.corp.com/saml"},
			Subject: &saml.Subject{NameID: &saml.NameID{Format: format, Value: value}},
		}
	}
	k := samlIdentityKey(mk(string(saml.PersistentNameIDFormat), "abc"), tid)
	if !k.Valid() || k.Subject != "abc" || k.ScopeTenantID == nil || *k.ScopeTenantID != tid {
		t.Fatalf("persistent NameID must key the identity, got %+v", k)
	}
	for _, f := range []string{string(saml.TransientNameIDFormat), string(saml.EmailAddressNameIDFormat), ""} {
		if samlIdentityKey(mk(f, "x@corp.com"), tid).Valid() {
			t.Fatalf("format %q must not key an identity", f)
		}
	}
	if samlIdentityKey(&saml.Assertion{}, tid).Valid() {
		t.Fatal("an assertion without a subject keys nothing")
	}
}
