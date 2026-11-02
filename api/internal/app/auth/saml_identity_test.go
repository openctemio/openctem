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

	res, err := svc.completeFederatedLogin(context.Background(), tn, "new@corp.com", "New", "member", true, federatedBinding{}, samlKey(tn, "nid-1"), "")
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

	res, err := svc.completeFederatedLogin(context.Background(), tn, "renamed@corp.com", "Person", "member", false, federatedBinding{}, samlKey(tn, "nid-1"), "")
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

	_, err := svc.completeFederatedLogin(context.Background(), tn, "gone@corp.com", "Gone", "member", true, federatedBinding{}, samlKey(tn, "nid-1"), "")
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
	if _, err := svc.completeFederatedLogin(context.Background(), b, "victim@corp.com", "V", "member", true, federatedBinding{}, samlKey(a, "nid-victim"), ""); !errors.Is(err, ErrSSOFederatedNotMember) {
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

	_, err := svc.completeFederatedLogin(context.Background(), tn, "person@corp.com", "X", "member", false, federatedBinding{}, samlKey(tn, "nid-2"), "")
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

	if _, err := svc.completeFederatedLogin(context.Background(), tn, "person@corp.com", "Person", "member", false, federatedBinding{}, samlKey(tn, "nid-1"), ""); err != nil {
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

// entraAssertion is an Entra-shaped assertion: emailAddress NameID (Entra's
// default, the user's UPN), plus the objectidentifier and tenantid claims
// Entra always sends.
func entraAssertion(nameIDFormat, nameID, oid, tid string) *saml.Assertion {
	a := &saml.Assertion{
		Issuer:  saml.Issuer{Value: "https://sts.windows.net/" + tid + "/"},
		Subject: &saml.Subject{NameID: &saml.NameID{Format: nameIDFormat, Value: nameID}},
	}
	var attrs []saml.Attribute
	if oid != "" {
		attrs = append(attrs, saml.Attribute{Name: samlEntraObjectIDAttr, Values: []saml.AttributeValue{{Value: oid}}})
	}
	if tid != "" {
		attrs = append(attrs, saml.Attribute{Name: samlEntraTenantIDAttr, Values: []saml.AttributeValue{{Value: tid}}})
	}
	a.AttributeStatements = []saml.AttributeStatement{{Attributes: attrs}}
	return a
}

const samlTestTID = "aaaaaaaa-1111-2222-3333-444444444444"

func TestSAMLIdentity_EntraObjectIDKeysEvenWithEmailNameID(t *testing.T) {
	tn := shared.NewID()
	k, legacy := samlIdentity(entraAssertion(string(saml.EmailAddressNameIDFormat), "alice@corp.com", "oid-1", samlTestTID), tn)
	if !k.Valid() || k.Subject != samlTestTID+"/oid-1" || k.ScopeTenantID == nil || *k.ScopeTenantID != tn || legacy != "" {
		t.Fatalf("the Entra object id must key the identity, got %+v legacy %q", k, legacy)
	}
	// A persistent NameID bound before becomes the legacy subject.
	k, legacy = samlIdentity(entraAssertion(string(saml.PersistentNameIDFormat), "nid-old", "oid-1", samlTestTID), tn)
	if k.Subject != samlTestTID+"/oid-1" || legacy != "nid-old" {
		t.Fatalf("want oid key with the persistent NameID as legacy, got %+v legacy %q", k, legacy)
	}
}

func TestSAMLIdentity_AmbiguousOrPartialEntraClaimsKeyNothing(t *testing.T) {
	tn := shared.NewID()
	email := string(saml.EmailAddressNameIDFormat)
	if k, _ := samlIdentity(entraAssertion(email, "a@corp.com", "oid-1", ""), tn); k.Valid() {
		t.Fatal("objectidentifier without tenantid must not key an identity")
	}
	if k, _ := samlIdentity(entraAssertion(email, "a@corp.com", "", samlTestTID), tn); k.Valid() {
		t.Fatal("tenantid without objectidentifier must not key an identity")
	}
	a := entraAssertion(email, "a@corp.com", "oid-1", samlTestTID)
	a.AttributeStatements[0].Attributes = append(a.AttributeStatements[0].Attributes,
		saml.Attribute{Name: samlEntraObjectIDAttr, Values: []saml.AttributeValue{{Value: "oid-2"}}})
	if k, _ := samlIdentity(a, tn); k.Valid() {
		t.Fatal("two objectidentifier claims are ambiguous and must key nothing")
	}
	b := entraAssertion(email, "a@corp.com", "oid-1/../x", samlTestTID)
	if k, _ := samlIdentity(b, tn); k.Valid() {
		t.Fatal("an object id with a separator must key nothing")
	}
}

// A reused address: the old holder's account is bound to their object id; a
// new directory user who now holds the address is a different person.
func TestSAMLLogin_EntraReusedAddressDoesNotInheritAccount(t *testing.T) {
	svc, users, members, ids := samlHarness(t, map[string]bool{"corp.com": true})
	tn := samlTenant(t, "acme")
	old, _ := userdom.New("john@corp.com", "John (left)")
	users.byEmail[old.Email()] = old
	m, _ := tenantdom.NewMembership(old.ID(), tn.ID(), tenantdom.RoleMember, nil)
	members.created[old.ID().String()] = m
	oldKey, _ := samlIdentity(entraAssertion(string(saml.EmailAddressNameIDFormat), "john@corp.com", "oid-old", samlTestTID), tn.ID())
	ident, _ := useridentity.New(old.ID(), oldKey)
	_ = ids.Create(context.Background(), ident)

	newKey, legacy := samlIdentity(entraAssertion(string(saml.EmailAddressNameIDFormat), "john@corp.com", "oid-new", samlTestTID), tn.ID())
	_, err := svc.completeFederatedLogin(context.Background(), tn, "john@corp.com", "John (new)", "member", true, federatedBinding{}, newKey, legacy)
	if !errors.Is(err, ErrFederatedIdentityConflict) {
		t.Fatalf("a new directory user holding a reused address must be refused, got %v", err)
	}
}

// An identity bound under a persistent NameID before is re-keyed to the
// object id on the next login: same account, no conflict.
func TestSAMLLogin_PersistentNameIDBindingRekeyedToObjectID(t *testing.T) {
	svc, users, members, ids := samlHarness(t, map[string]bool{"corp.com": true})
	tn := samlTenant(t, "acme")
	u, _ := userdom.New("alice@corp.com", "Alice")
	users.byEmail[u.Email()] = u
	m, _ := tenantdom.NewMembership(u.ID(), tn.ID(), tenantdom.RoleMember, nil)
	members.created[u.ID().String()] = m
	scope := tn.ID()
	issuer := "https://sts.windows.net/" + samlTestTID + "/"
	ident, _ := useridentity.New(u.ID(), useridentity.Key{Issuer: issuer, Subject: "nid-old", ScopeTenantID: &scope})
	_ = ids.Create(context.Background(), ident)

	key, legacy := samlIdentity(entraAssertion(string(saml.PersistentNameIDFormat), "nid-old", "oid-1", samlTestTID), tn.ID())
	res, err := svc.completeFederatedLogin(context.Background(), tn, "alice@corp.com", "Alice", "member", false, federatedBinding{}, key, legacy)
	if err != nil {
		t.Fatalf("returning login: %v", err)
	}
	if res.User.ID() != u.ID() {
		t.Fatal("the re-keyed identity must resolve the same account")
	}
	if keys := ids.keysOf(u.ID()); len(keys) != 1 || keys[0].Subject != samlTestTID+"/oid-1" {
		t.Fatalf("binding must be re-keyed to the object id, got %+v", keys)
	}
}
