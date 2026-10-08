package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	identityproviderdom "github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// regEnabled is the auth config used by findOrCreateUser tests that exercise the
// create path (the self_service sign-up mode).
func regEnabled() config.AuthConfig {
	return config.AuthConfig{TenantCreationMode: config.TenantCreationSelfService}
}

// ssoTn builds a throwaway tenant for the findOrCreateUser call signature. Same-
// provider / create paths never read it; the Case 2 proof-before-link gate does.
func ssoTn(t *testing.T) *tenantdom.Tenant {
	t.Helper()
	tn, err := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatalf("new tenant: %v", err)
	}
	return tn
}

// ssoFakeUserRepo records Create/Update for the SSO findOrCreateUser tests.
// (fakeUserRepo from oauth_takeover_test.go is reused where it suffices, but we
// need to observe Update here, so define a local one.)
type ssoFakeUserRepo struct {
	userdom.Repository
	byEmail *userdom.User
	created *userdom.User
	updated *userdom.User
	// others are further accounts, found by their exact email.
	others []*userdom.User
}

func (r *ssoFakeUserRepo) GetByEmail(_ context.Context, email string) (*userdom.User, error) {
	for _, u := range r.others {
		if u.Email() == email {
			return u, nil
		}
	}
	return r.byEmail, nil
}
func (r *ssoFakeUserRepo) GetByID(_ context.Context, id shared.ID) (*userdom.User, error) {
	for _, u := range append([]*userdom.User{r.byEmail, r.created}, r.others...) {
		if u != nil && u.ID() == id {
			return u, nil
		}
	}
	return nil, userdom.NotFoundError(id)
}
func (r *ssoFakeUserRepo) Update(_ context.Context, u *userdom.User) error { r.updated = u; return nil }
func (r *ssoFakeUserRepo) Create(_ context.Context, u *userdom.User) error { r.created = u; return nil }

func newSSOSvc(existing *userdom.User) (*SSOService, *ssoFakeUserRepo) {
	repo := &ssoFakeUserRepo{byEmail: existing}
	return &SSOService{userRepo: repo, identities: newMemIdentities(), logger: logger.NewNop(),
		authConfig: regEnabled(), domainVerifier: corpVerified()}, repo
}

// idsOf is the in-memory identity store of a service built by the helpers.
func idsOf(s *SSOService) *memIdentities { return s.identities.(*memIdentities) }

const (
	corpOkta   = "https://corp.okta.com"
	evilOkta   = "https://attacker.okta.com"
	victimMail = "victim@corp.com"
)

// THE HEADLINE FIX: a federated account bound to one OIDC issuer (corp Okta)
// must NOT be adoptable by a DIFFERENT OIDC issuer (attacker's own Okta) that
// asserts the same verified email — even though both collapse to
// AuthProviderOIDC and the provider-match check passes.
func TestSSOFindOrCreate_BlocksCrossIdPSameEnum(t *testing.T) {
	victim, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim") // AuthProviderOIDC
	s, repo := newSSOSvc(victim)
	idsOf(s).bindTo(victim, corpOkta, "corp-sub")

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: evilOkta, Subject: "evil-sub"},
		jitRP(identityproviderdom.ProviderOkta))

	if err == nil {
		t.Fatal("expected cross-IdP takeover (corp account ← attacker Okta) to be BLOCKED")
	}
	if got != nil {
		t.Fatalf("blocked login must not return a user, got %v", got)
	}
	if repo.updated != nil || repo.created != nil {
		t.Fatal("blocked login must not persist any change")
	}
	// The binding must be unchanged (still corp).
	if keys := idsOf(s).keysOf(victim.ID()); len(keys) != 1 || keys[0].Issuer != corpOkta {
		t.Fatalf("victim binding must stay %q only, got %+v", corpOkta, keys)
	}
}

// Re-login from the SAME issuer is fine.
func TestSSOFindOrCreate_SameIssuerOK(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	s, _ := newSSOSvc(u)
	idsOf(s).bindTo(u, corpOkta, "corp-sub")

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: corpOkta, Subject: "corp-sub"},
		jitRP(identityproviderdom.ProviderOkta))
	if err != nil {
		t.Fatalf("same-issuer re-login should succeed, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the existing user back")
	}
}

// A pre-tracking federated account (no recorded issuer) is bound on first use
// (trust-on-first-use) and adopted; subsequent logins are then enforced.
func TestSSOFindOrCreate_LegacyTrustOnFirstUseBinds(t *testing.T) {
	legacy, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim") // no federated identity
	s, repo := newSSOSvc(legacy)

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: corpOkta, Subject: "corp-sub"},
		jitRP(identityproviderdom.ProviderOkta))
	if err != nil {
		t.Fatalf("legacy first-use login should succeed, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the existing user back")
	}
	if keys := idsOf(s).keysOf(got.ID()); len(keys) != 1 || keys[0].Issuer != corpOkta || keys[0].Subject != "corp-sub" {
		t.Fatalf("expected (corp, corp-sub) bound on first use, got %+v", keys)
	}
	if repo.updated == nil {
		t.Fatal("the login must be persisted via Update")
	}
}

// When the provider returns no id_token (issuer empty) we cannot bind/verify;
// the login must still work (no regression) — falling back to the existing
// provider-match guard.
func TestSSOFindOrCreate_NoIssuerNoRegression(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	s, _ := newSSOSvc(u)
	idsOf(s).bindTo(u, corpOkta, "corp-sub")

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: "", Subject: ""},
		jitRP(identityproviderdom.ProviderOkta))
	if err != nil {
		t.Fatalf("no-id_token login should not regress, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the existing user back")
	}
}

// raceUserRepo simulates the create-race / transient-lookup path: the first
// GetByEmail misses, Create then fails (concurrent create / unique violation),
// and the retry GetByEmail returns an existing account.
type raceUserRepo struct {
	userdom.Repository
	calls   int
	onRetry *userdom.User
	updated *userdom.User
}

func (r *raceUserRepo) GetByEmail(_ context.Context, _ string) (*userdom.User, error) {
	r.calls++
	if r.calls == 1 {
		return nil, nil // initial lookup misses → proceed to create
	}
	return r.onRetry, nil // retry after Create fails
}
func (r *raceUserRepo) Create(_ context.Context, _ *userdom.User) error {
	return errTestCreateConflict
}
func (r *raceUserRepo) Update(_ context.Context, u *userdom.User) error { r.updated = u; return nil }
func (r *raceUserRepo) GetByID(_ context.Context, id shared.ID) (*userdom.User, error) {
	if r.onRetry != nil && r.onRetry.ID() == id {
		return r.onRetry, nil
	}
	return nil, userdom.NotFoundError(id)
}

var errTestCreateConflict = fmt.Errorf("duplicate key value violates unique constraint")

// The create-race retry path must apply the SAME takeover guard as the normal
// path: a password-backed LOCAL account revealed by the retry lookup must NOT
// be silently adopted by a federated login.
func TestSSOFindOrCreate_RetryPathBlocksPasswordLocalTakeover(t *testing.T) {
	victim, _ := userdom.NewLocalUser(victimMail, "Victim", "hashed-password")
	repo := &raceUserRepo{onRetry: victim}
	s := &SSOService{userRepo: repo, identities: newMemIdentities(), logger: logger.NewNop(), authConfig: regEnabled(), domainVerifier: corpVerified()}

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: evilOkta, Subject: "evil"},
		jitRP(identityproviderdom.ProviderOkta))
	if err == nil {
		t.Fatal("expected the retry path to block adoption of a password-backed local account")
	}
	if got != nil {
		t.Fatalf("blocked login must not return a user, got %v", got)
	}
	if repo.updated != nil {
		t.Fatal("blocked login must not persist a login/binding")
	}
}

// The retry path still succeeds for a legitimate concurrent creation of the
// same federated identity (same issuer).
func TestSSOFindOrCreate_RetryPathAdoptsSameIssuer(t *testing.T) {
	concurrent, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	repo := &raceUserRepo{onRetry: concurrent}
	ids := newMemIdentities()
	s := &SSOService{userRepo: repo, identities: ids, logger: logger.NewNop(), authConfig: regEnabled(), domainVerifier: corpVerified()}
	// The concurrent login created the account; its identity is bound the
	// moment our own lookup has already missed.
	ids.bindTo(concurrent, corpOkta, "corp-sub")
	ids.hideOnce = 1

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: corpOkta, Subject: "corp-sub"},
		jitRP(identityproviderdom.ProviderOkta))
	if err != nil {
		t.Fatalf("same-issuer concurrent creation should be adopted, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the concurrently-created user back")
	}
}

// A brand-new Okta / generic-OIDC user must be creatable. mapAuthProvider maps
// Okta to AuthProviderOIDC, which NewOAuthUser rejected — so first-login via
// Okta used to fail. NewFederatedUser fixes it; the new user is OIDC + bound.
func TestSSOFindOrCreate_NewOktaUserCreated(t *testing.T) {
	s, repo := newSSOSvc(nil) // no existing user
	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "newokta@corp.com", Name: "New Okta", Issuer: corpOkta, Subject: "okta-sub"},
		jitRP(identityproviderdom.ProviderOkta))
	if err != nil {
		t.Fatalf("Okta first-login should create the user, got %v", err)
	}
	if got == nil || repo.created == nil {
		t.Fatal("expected a created OIDC user")
	}
	if repo.created.AuthProvider() != userdom.AuthProviderOIDC {
		t.Fatalf("expected AuthProviderOIDC, got %s", repo.created.AuthProvider())
	}
	if keys := idsOf(s).keysOf(repo.created.ID()); len(keys) != 1 || keys[0].Issuer != corpOkta {
		t.Fatalf("new Okta user must be bound to %q, got %+v", corpOkta, keys)
	}
}

// A brand-new federated user records the IdP issuer at creation. Entra
// (→Microsoft) is used because NewOAuthUser accepts it.
func TestSSOFindOrCreate_NewUserBindsIssuer(t *testing.T) {
	s, repo := newSSOSvc(nil) // no existing user
	const entraIss = "https://login.microsoftonline.com/dir/v2.0"

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "new@corp.com", Name: "New", Issuer: entraIss, Subject: "entra-sub"},
		jitRP(identityproviderdom.ProviderEntraID))
	if err != nil {
		t.Fatalf("new federated user creation should succeed, got %v", err)
	}
	if got == nil || repo.created == nil {
		t.Fatal("expected a created user")
	}
	if keys := idsOf(s).keysOf(repo.created.ID()); len(keys) != 1 || keys[0].Issuer != entraIss {
		t.Fatalf("new user must be bound to %q, got %+v", entraIss, keys)
	}
}

// jitRP is the resolved provider a findOrCreateUser test logs in through:
// auto-provisioning on, so a brand-new account is admitted exactly when the
// verified-domain gate passes.
func jitRP(p identityproviderdom.Provider) *resolvedProvider {
	return &resolvedProvider{provider: p, autoProvision: true, source: "tenant"}
}

// corpVerified is a domain verifier for which corp.com is DNS-verified for the
// organization, the precondition for SSO to create a brand-new account.
func corpVerified() *fakeDomainVerifier {
	return &fakeDomainVerifier{verified: map[string]bool{"corp.com": true}}
}

// Cross-tenant takeover through an unbound account: every Okta/generic OIDC IdP
// maps to the same provider type, so for an account with no recorded issuer
// the type match proves nothing. An organization that has not DNS-verified the
// email domain must not get to adopt (and bind) the account with its own IdP.
func TestSSOFindOrCreate_UnboundAccountUnverifiedDomainRefused(t *testing.T) {
	legacy, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim") // no federated identity
	repo := &ssoFakeUserRepo{byEmail: legacy}
	s := &SSOService{userRepo: repo, identities: newMemIdentities(), logger: logger.NewNop(), authConfig: regEnabled(),
		domainVerifier: &fakeDomainVerifier{verified: map[string]bool{"attacker.io": true}}}

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: evilOkta, Subject: "evil-sub", EmailVerified: true},
		jitRP(identityproviderdom.ProviderOkta))
	if !errors.Is(err, ErrAccountLinkRequiresVerification) {
		t.Fatalf("expected ErrAccountLinkRequiresVerification, got %v", err)
	}
	if got != nil || repo.updated != nil {
		t.Fatal("a refused login must not return or bind the account")
	}
	if keys := idsOf(s).keysOf(legacy.ID()); len(keys) != 0 {
		t.Fatalf("the attacker's identity must not be bound, got %+v", keys)
	}
}

// A login without an id_token (issuer unknown) cannot be matched to the bound
// IdP, so it also needs the organization's DNS-verified domain.
func TestSSOFindOrCreate_NoIssuerUnverifiedDomainRefused(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	s := &SSOService{userRepo: &ssoFakeUserRepo{byEmail: u}, identities: newMemIdentities(), logger: logger.NewNop(), authConfig: regEnabled(),
		domainVerifier: &fakeDomainVerifier{verified: map[string]bool{}}}
	idsOf(s).bindTo(u, corpOkta, "corp-sub")

	_, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, EmailVerified: true},
		jitRP(identityproviderdom.ProviderOkta))
	if !errors.Is(err, ErrAccountLinkRequiresVerification) {
		t.Fatalf("expected ErrAccountLinkRequiresVerification, got %v", err)
	}
}

// A login that matches the bound issuer needs no domain proof.
func TestSSOFindOrCreate_BoundIssuerMatchNeedsNoDomainProof(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	s := &SSOService{userRepo: &ssoFakeUserRepo{byEmail: u}, identities: newMemIdentities(), logger: logger.NewNop(), authConfig: regEnabled(),
		domainVerifier: &fakeDomainVerifier{verified: map[string]bool{}}}
	idsOf(s).bindTo(u, corpOkta, "corp-sub")

	if _, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: corpOkta, Subject: "corp-sub", EmailVerified: true},
		jitRP(identityproviderdom.ProviderOkta)); err != nil {
		t.Fatalf("bound-issuer login should succeed without domain proof, got %v", err)
	}
}

// R16: the organization SSO path checked only the issuer, so another person in
// the same directory (same issuer, different subject) presenting the victim's
// email was let in. The subject must match too.
func TestSSOFindOrCreate_SameIssuerOtherSubjectRefused(t *testing.T) {
	victim, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	s, repo := newSSOSvc(victim)
	idsOf(s).bindTo(victim, corpOkta, "corp-sub")

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: corpOkta, Subject: "other-sub", EmailVerified: true},
		jitRP(identityproviderdom.ProviderOkta))
	if !errors.Is(err, ErrFederatedIdentityConflict) {
		t.Fatalf("expected ErrFederatedIdentityConflict, got %v", err)
	}
	if got != nil || repo.updated != nil || repo.created != nil {
		t.Fatal("a refused login must not return, change or create an account")
	}
	if keys := idsOf(s).keysOf(victim.ID()); len(keys) != 1 || keys[0].Subject != "corp-sub" {
		t.Fatalf("binding must stay corp-sub, got %+v", keys)
	}
}

// The returning account is found by (issuer, subject) even when the IdP now
// sends another email: no duplicate account, no refusal, and the email moves
// to the new address because the organization DNS-verified its domain.
func TestSSOFindOrCreate_EmailChangedAtIdP_Updated(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", "old@corp.com", "Person")
	s, repo := newSSOSvc(nil) // the new address names no account
	repo.others = []*userdom.User{u}
	idsOf(s).bindTo(u, corpOkta, "corp-sub")

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "new@corp.com", Issuer: corpOkta, Subject: "corp-sub", EmailVerified: true},
		jitRP(identityproviderdom.ProviderOkta))
	if err != nil {
		t.Fatalf("returning identity must sign in, got %v", err)
	}
	if got == nil || got.ID() != u.ID() || repo.created != nil {
		t.Fatal("the same account must be returned, never a new one")
	}
	if got.Email() != "new@corp.com" {
		t.Fatalf("email = %q, want new@corp.com", got.Email())
	}
	if repo.updated == nil || repo.updated.Email() != "new@corp.com" {
		t.Fatal("the email change must be persisted")
	}
}

// The new address is on a domain this organization has not DNS-verified: the
// IdP cannot vouch for it. The person still signs in; the email is kept.
func TestSSOFindOrCreate_EmailChangedAtIdP_UnverifiedDomainKept(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", "old@corp.com", "Person")
	s, repo := newSSOSvc(nil)
	repo.others = []*userdom.User{u}
	idsOf(s).bindTo(u, corpOkta, "corp-sub")

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "ceo@victim.example", Issuer: corpOkta, Subject: "corp-sub", EmailVerified: true},
		jitRP(identityproviderdom.ProviderOkta))
	if err != nil || got == nil || got.ID() != u.ID() {
		t.Fatalf("returning identity must sign in, got %v", err)
	}
	if got.Email() != "old@corp.com" {
		t.Fatalf("email must stay old@corp.com, got %q", got.Email())
	}
}

// The new address belongs to another account: never taken from it.
func TestSSOFindOrCreate_EmailChangedAtIdP_HeldByOtherAccountKept(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", "old@corp.com", "Person")
	other, _ := userdom.NewFromKeycloak("kc-2", "boss@corp.com", "Boss")
	s, repo := newSSOSvc(nil)
	repo.others = []*userdom.User{u, other}
	idsOf(s).bindTo(u, corpOkta, "corp-sub")

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "boss@corp.com", Issuer: corpOkta, Subject: "corp-sub", EmailVerified: true},
		jitRP(identityproviderdom.ProviderOkta))
	if err != nil || got == nil || got.ID() != u.ID() {
		t.Fatalf("returning identity must sign in as itself, got %v", err)
	}
	if got.Email() != "old@corp.com" || other.Email() != "boss@corp.com" {
		t.Fatalf("no address may move: got %q / %q", got.Email(), other.Email())
	}
}

// An identity bound to account A never lets a login reach account B, even
// when the IdP sends B's email.
func TestSSOFindOrCreate_IdentityWinsOverEmail(t *testing.T) {
	a, _ := userdom.NewFromKeycloak("kc-1", "a@corp.com", "A")
	b, _ := userdom.NewFromKeycloak("kc-2", "b@corp.com", "B")
	s, repo := newSSOSvc(nil)
	repo.others = []*userdom.User{a, b}
	idsOf(s).bindTo(a, corpOkta, "sub-a")

	got, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "b@corp.com", Issuer: corpOkta, Subject: "sub-a", EmailVerified: true},
		jitRP(identityproviderdom.ProviderOkta))
	if err != nil || got == nil || got.ID() != a.ID() {
		t.Fatalf("the identity must resolve account A, got %v / %v", got, err)
	}
}

// Without the identity store wired, a login carrying an identity fails
// closed rather than falling back to email matching.
func TestSSOFindOrCreate_IdentityStoreMissing_FailsClosed(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	s := &SSOService{userRepo: &ssoFakeUserRepo{byEmail: u}, logger: logger.NewNop(), authConfig: regEnabled(), domainVerifier: corpVerified()}
	if _, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: corpOkta, Subject: "corp-sub", EmailVerified: true},
		jitRP(identityproviderdom.ProviderOkta)); err == nil {
		t.Fatal("expected a refusal without the identity store")
	}
}
