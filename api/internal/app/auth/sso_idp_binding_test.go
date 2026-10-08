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
}

func (r *ssoFakeUserRepo) GetByEmail(_ context.Context, _ string) (*userdom.User, error) {
	return r.byEmail, nil
}
func (r *ssoFakeUserRepo) Update(_ context.Context, u *userdom.User) error { r.updated = u; return nil }
func (r *ssoFakeUserRepo) Create(_ context.Context, u *userdom.User) error { r.created = u; return nil }

func newSSOSvc(existing *userdom.User) (*SSOService, *ssoFakeUserRepo) {
	repo := &ssoFakeUserRepo{byEmail: existing}
	return &SSOService{userRepo: repo, logger: logger.NewNop(), authConfig: regEnabled(), domainVerifier: corpVerified()}, repo
}

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
	victim.BindFederatedIdentity(corpOkta, "corp-sub")
	s, repo := newSSOSvc(victim)

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
	if iss := victim.FederatedIssuer(); iss == nil || *iss != corpOkta {
		t.Fatalf("victim issuer must stay %q, got %v", corpOkta, iss)
	}
}

// Re-login from the SAME issuer is fine.
func TestSSOFindOrCreate_SameIssuerOK(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	u.BindFederatedIdentity(corpOkta, "corp-sub")
	s, _ := newSSOSvc(u)

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
	legacy, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim") // no federated issuer
	if legacy.FederatedIssuer() != nil {
		t.Fatal("precondition: legacy user must start unbound")
	}
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
	if iss := got.FederatedIssuer(); iss == nil || *iss != corpOkta {
		t.Fatalf("expected issuer bound to %q on first use, got %v", corpOkta, iss)
	}
	if repo.updated == nil {
		t.Fatal("the newly-bound identity must be persisted via Update")
	}
}

// When the provider returns no id_token (issuer empty) we cannot bind/verify;
// the login must still work (no regression) — falling back to the existing
// provider-match guard.
func TestSSOFindOrCreate_NoIssuerNoRegression(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	u.BindFederatedIdentity(corpOkta, "corp-sub")
	s, _ := newSSOSvc(u)

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

var errTestCreateConflict = fmt.Errorf("duplicate key value violates unique constraint")

// The create-race retry path must apply the SAME takeover guard as the normal
// path: a password-backed LOCAL account revealed by the retry lookup must NOT
// be silently adopted by a federated login.
func TestSSOFindOrCreate_RetryPathBlocksPasswordLocalTakeover(t *testing.T) {
	victim, _ := userdom.NewLocalUser(victimMail, "Victim", "hashed-password")
	repo := &raceUserRepo{onRetry: victim}
	s := &SSOService{userRepo: repo, logger: logger.NewNop(), authConfig: regEnabled(), domainVerifier: corpVerified()}

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
	concurrent.BindFederatedIdentity(corpOkta, "corp-sub")
	repo := &raceUserRepo{onRetry: concurrent}
	s := &SSOService{userRepo: repo, logger: logger.NewNop(), authConfig: regEnabled(), domainVerifier: corpVerified()}

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
	if iss := repo.created.FederatedIssuer(); iss == nil || *iss != corpOkta {
		t.Fatalf("new Okta user must be bound to %q, got %v", corpOkta, iss)
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
	if iss := repo.created.FederatedIssuer(); iss == nil || *iss != entraIss {
		t.Fatalf("new user must be bound to %q, got %v", entraIss, iss)
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
	legacy, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim") // no federated issuer
	repo := &ssoFakeUserRepo{byEmail: legacy}
	s := &SSOService{userRepo: repo, logger: logger.NewNop(), authConfig: regEnabled(),
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
	if legacy.FederatedIssuer() != nil {
		t.Fatal("the attacker's issuer must not be bound")
	}
}

// A login without an id_token (issuer unknown) cannot be matched to the bound
// IdP, so it also needs the organization's DNS-verified domain.
func TestSSOFindOrCreate_NoIssuerUnverifiedDomainRefused(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	u.BindFederatedIdentity(corpOkta, "corp-sub")
	s := &SSOService{userRepo: &ssoFakeUserRepo{byEmail: u}, logger: logger.NewNop(), authConfig: regEnabled(),
		domainVerifier: &fakeDomainVerifier{verified: map[string]bool{}}}

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
	u.BindFederatedIdentity(corpOkta, "corp-sub")
	s := &SSOService{userRepo: &ssoFakeUserRepo{byEmail: u}, logger: logger.NewNop(), authConfig: regEnabled(),
		domainVerifier: &fakeDomainVerifier{verified: map[string]bool{}}}

	if _, err := s.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: victimMail, Issuer: corpOkta, Subject: "corp-sub", EmailVerified: true},
		jitRP(identityproviderdom.ProviderOkta)); err != nil {
		t.Fatalf("bound-issuer login should succeed without domain proof, got %v", err)
	}
}
