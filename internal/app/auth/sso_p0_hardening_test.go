package auth

import (
	"context"
	"errors"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/api/internal/config"
	identityproviderdom "github.com/openctemio/api/pkg/domain/identityprovider"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// FIX 1 — the shared /common env fallback is opt-in per tenant and fail-closed
// =============================================================================

// entraCfg builds an env Entra config for the FIX 1 tests.
func entraCfg(tenantID string, allowedTenants, allowedDomains []string) config.EntraSSOConfig {
	return config.EntraSSOConfig{
		Enabled:        true,
		ClientID:       "env-client-id",
		ClientSecret:   "env-secret",
		TenantID:       tenantID,
		AllowedDomains: allowedDomains,
		AllowedTenants: allowedTenants,
		DefaultRole:    "member",
		DisplayName:    "Microsoft Entra ID",
	}
}

// A tenant that has NOT opted in gets NO env fallback provider and NO env button,
// even though the platform env config is fully configured.
func TestFix1_EnvFallback_NotOptedIn_Refused(t *testing.T) {
	// "acme" is the test tenant slug; allow-list contains a DIFFERENT slug.
	svc := newSSOForTest(&fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{}},
		entraCfg("dir-1234", []string{"other-org"}, nil))

	if _, err := svc.resolveProvider(context.Background(), "tid", "acme", identityproviderdom.ProviderEntraID); !errors.Is(err, ErrSSOProviderNotFound) {
		t.Fatalf("non-opted-in tenant must get no env fallback, got err=%v", err)
	}

	got, err := svc.GetProvidersForTenant(context.Background(), "acme")
	if err != nil {
		t.Fatalf("GetProvidersForTenant: %v", err)
	}
	for _, p := range got {
		if p.ID == "env:entra_id" {
			t.Fatalf("non-opted-in tenant must not see the env SSO button, got %+v", got)
		}
	}
}

// An empty allow-list disables the env fallback for everyone (fail-closed).
func TestFix1_EnvFallback_EmptyAllowlist_RefusedForAll(t *testing.T) {
	svc := newSSOForTest(&fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{}},
		entraCfg("dir-1234", nil, nil))
	if _, err := svc.resolveProvider(context.Background(), "tid", "acme", identityproviderdom.ProviderEntraID); !errors.Is(err, ErrSSOProviderNotFound) {
		t.Fatalf("empty allow-list must disable env fallback, got err=%v", err)
	}
}

// Opted-in but a non-specific directory (common) with EMPTY AllowedDomains is
// refused entirely — a multi-tenant authority with no domain gate is unusable.
func TestFix1_EnvFallback_CommonDirEmptyDomains_Refused(t *testing.T) {
	svc := newSSOForTest(&fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{}},
		entraCfg("common", []string{"acme"}, nil))
	if _, err := svc.resolveProvider(context.Background(), "tid", "acme", identityproviderdom.ProviderEntraID); !errors.Is(err, ErrSSOProviderNotFound) {
		t.Fatalf("common directory + empty domains must be refused, got err=%v", err)
	}
	// And no button.
	got, _ := svc.GetProvidersForTenant(context.Background(), "acme")
	for _, p := range got {
		if p.ID == "env:entra_id" {
			t.Fatal("common+empty-domains must not surface the env button")
		}
	}
}

// Opted-in, non-specific directory (common) WITH AllowedDomains is usable, but
// auto-provisioning is FORCED off (a multi-tenant authority must never JIT).
func TestFix1_EnvFallback_CommonDirWithDomains_NoAutoProvision(t *testing.T) {
	svc := newSSOForTest(&fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{}},
		entraCfg("common", []string{"acme"}, []string{"corp.com"}))
	rp, err := svc.resolveProvider(context.Background(), "tid", "acme", identityproviderdom.ProviderEntraID)
	if err != nil {
		t.Fatalf("common+domains+opted-in should resolve, got %v", err)
	}
	if rp.source != "env" {
		t.Fatalf("expected env source, got %q", rp.source)
	}
	if rp.autoProvision {
		t.Fatal("auto-provision MUST be forced off for a non-specific directory")
	}
}

// A pinned directory (real GUID) + AllowedDomains + opt-in may still auto-provision.
func TestFix1_EnvFallback_PinnedDirMayAutoProvision(t *testing.T) {
	cfg := entraCfg("dir-1234", []string{"acme"}, []string{"corp.com"})
	cfg.AutoProvision = true
	svc := newSSOForTest(&fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{}}, cfg)
	rp, err := svc.resolveProvider(context.Background(), "tid", "acme", identityproviderdom.ProviderEntraID)
	if err != nil {
		t.Fatalf("pinned dir should resolve, got %v", err)
	}
	if !rp.autoProvision {
		t.Fatal("a pinned directory with domains should keep auto-provision")
	}
}

// =============================================================================
// FIX 2 — JIT auto-provision is fail-closed (needs a non-empty AllowedDomains)
// =============================================================================

type p0MemberRepo struct {
	existing  *tenantdom.Membership
	created   *tenantdom.Membership
	createErr error
}

func (f *p0MemberRepo) GetMembership(_ context.Context, _, _ shared.ID) (*tenantdom.Membership, error) {
	return f.existing, nil
}
func (f *p0MemberRepo) CreateMembership(_ context.Context, m *tenantdom.Membership) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = m
	return nil
}

func memberTestFixtures(t *testing.T) (*SSOService, *userdom.User, *tenantdom.Tenant, *p0MemberRepo) {
	t.Helper()
	u, err := userdom.New("jit@corp.com", "JIT")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}
	tenant, err := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatalf("new tenant: %v", err)
	}
	mr := &p0MemberRepo{}
	svc := &SSOService{logger: logger.NewNop(), tenantMemberRepo: mr}
	return svc, u, tenant, mr
}

// Empty AllowedDomains ⇒ a non-member is refused, never silently granted.
func TestFix2_JIT_EmptyDomains_Refused(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	rp := &resolvedProvider{autoProvision: true, allowedDomains: nil, defaultRole: "member"}
	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("empty AllowedDomains must refuse JIT, got %v", err)
	}
	if mr.created != nil {
		t.Fatal("refused JIT must NOT create a membership")
	}
}

// Matching allowed domain ⇒ provisioned.
func TestFix2_JIT_MatchingDomain_Provisioned(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	rp := &resolvedProvider{autoProvision: true, allowedDomains: []string{"corp.com"}, defaultRole: "member"}
	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); err != nil {
		t.Fatalf("matching domain should provision, got %v", err)
	}
	if mr.created == nil {
		t.Fatal("matching domain must create a membership")
	}
}

// Non-matching domain ⇒ refused even with auto-provision + a non-empty allow-list.
func TestFix2_JIT_NonMatchingDomain_Refused(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	rp := &resolvedProvider{autoProvision: true, allowedDomains: []string{"other.com"}, defaultRole: "member"}
	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("non-matching domain must refuse, got %v", err)
	}
	if mr.created != nil {
		t.Fatal("refused JIT must NOT create a membership")
	}
}

// autoProvision disabled ⇒ refused even with a matching domain.
func TestFix2_JIT_AutoProvisionOff_Refused(t *testing.T) {
	svc, u, tenant, _ := memberTestFixtures(t)
	rp := &resolvedProvider{autoProvision: false, allowedDomains: []string{"corp.com"}, defaultRole: "member"}
	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("auto-provision off must refuse a non-member, got %v", err)
	}
}

// An EXISTING member passes through untouched (no new membership created).
func TestFix2_ExistingMember_Unaffected(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	existing, _ := tenantdom.NewMembership(u.ID(), tenant.ID(), tenantdom.RoleMember, nil)
	mr.existing = existing
	rp := &resolvedProvider{autoProvision: false, allowedDomains: nil, defaultRole: "member"}
	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); err != nil {
		t.Fatalf("existing member must be unaffected, got %v", err)
	}
	if mr.created != nil {
		t.Fatal("existing member must not trigger a new membership")
	}
}

// =============================================================================
// FIX 3 — the per-tenant Entra path keys on the verified id_token + xms_edov
// =============================================================================

// The Entra email is trusted ONLY when xms_edov==true; absent/false is refused
// (never falls back to Graph /me mail), and identity is keyed on (issuer,subject).
func TestFix3_EntraUserInfoFromClaims_RequiresXmsEdov(t *testing.T) {
	if _, err := entraUserInfoFromClaims(msClaims("victim@corp.com", nil)); err == nil {
		t.Fatal("expected refusal when xms_edov is absent")
	}
	if _, err := entraUserInfoFromClaims(msClaims("victim@corp.com", boolPtr(false))); err == nil {
		t.Fatal("expected refusal when xms_edov=false")
	}
	info, err := entraUserInfoFromClaims(msClaims("real@corp.com", boolPtr(true)))
	if err != nil {
		t.Fatalf("domain-verified email should be accepted: %v", err)
	}
	if info.Email != "real@corp.com" {
		t.Fatalf("unexpected email: %q", info.Email)
	}
	// Identity must be keyed on the immutable (issuer, subject) from the token.
	if info.Subject != "sub-1" || info.Issuer != "https://login.microsoftonline.com/tenant-1/v2.0" {
		t.Fatalf("identity must key on verified iss/sub, got iss=%q sub=%q", info.Issuer, info.Subject)
	}
}

// A verified token with an empty email claim is still refused.
func TestFix3_EntraUserInfoFromClaims_RejectsEmptyEmail(t *testing.T) {
	if _, err := entraUserInfoFromClaims(msClaims("", boolPtr(true))); err == nil {
		t.Fatal("expected refusal when the id_token carries no email")
	}
}

// The invited-account claim path must not be reachable for Entra without an
// xms_edov-verified email: because entraUserInfoFromClaims is the ONLY producer
// of the Entra SSOUserInfo, an unverified email never yields a userInfo to adopt
// a passwordless invited account with. This asserts that upstream gate directly.
func TestFix3_EntraUnverifiedEmail_NeverProducesUserInfo(t *testing.T) {
	claims := &oidcClaims{
		Email:   "invited@corp.com", // matches a pre-invited account, but...
		XMSEdov: nil,                // ...NOT domain-owner-verified
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:  "https://login.microsoftonline.com/rogue/v2.0",
			Subject: "rogue-sub",
		},
	}
	if _, err := entraUserInfoFromClaims(claims); err == nil {
		t.Fatal("unverified Entra email must not produce a userInfo (pre-hijack window)")
	}
}

// =============================================================================
// FIX 4 — federated login respects AUTH_ALLOW_REGISTRATION
// =============================================================================

// SSO: registration disabled ⇒ a brand-new user is refused (no create).
func TestFix4_SSO_RegistrationDisabled_BlocksNewUser(t *testing.T) {
	repo := &ssoFakeUserRepo{byEmail: nil} // no existing user
	svc := &SSOService{userRepo: repo, logger: logger.NewNop(), authConfig: config.AuthConfig{AllowRegistration: false}}

	_, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "new@corp.com", Name: "New", Issuer: "iss", Subject: "sub"},
		identityproviderdom.ProviderEntraID)
	if !errors.Is(err, ErrSSORegistrationDisabled) {
		t.Fatalf("registration disabled must block new SSO user, got %v", err)
	}
	if repo.created != nil {
		t.Fatal("registration disabled must NOT create a user")
	}
}

// SSO: registration disabled STILL binds a pre-invited (passwordless local)
// account — provided proof-before-link is satisfied (IdP-verified email AND a
// DNS-verified tenant domain). The AllowRegistration gate must not block the
// claim of an existing seat once ownership is proven.
func TestFix4_SSO_RegistrationDisabled_BindsExisting(t *testing.T) {
	invited, err := userdom.New("invited@corp.com", "Invited") // local, no password
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if invited.PasswordHash() != nil {
		t.Skip("userdom.New unexpectedly set a password")
	}
	repo := &ssoFakeUserRepo{byEmail: invited}
	svc := &SSOService{
		userRepo:       repo,
		logger:         logger.NewNop(),
		authConfig:     config.AuthConfig{AllowRegistration: false},
		domainVerifier: &fakeDomainVerifier{verified: map[string]bool{"corp.com": true}},
	}

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "invited@corp.com", Issuer: "iss", Subject: "sub", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if err != nil {
		t.Fatalf("binding a pre-invited account must work even with registration disabled, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the adopted account back")
	}
}

// OAuth: registration disabled ⇒ a brand-new social user is refused.
func TestFix4_OAuth_RegistrationDisabled_BlocksNewUser(t *testing.T) {
	repo := &fakeUserRepo{byEmail: nil}
	svc := &OAuthService{userRepo: repo, logger: logger.NewNop(), authConfig: config.AuthConfig{AllowRegistration: false}}

	_, err := svc.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "new@corp.com", Name: "New"}, OAuthProviderGoogle)
	if !errors.Is(err, ErrRegistrationDisabled) {
		t.Fatalf("registration disabled must block new OAuth user, got %v", err)
	}
	if repo.created != nil {
		t.Fatal("registration disabled must NOT create a user")
	}
}

// OAuth: registration disabled STILL binds a pre-invited local account.
func TestFix4_OAuth_RegistrationDisabled_BindsExisting(t *testing.T) {
	invited, err := userdom.New("invited@corp.com", "Invited")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if invited.PasswordHash() != nil {
		t.Skip("userdom.New unexpectedly set a password")
	}
	repo := &fakeUserRepo{byEmail: invited}
	svc := &OAuthService{userRepo: repo, logger: logger.NewNop(), authConfig: config.AuthConfig{AllowRegistration: false}}

	got, err := svc.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "invited@corp.com"}, OAuthProviderGoogle)
	if err != nil {
		t.Fatalf("binding a pre-invited account must work with registration disabled, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the adopted account back")
	}
}
