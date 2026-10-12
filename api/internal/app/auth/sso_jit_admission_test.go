package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// For an organization, SSO decides who is admitted (RFC-025). These tests pin the
// admission rule shared by OIDC (ensureTenantMembership / findOrCreateUser) and
// SAML (CompleteFederatedLogin).

func jitTenant(t *testing.T, allowedDomains ...string) *tenantdom.Tenant {
	t.Helper()
	tn, err := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if len(allowedDomains) > 0 {
		sec := tn.TypedSettings().Security
		sec.AllowedDomains = allowedDomains
		if err := tn.UpdateSecuritySettings(sec); err != nil {
			t.Fatalf("security: %v", err)
		}
	}
	return tn
}

func TestJIT_VerifiedDomainAdmitted(t *testing.T) {
	svc := &SSOService{logger: logger.NewNop(), domainVerifier: corpVerified()}
	rp := &resolvedProvider{autoProvision: true}
	if !svc.jitProvisioningAllowed(context.Background(), jitTenant(t), rp, "a@corp.com") {
		t.Fatal("verified domain + auto-provision must be admitted")
	}
	if svc.jitProvisioningAllowed(context.Background(), jitTenant(t), rp, "a@other.com") {
		t.Fatal("an unverified domain must be refused")
	}
}

// The organization's own Security.AllowedDomains narrows SSO admission too.
func TestJIT_TenantAllowedDomainsEnforced(t *testing.T) {
	svc := &SSOService{logger: logger.NewNop(), domainVerifier: corpVerified()}
	rp := &resolvedProvider{autoProvision: true}
	if svc.jitProvisioningAllowed(context.Background(), jitTenant(t, "partner.com"), rp, "a@corp.com") {
		t.Fatal("a verified domain outside the organization's AllowedDomains must be refused")
	}
	if !svc.jitProvisioningAllowed(context.Background(), jitTenant(t, "corp.com"), rp, "a@corp.com") {
		t.Fatal("a verified domain inside AllowedDomains must be admitted")
	}
}

func TestJIT_NilTenantOrProviderRefused(t *testing.T) {
	svc := &SSOService{logger: logger.NewNop(), domainVerifier: corpVerified()}
	if svc.jitProvisioningAllowed(context.Background(), nil, &resolvedProvider{autoProvision: true}, "a@corp.com") {
		t.Fatal("nil tenant must be refused")
	}
	if svc.jitProvisioningAllowed(context.Background(), jitTenant(t), nil, "a@corp.com") {
		t.Fatal("nil provider must be refused")
	}
	if svc.jitProvisioningAllowed(context.Background(), jitTenant(t), &resolvedProvider{autoProvision: true}, "no-at-sign") {
		t.Fatal("an email without a domain must be refused")
	}
}

func TestJITMembershipRole_LeastPrivilegeDefault(t *testing.T) {
	cases := map[string]tenantdom.Role{
		"":        tenantdom.RoleViewer,
		"viewer":  tenantdom.RoleViewer,
		"member":  tenantdom.RoleMember,
		"Admin":   tenantdom.RoleViewer, // never granted by SSO (B18)
		"owner":   tenantdom.RoleViewer, // never granted by SSO
		"garbage": tenantdom.RoleViewer,
	}
	for in, want := range cases {
		if got := jitMembershipRole(in); got != want {
			t.Errorf("jitMembershipRole(%q) = %s, want %s", in, got, want)
		}
	}
}

// SAML: a brand-new email on an UNVERIFIED domain is refused and no account is
// created (previously the account was created and a tenant-less session issued).
func TestCompleteFederatedLogin_NewUser_UnverifiedDomain_RefusedNoAccount(t *testing.T) {
	repo := &fakeUserRepo{byEmail: nil}
	members := &p0MemberRepo{}
	svc := &SSOService{userRepo: repo, tenantMemberRepo: members, logger: logger.NewNop(),
		domainVerifier: &fakeDomainVerifier{verified: map[string]bool{"other.com": true}}}

	_, err := svc.CompleteFederatedLogin(context.Background(), jitTenant(t), "new@corp.com", "New", "member", true)
	if !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("unverified domain must be refused, got %v", err)
	}
	if repo.created != nil || members.created != nil {
		t.Fatal("a refused SAML login must not create an account or a membership")
	}
}

// SAML: auto-provisioning off ⇒ a brand-new email is refused, nothing created.
func TestCompleteFederatedLogin_NewUser_AutoProvisionOff_Refused(t *testing.T) {
	repo := &fakeUserRepo{byEmail: nil}
	svc := &SSOService{userRepo: repo, tenantMemberRepo: &p0MemberRepo{}, logger: logger.NewNop(),
		domainVerifier: corpVerified()}

	_, err := svc.CompleteFederatedLogin(context.Background(), jitTenant(t), "new@corp.com", "New", "member", false)
	if !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("auto-provision off must refuse a new account, got %v", err)
	}
	if repo.created != nil {
		t.Fatal("no account may be created")
	}
}

// SAML: the organization's AllowedDomains is enforced on JIT.
func TestCompleteFederatedLogin_NewUser_TenantAllowedDomainsRefused(t *testing.T) {
	repo := &fakeUserRepo{byEmail: nil}
	svc := &SSOService{userRepo: repo, tenantMemberRepo: &p0MemberRepo{}, logger: logger.NewNop(),
		domainVerifier: corpVerified()}

	_, err := svc.CompleteFederatedLogin(context.Background(), jitTenant(t, "partner.com"), "new@corp.com", "New", "", true)
	if !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("AllowedDomains must be enforced on SAML JIT, got %v", err)
	}
	if repo.created != nil {
		t.Fatal("no account may be created")
	}
}

// Only the display name is re-synced on login; nothing else changes.
func TestSyncFederatedProfile_NameOnly(t *testing.T) {
	u, _ := userdom.NewFederatedUser("a@corp.com", "Old Name", "", userdom.AuthProviderGoogle)
	syncFederatedProfile(u, "  New Name ")
	if u.Name() != "New Name" || u.Email() != "a@corp.com" {
		t.Fatalf("name must be re-synced and email untouched, got name=%q email=%q", u.Name(), u.Email())
	}
	syncFederatedProfile(u, "")
	if u.Name() != "New Name" {
		t.Fatal("an empty IdP name must not blank the profile")
	}
}
