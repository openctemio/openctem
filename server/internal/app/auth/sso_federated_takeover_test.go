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

type fakeMemberRepo struct {
	member *tenantdom.Membership // nil = not a member of the queried tenant
}

func (f *fakeMemberRepo) CreateMembership(_ context.Context, _ *tenantdom.Membership) error {
	return nil
}

func (f *fakeMemberRepo) GetMembership(_ context.Context, _, _ shared.ID) (*tenantdom.Membership, error) {
	if f.member == nil {
		return nil, errors.New("membership not found")
	}
	return f.member, nil
}

// A federated (e.g. SAML) login must NOT bind to an existing global user who is
// not already a member of the target tenant — otherwise a malicious tenant that
// controls its own IdP signing key could forge an assertion for any user's
// email and hijack them.
func TestCompleteFederatedLogin_BlocksNonMemberCrossTenant(t *testing.T) {
	victim, err := userdom.NewOAuthUser("victim@corp.com", "Victim", "", userdom.AuthProviderGoogle)
	if err != nil {
		t.Fatalf("NewOAuthUser: %v", err)
	}
	tnt, _ := tenantdom.NewTenant("Attacker", "attacker", "00000000-0000-0000-0000-000000000001")

	svc := &SSOService{
		userRepo:         &fakeUserRepo{byEmail: victim},
		tenantMemberRepo: &fakeMemberRepo{member: nil}, // victim is NOT a member
		logger:           logger.NewNop(),
	}

	_, err = svc.CompleteFederatedLogin(context.Background(), tnt, "victim@corp.com", "Victim", "member", true)
	if !errors.Is(err, ErrSSOFederatedNotMember) {
		t.Fatalf("expected ErrSSOFederatedNotMember for a non-member existing user, got %v", err)
	}
}

// A password-backed local account is still blocked from federated login (the
// pre-existing takeover guard), independent of membership.
func TestCompleteFederatedLogin_BlocksPasswordLocalAccount(t *testing.T) {
	local, err := userdom.NewLocalUser("boss@corp.com", "Boss", "hashed-password-value")
	if err != nil {
		t.Fatalf("NewLocalUser: %v", err)
	}
	tnt, _ := tenantdom.NewTenant("Attacker", "attacker", "00000000-0000-0000-0000-000000000001")

	svc := &SSOService{
		userRepo:         &fakeUserRepo{byEmail: local},
		tenantMemberRepo: &fakeMemberRepo{member: nil},
		logger:           logger.NewNop(),
	}

	_, err = svc.CompleteFederatedLogin(context.Background(), tnt, "boss@corp.com", "Boss", "member", true)
	if !errors.Is(err, ErrSSOFederatedTakeover) {
		t.Fatalf("expected ErrSSOFederatedTakeover for a password-backed local account, got %v", err)
	}
}

// Cross-tenant takeover through membership: organization B makes the victim a
// member (SCIM, an admin add or an accepted invitation), then its own IdP signs
// an assertion for the victim's email. Membership must not be enough — the
// session would be exchangeable for every organization the victim belongs to.
// B has not DNS-verified corp.com, so the login is refused.
func TestCompleteFederatedLogin_MemberOnUnverifiedDomain_Refused(t *testing.T) {
	victim, err := userdom.NewOAuthUser("victim@corp.com", "Victim", "", userdom.AuthProviderMicrosoft)
	if err != nil {
		t.Fatalf("NewOAuthUser: %v", err)
	}
	tnt, _ := tenantdom.NewTenant("Attacker", "attacker", "00000000-0000-0000-0000-000000000001")
	m, _ := tenantdom.NewMembership(victim.ID(), tnt.ID(), tenantdom.RoleMember, nil)

	for name, verifier := range map[string]DomainVerifier{
		"no verifier wired":   nil,
		"domain not verified": &fakeDomainVerifier{verified: map[string]bool{"attacker.io": true}},
		"verifier error":      &fakeDomainVerifier{err: errors.New("db down")},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &SSOService{
				userRepo:         &fakeUserRepo{byEmail: victim},
				tenantMemberRepo: &fakeMemberRepo{member: m},
				domainVerifier:   verifier,
				logger:           logger.NewNop(),
			}
			_, err := svc.CompleteFederatedLogin(context.Background(), tnt, "victim@corp.com", "Victim", "member", true)
			if !errors.Is(err, ErrSSOFederatedDomainUnverified) {
				t.Fatalf("expected ErrSSOFederatedDomainUnverified, got %v", err)
			}
		})
	}
}

// A passwordless (invited / SCIM / SAML-created) account is refused the same
// way: it is the most common shape of a SAML user.
func TestCompleteFederatedLogin_PasswordlessMemberOnUnverifiedDomain_Refused(t *testing.T) {
	victim, err := userdom.New("victim@corp.com", "Victim")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tnt, _ := tenantdom.NewTenant("Attacker", "attacker", "00000000-0000-0000-0000-000000000001")
	m, _ := tenantdom.NewMembership(victim.ID(), tnt.ID(), tenantdom.RoleMember, nil)

	svc := &SSOService{
		userRepo:         &fakeUserRepo{byEmail: victim},
		tenantMemberRepo: &fakeMemberRepo{member: m},
		domainVerifier:   &fakeDomainVerifier{verified: map[string]bool{}},
		logger:           logger.NewNop(),
	}
	_, err = svc.CompleteFederatedLogin(context.Background(), tnt, "victim@corp.com", "Victim", "member", false)
	if !errors.Is(err, ErrSSOFederatedDomainUnverified) {
		t.Fatalf("expected ErrSSOFederatedDomainUnverified, got %v", err)
	}
}
