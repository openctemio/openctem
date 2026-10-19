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

// fakeUserRepo implements only the three methods findOrCreateUser touches; the
// rest of the large Repository interface is satisfied by the embedded nil.
type fakeUserRepo struct {
	userdom.Repository
	byEmail *userdom.User
	created *userdom.User
}

func (r *fakeUserRepo) GetByEmail(_ context.Context, _ string) (*userdom.User, error) {
	return r.byEmail, nil
}
func (r *fakeUserRepo) Update(_ context.Context, _ *userdom.User) error { return nil }
func (r *fakeUserRepo) GetByID(_ context.Context, id shared.ID) (*userdom.User, error) {
	for _, u := range []*userdom.User{r.byEmail, r.created} {
		if u != nil && u.ID() == id {
			return u, nil
		}
	}
	return nil, userdom.NotFoundError(id)
}
func (r *fakeUserRepo) Create(_ context.Context, u *userdom.User) error { r.created = u; return nil }

func newOAuthSvcWithUser(u *userdom.User) (*OAuthService, *fakeUserRepo) {
	repo := &fakeUserRepo{byEmail: u}
	return &OAuthService{userRepo: repo, logger: logger.NewNop()}, repo
}

// The headline fix: an account created by one federated provider (Google) must
// NOT be adoptable by a different federated provider (GitHub) on an email match.
func TestOAuthFindOrCreate_BlocksCrossFederatedTakeover(t *testing.T) {
	victim, err := userdom.NewOAuthUser("v@example.com", "Victim", "", userdom.AuthProviderGoogle)
	if err != nil {
		t.Fatalf("NewOAuthUser: %v", err)
	}
	s, repo := newOAuthSvcWithUser(victim)

	got, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "v@example.com", Name: "Attacker"}, OAuthProviderGitHub)
	if err == nil {
		t.Fatal("expected cross-provider (Google account ← GitHub login) to be BLOCKED, got nil error")
	}
	if got != nil {
		t.Fatalf("blocked login must not return a user; got %v", got)
	}
	if repo.created != nil {
		t.Fatal("blocked login must not create a user")
	}
}

// Same provider re-login is fine.
func TestOAuthFindOrCreate_SameProviderOK(t *testing.T) {
	u, _ := userdom.NewOAuthUser("u@example.com", "U", "", userdom.AuthProviderGoogle)
	s, _ := newOAuthSvcWithUser(u)

	got, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "u@example.com"}, OAuthProviderGoogle)
	if err != nil {
		t.Fatalf("same-provider login should succeed: %v", err)
	}
	if got == nil || got.Email() != "u@example.com" {
		t.Fatalf("expected the existing user back, got %v", got)
	}
}

// A claimable local account (invited, no password yet) MAY be adopted by a
// federated provider on first login — that's the legitimate invite→SSO flow.
func TestOAuthFindOrCreate_AllowsClaimableLocal(t *testing.T) {
	invited, err := userdom.New("invited@example.com", "Invited") // local, no password
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if invited.PasswordHash() != nil {
		t.Skip("userdom.New unexpectedly set a password; claimable-local precondition not met")
	}
	s, _ := newOAuthSvcWithUser(invited)
	// Not yet in any organization: nothing to land in.
	s.SetClaimGuard(claimMembers{ms: &tenantdom.UserMembershipsByStatus{}}, claimDomains{})

	got, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "invited@example.com"}, OAuthProviderGoogle)
	if err != nil {
		t.Fatalf("claimable local account should be adoptable via OAuth: %v", err)
	}
	if got == nil {
		t.Fatal("expected the adopted user back")
	}
}

// A password-backed local account cannot be logged into via OAuth.
func TestOAuthFindOrCreate_BlocksPasswordLocal(t *testing.T) {
	local, err := userdom.NewLocalUser("local@example.com", "Local", "argon2-hash")
	if err != nil {
		t.Fatalf("NewLocalUser: %v", err)
	}
	s, _ := newOAuthSvcWithUser(local)

	if _, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "local@example.com"}, OAuthProviderGoogle); err == nil {
		t.Fatal("expected password-backed local account to block OAuth login")
	}
}

// claimMembers is a fixed membership list for the claim guard.
type claimMembers struct {
	ms  *tenantdom.UserMembershipsByStatus
	err error
}

func (c claimMembers) GetUserMembershipsWithStatus(context.Context, shared.ID) (*tenantdom.UserMembershipsByStatus, error) {
	return c.ms, c.err
}

// claimDomains: verified (tenant id, domain) pairs.
type claimDomains map[string]bool

func (d claimDomains) IsVerifiedDomain(_ context.Context, tenantID, domain string) (bool, error) {
	return d[tenantID+"|"+domain], nil
}

// A passwordless account that an organization provisioned without proving the
// email domain (SCIM squatting) must not capture the real owner's social
// sign-in into that organization.
func TestOAuthFindOrCreate_RefusesClaimIntoUnverifiedOrg(t *testing.T) {
	squatted, _ := userdom.New("victim@gmail.example", "Victim")
	attacker := shared.NewID().String()
	owner := shared.NewID().String()
	cases := map[string]struct {
		members claimMembers
		domains claimDomains
	}{
		"active membership in an org without the domain": {
			members: claimMembers{ms: &tenantdom.UserMembershipsByStatus{Active: []tenantdom.UserMembership{{TenantID: attacker}}}},
			domains: claimDomains{},
		},
		"suspended membership in an org without the domain": {
			members: claimMembers{ms: &tenantdom.UserMembershipsByStatus{Suspended: []tenantdom.UserMembership{{TenantID: attacker}}}},
			domains: claimDomains{},
		},
		"one verified org does not vouch for another": {
			members: claimMembers{ms: &tenantdom.UserMembershipsByStatus{Active: []tenantdom.UserMembership{{TenantID: owner}, {TenantID: attacker}}}},
			domains: claimDomains{owner + "|gmail.example": true},
		},
		"membership lookup error": {
			members: claimMembers{err: errors.New("db down")},
			domains: claimDomains{},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, repo := newOAuthSvcWithUser(squatted)
			s.SetClaimGuard(tc.members, tc.domains)
			got, err := s.findOrCreateUser(context.Background(),
				&OAuthUserInfo{Email: "victim@gmail.example"}, OAuthProviderGoogle)
			if err == nil || got != nil {
				t.Fatalf("claim into an unverified organization must be refused, got user=%v err=%v", got, err)
			}
			if repo.created != nil {
				t.Fatal("a refused claim must not create an account")
			}
		})
	}

	// No guard wired: fail closed.
	s, _ := newOAuthSvcWithUser(squatted)
	if got, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "victim@gmail.example"}, OAuthProviderGoogle); err == nil || got != nil {
		t.Fatalf("without the claim guard a claimable account must not be adopted, got user=%v err=%v", got, err)
	}
}

// Control: an account provisioned by an organization that verified the domain
// is claimed on the person's first social sign-in.
func TestOAuthFindOrCreate_ClaimIntoVerifiedOrg(t *testing.T) {
	staff, _ := userdom.New("staff@corp.example", "Staff")
	org := shared.NewID().String()
	s, _ := newOAuthSvcWithUser(staff)
	s.SetClaimGuard(
		claimMembers{ms: &tenantdom.UserMembershipsByStatus{Active: []tenantdom.UserMembership{{TenantID: org}}}},
		claimDomains{org + "|corp.example": true})
	if got, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "staff@corp.example"}, OAuthProviderGoogle); err != nil || got == nil {
		t.Fatalf("claim on a verified domain should succeed: user=%v err=%v", got, err)
	}
}
