package auth

import (
	"context"
	"testing"

	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
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
