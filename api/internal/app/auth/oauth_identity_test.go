package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// emailUsers finds accounts by exact email (the social path's lookups).
type emailUsers struct {
	userdom.Repository
	all     []*userdom.User
	updated int
}

func (r *emailUsers) GetByEmail(_ context.Context, email string) (*userdom.User, error) {
	for _, u := range r.all {
		if u.Email() == email {
			return u, nil
		}
	}
	return nil, userdom.NotFoundByEmailError(email)
}
func (r *emailUsers) GetByID(_ context.Context, id shared.ID) (*userdom.User, error) {
	for _, u := range r.all {
		if u.ID() == id {
			return u, nil
		}
	}
	return nil, userdom.NotFoundError(id)
}
func (r *emailUsers) Update(context.Context, *userdom.User) error { r.updated++; return nil }

// A Google account bound to its sub keeps signing in after the address
// changes at Google, and the account follows the new (Google-verified) email.
func TestOAuthLogin_GoogleEmailChange_SameAccount(t *testing.T) {
	u, _ := userdom.NewOAuthUser("old@gmail.com", "U", "", userdom.AuthProviderGoogle)
	repo := &emailUsers{all: []*userdom.User{u}}
	ids := newMemIdentities()
	ids.bindTo(u, googleIssuer, "g-1")
	s := &OAuthService{userRepo: repo, identities: ids, logger: logger.NewNop()}

	got, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "new@example.org", Issuer: googleIssuer, Subject: "g-1"}, OAuthProviderGoogle)
	if err != nil || got == nil || got.ID() != u.ID() {
		t.Fatalf("returning identity must sign in as the same account, got %v / %v", got, err)
	}
	if u.Email() != "new@example.org" {
		t.Fatalf("email = %q, want new@example.org", u.Email())
	}
}

// The new address belongs to someone else: the login works, the address does
// not move.
func TestOAuthLogin_EmailChangeToTakenAddress_Kept(t *testing.T) {
	u, _ := userdom.NewOAuthUser("old@gmail.com", "U", "", userdom.AuthProviderGoogle)
	other, _ := userdom.NewLocalUser("boss@corp.com", "Boss", "hash")
	repo := &emailUsers{all: []*userdom.User{u, other}}
	ids := newMemIdentities()
	ids.bindTo(u, googleIssuer, "g-1")
	s := &OAuthService{userRepo: repo, identities: ids, logger: logger.NewNop()}

	got, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "boss@corp.com", Issuer: googleIssuer, Subject: "g-1"}, OAuthProviderGoogle)
	if err != nil || got == nil || got.ID() != u.ID() {
		t.Fatalf("returning identity must sign in as itself, got %v / %v", got, err)
	}
	if u.Email() != "old@gmail.com" {
		t.Fatalf("email must stay old@gmail.com, got %q", u.Email())
	}
}

// An existing, unbound Google account is bound on its next login (verified
// email matches, no other subject bound); a second Google account presenting
// the same email afterwards is refused.
func TestOAuthLogin_ExistingGoogleAccountBoundThenOtherSubjectRefused(t *testing.T) {
	u, _ := userdom.NewOAuthUser("me@gmail.com", "U", "", userdom.AuthProviderGoogle)
	repo := &emailUsers{all: []*userdom.User{u}}
	ids := newMemIdentities()
	s := &OAuthService{userRepo: repo, identities: ids, logger: logger.NewNop()}

	if _, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "me@gmail.com", Issuer: googleIssuer, Subject: "g-1"}, OAuthProviderGoogle); err != nil {
		t.Fatalf("first login after the upgrade must bind: %v", err)
	}
	if keys := ids.keysOf(u.ID()); len(keys) != 1 || keys[0].Subject != "g-1" {
		t.Fatalf("expected g-1 bound, got %+v", keys)
	}
	if _, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "me@gmail.com", Issuer: googleIssuer, Subject: "g-2"}, OAuthProviderGoogle); err == nil {
		t.Fatal("another Google subject with the same email must be refused")
	}
}

// GitHub accounts are keyed on the numeric user id.
func TestOAuthLogin_GitHubKeyedOnID(t *testing.T) {
	u, _ := userdom.NewOAuthUser("dev@example.org", "Dev", "", userdom.AuthProviderGitHub)
	repo := &emailUsers{all: []*userdom.User{u}}
	ids := newMemIdentities()
	ids.bindTo(u, githubIssuer, "42")
	s := &OAuthService{userRepo: repo, identities: ids, logger: logger.NewNop()}

	got, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "dev@new.example.org", Issuer: githubIssuer, Subject: "42"}, OAuthProviderGitHub)
	if err != nil || got == nil || got.ID() != u.ID() {
		t.Fatalf("GitHub id must resolve the account, got %v / %v", got, err)
	}
}

// A social sign-in whose provider key matches an identity an organization's
// single sign-on manages is refused (the person never confirmed that route):
// no account change, no session. A social identity still signs in.
func TestOAuthLogin_SocialRefusesSSOManagedIdentity(t *testing.T) {
	cases := []struct {
		name     string
		provider OAuthProvider
		auth     userdom.AuthProvider
		issuer   string
	}{
		{"google", OAuthProviderGoogle, userdom.AuthProviderGoogle, googleIssuer},
		{"microsoft", OAuthProviderMicrosoft, userdom.AuthProviderMicrosoft, "https://login.microsoftonline.com/tid-1/v2.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := userdom.NewOAuthUser("p@corp.com", "P", "", c.auth)
			repo := &emailUsers{all: []*userdom.User{u}}
			ids := newMemIdentities()
			ids.bindSSO(u, c.issuer, "sub-1")
			s := &OAuthService{userRepo: repo, identities: ids, logger: logger.NewNop()}

			got, err := s.findOrCreateUser(context.Background(),
				&OAuthUserInfo{Email: "p@corp.com", Issuer: c.issuer, Subject: "sub-1"}, c.provider)
			if !errors.Is(err, ErrOAuthUseOrgSSO) || got != nil {
				t.Fatalf("sso-managed identity must be refused, got %v / %v", got, err)
			}
			if repo.updated != 0 {
				t.Fatalf("a refused sign-in must write nothing, updated=%d", repo.updated)
			}

			// A social identity (another person) still signs in.
			v, _ := userdom.NewOAuthUser("q@example.org", "Q", "", c.auth)
			repo.all = append(repo.all, v)
			ids.bindTo(v, c.issuer, "sub-social")
			got, err = s.findOrCreateUser(context.Background(),
				&OAuthUserInfo{Email: "q@example.org", Issuer: c.issuer, Subject: "sub-social"}, c.provider)
			if err != nil || got == nil || got.ID() != v.ID() {
				t.Fatalf("a social identity must still sign in, got %v / %v", got, err)
			}
		})
	}
}
