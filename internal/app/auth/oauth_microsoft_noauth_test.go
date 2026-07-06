package auth

import (
	"context"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
)

func boolPtr(b bool) *bool { return &b }

func msClaims(email string, edov *bool) *oidcClaims {
	return &oidcClaims{
		Email:   email,
		Name:    "User",
		TID:     "tenant-1",
		XMSEdov: edov,
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:  "https://login.microsoftonline.com/tenant-1/v2.0",
			Subject: "sub-1",
		},
	}
}

// nOAuth core: an Entra id_token whose email is NOT domain-owner-verified
// (xms_edov absent or false) must be refused — a rogue tenant can set a mutable
// `mail` to a victim's address, so only xms_edov=true proves domain ownership.
func TestMicrosoftUserInfoFromClaims_RequiresXmsEdov(t *testing.T) {
	if _, err := microsoftUserInfoFromClaims(msClaims("victim@corp.com", nil)); err == nil {
		t.Fatal("expected rejection when xms_edov is absent (unverified email)")
	}
	if _, err := microsoftUserInfoFromClaims(msClaims("victim@corp.com", boolPtr(false))); err == nil {
		t.Fatal("expected rejection when xms_edov=false")
	}

	info, err := microsoftUserInfoFromClaims(msClaims("real@corp.com", boolPtr(true)))
	if err != nil {
		t.Fatalf("domain-verified email should be accepted: %v", err)
	}
	if info.Email != "real@corp.com" || info.Subject != "sub-1" || info.Issuer == "" {
		t.Fatalf("unexpected mapped info: %+v", info)
	}
}

// Verified email with an empty email claim is still rejected.
func TestMicrosoftUserInfoFromClaims_RejectsEmptyEmail(t *testing.T) {
	if _, err := microsoftUserInfoFromClaims(msClaims("", boolPtr(true))); err == nil {
		t.Fatal("expected rejection when the id_token carries no email")
	}
}

// Defense-in-depth: an account already pinned to federated identity A must
// reject a login presenting the SAME email but a DIFFERENT (issuer, subject).
func TestOAuthFindOrCreate_BlocksFederatedIdentityMismatch(t *testing.T) {
	u, _ := userdom.NewOAuthUser("u@corp.com", "U", "", userdom.AuthProviderMicrosoft)
	u.BindFederatedIdentity("iss-A", "sub-A")
	s, _ := newOAuthSvcWithUser(u)

	// Same identity → OK.
	if _, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "u@corp.com", Issuer: "iss-A", Subject: "sub-A"},
		OAuthProviderMicrosoft); err != nil {
		t.Fatalf("same federated identity should succeed: %v", err)
	}

	// Different identity, same email → BLOCKED.
	if _, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "u@corp.com", Issuer: "iss-EVIL", Subject: "sub-EVIL"},
		OAuthProviderMicrosoft); err == nil {
		t.Fatal("expected a different federated identity for the same email to be BLOCKED")
	}
}

// A newly-created OAuth account is pinned to the federated identity it logged
// in with, so subsequent logins can be identity-matched.
func TestOAuthFindOrCreate_BindsOnCreate(t *testing.T) {
	repo := &fakeUserRepo{byEmail: nil} // no existing user → create path
	s := &OAuthService{userRepo: repo, logger: logger.NewNop()}

	if _, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "new@corp.com", Name: "New", Issuer: "iss-A", Subject: "sub-A"},
		OAuthProviderMicrosoft); err != nil {
		t.Fatalf("create: %v", err)
	}
	if repo.created == nil {
		t.Fatal("expected a user to be created")
	}
	if fi := repo.created.FederatedIssuer(); fi == nil || *fi != "iss-A" {
		t.Fatalf("created user should be bound to iss-A, got %v", fi)
	}
	if fs := repo.created.FederatedSubject(); fs == nil || *fs != "sub-A" {
		t.Fatalf("created user should be bound to sub-A, got %v", fs)
	}
}
