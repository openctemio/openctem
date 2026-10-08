package auth

import (
	"context"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/api/internal/config"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

func boolPtr(b bool) *bool { return &b }

func msClaims(email string, edov *bool) *oidc.Claims {
	return &oidc.Claims{
		Email:   email,
		Name:    "User",
		TID:     "tenant-1",
		XMSEdov: oidc.FlexBool(edov != nil && *edov),
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

// Defense-in-depth: an account already bound to federated identity A must
// reject a login presenting the SAME email but a DIFFERENT (issuer, subject).
func TestOAuthFindOrCreate_BlocksFederatedIdentityMismatch(t *testing.T) {
	u, _ := userdom.NewOAuthUser("u@corp.com", "U", "", userdom.AuthProviderMicrosoft)
	repo := &fakeUserRepo{byEmail: u}
	ids := newMemIdentities()
	ids.bindTo(u, "iss-A", "sub-A")
	s := &OAuthService{userRepo: repo, identities: ids, logger: logger.NewNop()}

	// Same identity → OK.
	if _, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "u@corp.com", Issuer: "iss-A", Subject: "sub-A"},
		OAuthProviderMicrosoft); err != nil {
		t.Fatalf("same federated identity should succeed: %v", err)
	}

	// Different issuer, same email → BLOCKED.
	if _, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "u@corp.com", Issuer: "iss-EVIL", Subject: "sub-EVIL"},
		OAuthProviderMicrosoft); err == nil {
		t.Fatal("expected a different federated identity for the same email to be BLOCKED")
	}
	// Same issuer, different subject, same email → BLOCKED (another person in
	// the same directory claiming the address).
	if _, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "u@corp.com", Issuer: "iss-A", Subject: "sub-OTHER"},
		OAuthProviderMicrosoft); err == nil {
		t.Fatal("expected another subject at the same issuer to be BLOCKED")
	}
	if keys := ids.keysOf(u.ID()); len(keys) != 1 || keys[0].Subject != "sub-A" {
		t.Fatalf("binding must stay sub-A only, got %+v", keys)
	}
}

// A newly-created OAuth account is bound to the federated identity it logged
// in with, so subsequent logins are matched by it.
func TestOAuthFindOrCreate_BindsOnCreate(t *testing.T) {
	repo := &fakeUserRepo{byEmail: nil} // no existing user → create path
	ids := newMemIdentities()
	s := &OAuthService{userRepo: repo, identities: ids, logger: logger.NewNop(), authConfig: config.AuthConfig{TenantCreationMode: config.TenantCreationSelfService}}

	if _, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "new@corp.com", Name: "New", Issuer: "iss-A", Subject: "sub-A"},
		OAuthProviderMicrosoft); err != nil {
		t.Fatalf("create: %v", err)
	}
	if repo.created == nil {
		t.Fatal("expected a user to be created")
	}
	keys := ids.keysOf(repo.created.ID())
	if len(keys) != 1 || keys[0].Issuer != "iss-A" || keys[0].Subject != "sub-A" || keys[0].ScopeTenantID != nil {
		t.Fatalf("created user should be bound to (iss-A, sub-A) platform-wide, got %+v", keys)
	}
}

// Microsoft accounts are keyed on oid (the same for every app in the
// directory), with sub kept as the legacy key to re-key old bindings.
func TestMicrosoftUserInfoFromClaims_KeysOnOID(t *testing.T) {
	c := msClaims("real@corp.com", boolPtr(true))
	c.OID = "oid-1"
	info, err := microsoftUserInfoFromClaims(c)
	if err != nil {
		t.Fatal(err)
	}
	if info.Subject != "oid-1" || info.LegacySubject != "sub-1" {
		t.Fatalf("subject=%q legacy=%q, want oid-1 / sub-1", info.Subject, info.LegacySubject)
	}
	// No oid (should not happen with Entra): sub is the key, nothing to re-key.
	info, _ = microsoftUserInfoFromClaims(msClaims("real@corp.com", boolPtr(true)))
	if info.Subject != "sub-1" || info.LegacySubject != "" {
		t.Fatalf("subject=%q legacy=%q, want sub-1 / empty", info.Subject, info.LegacySubject)
	}
}

// An account bound under the old key (sub) is found by its oid login and
// re-keyed, so the next login matches on oid directly.
func TestOAuthFindOrCreate_RekeysLegacyMicrosoftSubject(t *testing.T) {
	u, _ := userdom.NewOAuthUser("u@corp.com", "U", "", userdom.AuthProviderMicrosoft)
	repo := &fakeUserRepo{byEmail: u}
	ids := newMemIdentities()
	ids.bindTo(u, "iss-A", "sub-1")
	s := &OAuthService{userRepo: repo, identities: ids, logger: logger.NewNop()}

	got, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "u@corp.com", Issuer: "iss-A", Subject: "oid-1", LegacySubject: "sub-1"},
		OAuthProviderMicrosoft)
	if err != nil || got == nil || got.ID() != u.ID() {
		t.Fatalf("legacy-bound account should be found: %v", err)
	}
	if keys := ids.keysOf(u.ID()); len(keys) != 1 || keys[0].Subject != "oid-1" {
		t.Fatalf("binding should be re-keyed to oid-1, got %+v", keys)
	}
}
