package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Social sign-in that would create an account goes through the one
// admission rule (signup.Admit). A refusal writes no account.

type fakeInvitations struct {
	invited map[string]bool
	err     error
}

func (f fakeInvitations) HasPendingInvitationForEmail(_ context.Context, email string) (bool, error) {
	return f.invited[email], f.err
}

func TestOAuthSignupAdmission(t *testing.T) {
	adminOnly := signupdom.Static{Mode: signupdom.ModeAdminOnly}
	selfService := signupdom.Static{Mode: signupdom.ModeSelfService}
	cases := []struct {
		name        string
		policy      signupdom.PolicySource
		cfg         config.AuthConfig
		invitations InvitationLookup
		wantCreated bool
		email       string
	}{
		{"self_service, disposable email", selfService, config.AuthConfig{}, fakeInvitations{}, false, "x@mailinator.com"},
		{"admin_only, stranger", adminOnly, config.AuthConfig{}, fakeInvitations{}, false, ""},
		{"admin_only, invited", adminOnly, config.AuthConfig{}, fakeInvitations{invited: map[string]bool{"new@corp.com": true}}, true, ""},
		{"admin_only, invitation lookup fails", adminOnly, config.AuthConfig{}, fakeInvitations{err: errors.New("db down")}, false, ""},
		{"admin_only, no lookup wired", adminOnly, config.AuthConfig{}, nil, false, ""},
		{"self_service, stranger", selfService, config.AuthConfig{}, fakeInvitations{}, true, ""},
		// The console policy wins over the environment.
		{"console admin_only over env self_service", adminOnly, config.AuthConfig{TenantCreationMode: config.TenantCreationSelfService}, fakeInvitations{}, false, ""},
		// Without the console policy wired, the environment seed decides.
		{"no policy wired, env admin_only", nil, config.AuthConfig{}, fakeInvitations{}, false, ""},
		{"no policy wired, env self_service", nil, config.AuthConfig{TenantCreationMode: config.TenantCreationSelfService}, fakeInvitations{}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := &fakeUserRepo{}
			svc := &OAuthService{userRepo: repo, logger: logger.NewNop(), authConfig: c.cfg}
			if c.policy != nil {
				svc.SetSignupPolicy(c.policy)
			}
			if c.invitations != nil {
				svc.SetInvitationLookup(c.invitations)
			}
			email := "new@corp.com"
			if c.email != "" {
				email = c.email
			}
			u, err := svc.findOrCreateUser(context.Background(),
				&OAuthUserInfo{Email: email, Name: "New"}, OAuthProviderGoogle)
			if c.wantCreated {
				if err != nil || u == nil || repo.created == nil {
					t.Fatalf("expected the account to be created, got user=%v err=%v", u, err)
				}
				return
			}
			if !errors.Is(err, ErrSignupNotAvailable) {
				t.Fatalf("expected ErrSignupNotAvailable, got %v", err)
			}
			if repo.created != nil {
				t.Fatal("a refused sign-up must not create an account")
			}
		})
	}
}
