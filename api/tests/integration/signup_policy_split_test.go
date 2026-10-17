package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	signupapp "github.com/openctemio/openctem/api/internal/app/signup"
	"github.com/openctemio/openctem/api/internal/config"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The two decisions of the sign-up policy (who may create an account, who
// may create an organization), each clamped to the ceiling, across the paths
// that write: register and create-first-team. A refusal writes no users row.
func TestSignupPolicySplit_PathByPolicy(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()

	cases := []struct {
		name         string
		ceiling      string
		stored       signupdom.Policy
		registerOK   bool
		createTeamOK bool
	}{
		{"disabled ceiling, everything stored open", config.SignupModeDisabled,
			signupdom.Policy{Mode: signupdom.ModeSelfService, Accounts: signupdom.AccountsOpen}, false, false},
		{"domain ceiling, open stored: clamped to domain, stranger refused", config.SignupModeDomain,
			signupdom.Policy{Mode: signupdom.ModeSelfService, Accounts: signupdom.AccountsOpen}, false, false},
		{"domain ceiling, domain accounts: stranger (no joinable domain) refused", config.SignupModeDomain,
			signupdom.Policy{Mode: signupdom.ModeAdminOnly, Accounts: signupdom.AccountsDomain}, false, false},
		{"open ceiling, accounts open, organizations admin only", config.SignupModeOpen,
			signupdom.Policy{Mode: signupdom.ModeAdminOnly, Accounts: signupdom.AccountsOpen}, true, false},
		{"open ceiling, accounts closed", config.SignupModeOpen,
			signupdom.Policy{Mode: signupdom.ModeAdminOnly, Accounts: signupdom.AccountsClosed}, false, false},
		{"open ceiling, self-service", config.SignupModeOpen,
			signupdom.Policy{Mode: signupdom.ModeSelfService, Accounts: signupdom.AccountsOpen}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := withStoredSignupPolicy(t, db, tc.stored)
			policy := signupapp.NewService(repo, nil, nil, nil, logger.NewNop())
			policy.SetCeiling(signupdom.Ceiling(tc.ceiling))
			svc := orgAuthService(db, tc.ceiling)
			svc.SetSignupPolicy(policy)

			email := "split-" + uuid.NewString()[:8] + "@example.com"
			t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE email = $1`, email) })
			_, err := svc.Register(ctx, authapp.RegisterInput{Email: email, Password: "Correct-Horse-9!", Name: "S"})
			var n int
			if qerr := db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = $1`, email).Scan(&n); qerr != nil {
				t.Fatal(qerr)
			}
			if tc.registerOK {
				if err != nil || n != 1 {
					t.Fatalf("register must create the account: %v (rows %d)", err, n)
				}
			} else if !errors.Is(err, authapp.ErrSignupNotAvailable) || n != 0 {
				t.Fatalf("register must be refused with nothing written: %v (rows %d)", err, n)
			}

			_, refresh := orgSelfServiceUser(t, db, svc)
			slug := "split-" + uuid.NewString()[:8]
			t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, slug) })
			_, err = svc.CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{RefreshToken: refresh, TeamName: "Split", TeamSlug: slug})
			if tc.createTeamOK != (err == nil) {
				t.Fatalf("create-first-team: want ok=%v, got %v", tc.createTeamOK, err)
			}
			if !tc.createTeamOK {
				var orgs int
				_ = db.QueryRow(`SELECT COUNT(*) FROM tenants WHERE slug = $1`, slug).Scan(&orgs)
				if orgs != 0 {
					t.Fatal("a refused create-first-team writes no organization")
				}
			}
		})
	}
}
