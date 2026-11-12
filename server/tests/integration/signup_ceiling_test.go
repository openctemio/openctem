package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	signupapp "github.com/openctemio/openctem/api/internal/app/signup"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// withStoredSignupPolicy stores p as the sign-up policy row (as a console save
// on an earlier, open deployment would have) and restores the row afterwards.
func withStoredSignupPolicy(t *testing.T, db *postgres.DB, p signupdom.Policy) *postgres.SignupPolicyRepository {
	t.Helper()
	ctx := context.Background()
	repo := postgres.NewSignupPolicyRepository(db)
	before, berr := repo.Get(ctx)
	if _, err := db.ExecContext(ctx, `DELETE FROM platform_settings WHERE key = $1`, signupdom.SettingKey); err != nil {
		t.Fatalf("clean sign-up policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_settings WHERE key = $1`, signupdom.SettingKey)
		if berr == nil {
			_, _ = repo.CreateIfAbsent(context.Background(), before)
		}
	})
	if _, err := repo.CreateIfAbsent(ctx, signupdom.State{
		Policy: p, Version: 1, Source: signupdom.SourceConsole, UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("store sign-up policy: %v", err)
	}
	return repo
}

// The deployment ceiling wins over the stored console policy, end to end on
// the database: a self_service policy stored while the deployment was open
// admits nobody once SIGNUP_MODE is disabled (no account row is written),
// creates no organization, and the console cannot store it again.
func TestSignupCeiling_ClampsStoredPolicy(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	repo := withStoredSignupPolicy(t, db, signupdom.Policy{Mode: signupdom.ModeSelfService})

	for _, ceiling := range []string{config.SignupModeDisabled, config.SignupModeDomain} {
		t.Run(ceiling, func(t *testing.T) {
			policy := signupapp.NewService(repo, nil, nil, nil, logger.NewNop())
			policy.SetCeiling(signupdom.Ceiling(ceiling))
			if policy.Current(ctx).AllowsSelfService() {
				t.Fatalf("SIGNUP_MODE=%s must clamp the stored self_service policy", ceiling)
			}

			svc := orgAuthService(db, ceiling)
			svc.SetSignupPolicy(policy)
			email := "ceiling-" + uuid.NewString()[:8] + "@example.com"
			_, err := svc.Register(ctx, authapp.RegisterInput{Email: email, Password: "Correct-Horse-9!", Name: "Stranger"})
			if !errors.Is(err, authapp.ErrSignupNotAvailable) {
				t.Fatalf("register must be refused, got %v", err)
			}
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = $1`, email).Scan(&n); err != nil || n != 0 {
				t.Fatalf("a refused sign-up writes no account: %d %v", n, err)
			}

			// An existing account cannot create an organization either.
			_, refresh := orgSelfServiceUser(t, db, svc)
			_, err = svc.CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{
				RefreshToken: refresh, TeamName: "Sneaky", TeamSlug: "sneaky-" + uuid.NewString()[:8],
			})
			if !errors.Is(err, authapp.ErrTenantCreationDisabled) {
				t.Fatalf("create-first-team must be refused, got %v", err)
			}

			// The console cannot store self_service under this ceiling.
			actor, aerr := admin.NewAdminUser("ceiling-"+uuid.NewString()[:8]+"@op.example", "Op", admin.AdminRoleSuperAdmin, nil)
			if aerr != nil {
				t.Fatal(aerr)
			}
			st, _ := repo.Get(ctx)
			if _, err := policy.Update(ctx, actor, signupdom.Policy{Mode: signupdom.ModeSelfService}, st.Version, "", ""); !errors.Is(err, signupdom.ErrLockedByDeployment) {
				t.Fatalf("console save above the ceiling must be refused, got %v", err)
			}
			if after, _ := repo.Get(ctx); after.Version != st.Version {
				t.Fatalf("a refused save writes nothing: version %d -> %d", st.Version, after.Version)
			}
		})
	}

	// Under SIGNUP_MODE=open the same stored policy is in force.
	open := signupapp.NewService(repo, nil, nil, nil, logger.NewNop())
	open.SetCeiling(signupdom.CeilingOpen)
	if !open.Current(ctx).AllowsSelfService() {
		t.Fatal("SIGNUP_MODE=open keeps the stored self_service policy")
	}
}
