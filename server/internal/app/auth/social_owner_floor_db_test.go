package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/platformmfa"
	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/crypto"
	"github.com/openctemio/openctem/server/pkg/domain/mfa"
	sessiondom "github.com/openctemio/openctem/server/pkg/domain/session"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/server/pkg/domain/user"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/totp"
)

type fixedFloor struct{ p platformmfa.Policy }

func (f fixedFloor) Policy(context.Context) (platformmfa.Policy, error) { return f.p, nil }

// A person who signed up through a social provider owns a personal
// organization while the platform floor covers owners and the grace is over.
// The organization refuses the session with MFA_ENROLLMENT_REQUIRED (a reason,
// not a sign-out), the person enrolls a second factor in place within the
// window, and the session that step opens reaches the organization. A session
// older than the window must sign in again first. This is why the social
// sign-in no longer holds the personal organization back.
func TestSocialOwnerUnderFloor_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer sqlDB.Close()
	if err := sqlDB.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	db := &postgres.DB{DB: sqlDB}
	ctx := context.Background()

	users := postgres.NewUserRepository(db)
	sessions := postgres.NewSessionRepository(sqlDB)
	refresh := postgres.NewRefreshTokenRepository(sqlDB)
	tenants := postgres.NewTenantRepository(db)
	cfg := config.AuthConfig{JWTSecret: "test-secret-test-secret-test-secret!", AccessTokenDuration: time.Minute,
		RefreshTokenDuration: time.Hour, SessionDuration: time.Hour}
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	svc := NewAuthService(users, sessions, refresh, tenants, auditSvc, cfg, logger.NewNop())
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc.SetMFA(postgres.NewUserMFARepository(db), cipher, "OpenCTEM")
	// The floor covers owners; the account's new-account grace is over below.
	svc.SetMFAFloor(fixedFloor{platformmfa.Policy{Floor: tenantdom.MFAFloorAdmins}}, nil)

	// socialOwner is a social-only account that owns its organization, with a
	// session signed in `age` ago.
	socialOwner := func(t *testing.T, age time.Duration) (org *tenantdom.Tenant, rt string, sid shared.ID) {
		t.Helper()
		u, err := userdom.NewOAuthUser("sof-"+shared.NewID().String()+"@example.com", "Sam", "", userdom.AuthProviderGoogle)
		if err != nil {
			t.Fatal(err)
		}
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		org, err = tenantdom.NewTenant("Sam's organization", "sof-"+shared.NewID().String()[24:], u.ID().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := tenants.Create(ctx, org); err != nil {
			t.Fatalf("create tenant: %v", err)
		}
		ms, err := tenantdom.NewOwnerMembership(u.ID(), org.ID())
		if err != nil {
			t.Fatal(err)
		}
		if err := tenants.CreateMembership(ctx, ms); err != nil {
			t.Fatalf("create membership: %v", err)
		}
		t.Cleanup(func() {
			for _, q := range []string{
				`DELETE FROM user_mfa_recovery_codes WHERE user_id = $1`,
				`DELETE FROM user_mfa_challenges WHERE user_id = $1`,
				`DELETE FROM user_mfa WHERE user_id = $1`,
				`DELETE FROM sessions WHERE user_id = $1`,
				`DELETE FROM tenant_members WHERE user_id = $1`,
			} {
				_, _ = sqlDB.ExecContext(context.Background(), q, u.ID().String())
			}
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, org.ID().String())
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, u.ID().String())
		})
		sess, err := sessiondom.New(u.ID(), "access-"+shared.NewID().String(), "127.0.0.1", "test", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		sess.SetAuthMethod(sessiondom.AuthMethodSSO)
		if err := sessions.Create(ctx, sess); err != nil {
			t.Fatalf("create session: %v", err)
		}
		if age > 0 {
			if _, err := sqlDB.ExecContext(context.Background(), `UPDATE sessions SET created_at = $2 WHERE id = $1`, sess.ID().String(), time.Now().Add(-age)); err != nil {
				t.Fatal(err)
			}
		}
		// The account is past the new-account grace.
		if _, err := sqlDB.ExecContext(context.Background(), `UPDATE users SET created_at = now() - interval '90 days' WHERE id = $1`, u.ID().String()); err != nil {
			t.Fatal(err)
		}
		rt, _, err = svc.tokenGenerator.GenerateGlobalRefreshToken(u.ID().String(), u.Email(), u.Name(), sess.ID().String())
		if err != nil {
			t.Fatal(err)
		}
		stored, err := sessiondom.NewRefreshToken(u.ID(), sess.ID(), rt, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := refresh.Create(ctx, stored); err != nil {
			t.Fatalf("create refresh token: %v", err)
		}
		return org, rt, sess.ID()
	}

	t.Run("fresh session: refused, kept, enrolls in place, then opens the organization", func(t *testing.T) {
		org, rt, sid := socialOwner(t, 0)
		if _, err := svc.ExchangeToken(ctx, ExchangeTokenInput{RefreshToken: rt, TenantID: org.ID().String()}); !errors.Is(err, ErrMFAEnrollmentRequired) {
			t.Fatalf("want ErrMFAEnrollmentRequired, got %v", err)
		}
		if s, err := sessions.GetByID(ctx, sid); err != nil || !s.IsActive() {
			t.Fatalf("the refusal must keep the session: %v", err)
		}
		info, err := svc.SessionMFAChallenge(ctx, rt, "127.0.0.1", "test")
		if err != nil || info.Purpose != mfa.PurposeEnroll {
			t.Fatalf("enroll challenge: %+v %v", info, err)
		}
		setup, err := svc.BeginMFAEnrollmentFromChallenge(ctx, info.Token)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		code, _ := totp.Code(setup.Secret, time.Now())
		res, _, err := svc.CompleteMFAEnrollmentFromChallenge(ctx, CompleteMFAEnrollmentInput{Token: info.Token, Code: code, IPAddress: "127.0.0.1", UserAgent: "test"})
		if err != nil || res == nil || res.RefreshToken == "" {
			t.Fatalf("complete: %+v %v", res, err)
		}
		if _, err := svc.ExchangeToken(ctx, ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: org.ID().String()}); err != nil {
			t.Fatalf("the session opened by the second step must reach the organization: %v", err)
		}
	})

	t.Run("a session older than the window must sign in again", func(t *testing.T) {
		org, rt, _ := socialOwner(t, sessionEnrollFreshness+time.Minute)
		if _, err := svc.ExchangeToken(ctx, ExchangeTokenInput{RefreshToken: rt, TenantID: org.ID().String()}); !errors.Is(err, ErrMFAEnrollmentRequired) {
			t.Fatalf("want ErrMFAEnrollmentRequired, got %v", err)
		}
		if _, err := svc.SessionMFAChallenge(ctx, rt, "127.0.0.1", "test"); !errors.Is(err, ErrReauthRequired) {
			t.Fatalf("want ErrReauthRequired, got %v", err)
		}
	})
}
