package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
)

// The pending link against the real stores: users, user_identities and the
// sessions row whose sign-in time decides whether the confirm is allowed.
func TestPendingLink_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer sqlDB.Close()
	if err := sqlDB.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	db := &postgres.DB{DB: sqlDB}
	ctx := context.Background()

	users := postgres.NewUserRepository(db)
	sessions := postgres.NewSessionRepository(sqlDB)
	revoker := &fakeRevoker{}
	svc := NewOAuthService(users, sessions, postgres.NewRefreshTokenRepository(sqlDB),
		config.OAuthConfig{Enabled: true, Google: config.OAuthProviderConfig{Enabled: true, ClientID: "c", ClientSecret: "s"}},
		config.AuthConfig{JWTSecret: "test-secret-test-secret-test-secret!", AccessTokenDuration: time.Minute,
			RefreshTokenDuration: time.Hour, SessionDuration: time.Hour},
		logger.NewNop())
	svc.SetIdentityRepo(postgres.NewUserIdentityRepository(db))
	svc.SetSessionRevoker(revoker)
	svc.SetSignupPolicy(signupdom.Static{Mode: signupdom.ModeAdminOnly})
	// The real proof check against the real session rows: these accounts
	// have a password and no TOTP, so the password is the proof.
	authCfg := config.AuthConfig{JWTSecret: "test-secret-test-secret-test-secret!", AccessTokenDuration: time.Minute,
		RefreshTokenDuration: time.Hour, SessionDuration: time.Hour}
	svc.SetLinkProofVerifier(NewAuthService(users, sessions, postgres.NewRefreshTokenRepository(sqlDB),
		postgres.NewTenantRepository(db), nil, authCfg, logger.NewNop()))
	const dbPassword = "Pending-link-db-pw-1"
	dbHash, err := password.New(password.WithCost(4)).Hash(dbPassword)
	if err != nil {
		t.Fatal(err)
	}
	dbProof := StepUpProof{Password: dbPassword}

	newAccount := func(t *testing.T) *userdom.User {
		t.Helper()
		u, err := userdom.NewLocalUser("pl-"+shared.NewID().String()+"@gmail.com", "P", dbHash)
		if err != nil {
			t.Fatal(err)
		}
		u.VerifyEmail()
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		t.Cleanup(func() {
			_, _ = sqlDB.Exec(`DELETE FROM user_identities WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM sessions WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM users WHERE id = $1`, u.ID().String())
		})
		return u
	}
	signIn := func(t *testing.T, u *userdom.User) string {
		t.Helper()
		id := shared.NewID()
		s, err := sessiondom.NewWithID(id, u.ID(), "tok-"+id.String(), "127.0.0.1", "test", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := sessions.Create(ctx, s); err != nil {
			t.Fatalf("create session: %v", err)
		}
		return id.String()
	}
	identities := func(u *userdom.User) int {
		var n int
		if err := sqlDB.QueryRow(`SELECT count(*) FROM user_identities WHERE user_id = $1`, u.ID().String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	collideDB := func(t *testing.T, u *userdom.User, sub string) string {
		t.Helper()
		_, err := svc.findOrCreateUser(ctx, googleInfo(u.Email(), sub, ""), OAuthProviderGoogle)
		var pending *PendingLinkError
		if !errors.As(err, &pending) {
			t.Fatalf("want a pending link, got %v", err)
		}
		if identities(u) != 0 {
			t.Fatal("the refused sign-in linked the identity")
		}
		return pending.Token
	}

	t.Run("signed in after the refusal: linked", func(t *testing.T) {
		u := newAccount(t)
		tok := collideDB(t, u, "db-"+shared.NewID().String())
		sid := signIn(t, u)
		if _, err := svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: u.ID().String(), SessionID: sid, Token: tok, Proof: dbProof}); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		if identities(u) != 1 {
			t.Fatal("identity not stored")
		}
	})
	t.Run("session from before the refusal: refused", func(t *testing.T) {
		u := newAccount(t)
		sid := signIn(t, u)
		if _, err := sqlDB.Exec(`UPDATE sessions SET created_at = now() - interval '1 hour', step_up_at = NULL WHERE id = $1`, sid); err != nil {
			t.Fatal(err)
		}
		tok := collideDB(t, u, "db-"+shared.NewID().String())
		if _, err := svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: u.ID().String(), SessionID: sid, Token: tok, Proof: dbProof}); !errors.Is(err, ErrPendingLinkNeedsSignIn) {
			t.Fatalf("got %v", err)
		}
		if identities(u) != 0 {
			t.Fatal("linked")
		}
	})
	t.Run("another account's session: refused", func(t *testing.T) {
		victim := newAccount(t)
		attacker := newAccount(t)
		tok := collideDB(t, victim, "db-"+shared.NewID().String())
		sid := signIn(t, attacker)
		if _, err := svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: attacker.ID().String(), SessionID: sid, Token: tok, Proof: dbProof}); !errors.Is(err, ErrPendingLinkInvalid) {
			t.Fatalf("got %v", err)
		}
		// The victim's user id with the attacker's session id: that session
		// is not the victim's, so no proof can be spent on it.
		if _, err := svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: victim.ID().String(), SessionID: sid, Token: tok, Proof: dbProof}); !errors.Is(err, ErrLinkProofUnavailable) {
			t.Fatalf("another account's session: %v", err)
		}
		if identities(victim) != 0 || identities(attacker) != 0 {
			t.Fatal("linked")
		}
	})
	t.Run("the sign-in alone does not link; a wrong password keeps the pending link", func(t *testing.T) {
		u := newAccount(t)
		tok := collideDB(t, u, "db-"+shared.NewID().String())
		sid := signIn(t, u)
		if _, err := svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: u.ID().String(), SessionID: sid, Token: tok}); !errors.Is(err, ErrLinkProofRequired) {
			t.Fatalf("no proof: %v", err)
		}
		if _, err := svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: u.ID().String(), SessionID: sid, Token: tok, Proof: StepUpProof{Password: "wrong"}}); !errors.Is(err, ErrLinkProofFailed) {
			t.Fatalf("wrong password: %v", err)
		}
		var failed int
		if err := sqlDB.QueryRow(`SELECT failed_login_attempts FROM users WHERE id = $1`, u.ID().String()).Scan(&failed); err != nil {
			t.Fatal(err)
		}
		if failed != 1 {
			t.Fatalf("a wrong password must count towards the lockout: %d", failed)
		}
		if identities(u) != 0 {
			t.Fatal("linked without a proof")
		}
		if _, err := svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: u.ID().String(), SessionID: sid, Token: tok, Proof: dbProof}); err != nil {
			t.Fatalf("the pending link must survive a missing or wrong proof: %v", err)
		}
		if identities(u) != 1 {
			t.Fatal("identity not stored")
		}
	})
	t.Run("session of another account named with this account: refused", func(t *testing.T) {
		u := newAccount(t)
		other := newAccount(t)
		tok := collideDB(t, u, "db-"+shared.NewID().String())
		sid := signIn(t, other)
		if _, err := svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: u.ID().String(), SessionID: sid, Token: tok, Proof: dbProof}); !errors.Is(err, ErrLinkProofUnavailable) {
			t.Fatalf("got %v", err)
		}
		if identities(u) != 0 {
			t.Fatal("linked")
		}
	})
}
