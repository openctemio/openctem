package auth

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The refresh-token rotation grace against the real stores (users, tenants,
// memberships, sessions, refresh_tokens, audit_logs). Parallel refreshes of
// one token by the same client share one successor; every other reuse still
// ends the session and is audited.
func TestRefreshRotationGrace_DB(t *testing.T) {
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
	tenants := postgres.NewTenantRepository(db)
	tokens := postgres.NewRefreshTokenRepository(sqlDB)
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())

	newService := func(grace time.Duration) *AuthService {
		cfg := config.AuthConfig{JWTSecret: "test-secret-test-secret-test-secret!", AccessTokenDuration: time.Minute,
			RefreshTokenDuration: time.Hour, SessionDuration: time.Hour, RefreshReuseGrace: grace}
		return NewAuthService(users, sessions, tokens, tenants, auditSvc, cfg, logger.NewNop())
	}

	newMember := func(t *testing.T) (*userdom.User, string) {
		t.Helper()
		u, err := userdom.NewLocalUser("grace-"+shared.NewID().String()+"@example.com", "G", "x")
		if err != nil {
			t.Fatal(err)
		}
		u.VerifyEmail()
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		tn, err := tenantdom.NewTenant("Grace org", "grace-"+shared.NewID().String()[24:], u.ID().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := tenants.Create(ctx, tn); err != nil {
			t.Fatalf("create tenant: %v", err)
		}
		ms, err := tenantdom.NewMembership(u.ID(), tn.ID(), tenantdom.Role("member"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := tenants.CreateMembership(ctx, ms); err != nil {
			t.Fatalf("create membership: %v", err)
		}
		t.Cleanup(func() {
			_, _ = sqlDB.Exec(`DELETE FROM audit_logs WHERE actor_id = $1`, u.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM refresh_tokens WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM sessions WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM tenant_members WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM tenants WHERE id = $1`, tn.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM users WHERE id = $1`, u.ID().String())
		})
		return u, tn.ID().String()
	}

	// signIn opens a session and stores its first refresh token.
	signIn := func(t *testing.T, svc *AuthService, u *userdom.User) (sid shared.ID, rt string) {
		t.Helper()
		sid = shared.NewID()
		s, err := sessiondom.NewWithID(sid, u.ID(), "tok-"+sid.String(), "127.0.0.1", "test", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := sessions.Create(ctx, s); err != nil {
			t.Fatalf("create session: %v", err)
		}
		rt, _, err = svc.tokenGenerator.GenerateGlobalRefreshToken(u.ID().String(), u.Email(), u.Name(), sid.String())
		if err != nil {
			t.Fatal(err)
		}
		row, err := sessiondom.NewRefreshToken(u.ID(), sid, rt, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := tokens.Create(ctx, row); err != nil {
			t.Fatalf("create refresh token: %v", err)
		}
		return sid, rt
	}

	refresh := func(svc *AuthService, rt, tenantID, ua string) (*RefreshTokenResult, error) {
		return svc.RefreshToken(ctx, RefreshTokenInput{RefreshToken: rt, TenantID: tenantID, UserAgent: ua})
	}
	sessionActive := func(t *testing.T, sid shared.ID) bool {
		t.Helper()
		s, err := sessions.GetByID(ctx, sid)
		if err != nil {
			t.Fatalf("get session: %v", err)
		}
		return s.IsActive()
	}
	reuseAudits := func(t *testing.T, sid shared.ID) int {
		t.Helper()
		var n int
		if err := sqlDB.QueryRow(`SELECT count(*) FROM audit_logs
			WHERE action = 'auth.session_revoked' AND session_id = $1
			  AND metadata->>'reason' = 'refresh_token_reuse'`, sid.String()).Scan(&n); err != nil {
			t.Fatalf("count audits: %v", err)
		}
		return n
	}
	familySize := func(t *testing.T, sid shared.ID) int {
		t.Helper()
		var n int
		if err := sqlDB.QueryRow(`SELECT count(*) FROM refresh_tokens WHERE session_id = $1`, sid.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	const ua = "node"

	t.Run("parallel refreshes within the grace share one successor", func(t *testing.T) {
		svc := newService(30 * time.Second)
		u, tid := newMember(t)
		sid, rt := signIn(t, svc, u)

		const n = 8
		results := make([]*RefreshTokenResult, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i], errs[i] = refresh(svc, rt, tid, ua)
			}()
		}
		wg.Wait()
		for i := range n {
			if errs[i] != nil {
				t.Fatalf("refresh %d: %v", i, errs[i])
			}
			if results[i].RefreshToken != results[0].RefreshToken {
				t.Fatalf("refresh %d got a different successor: the family forked", i)
			}
			if results[i].AccessToken == "" || results[i].TenantID != tid {
				t.Fatalf("refresh %d: missing or mis-scoped access token", i)
			}
		}
		if got := familySize(t, sid); got != 2 {
			t.Fatalf("want the presented token and one successor, got %d rows", got)
		}
		if !sessionActive(t, sid) || reuseAudits(t, sid) != 0 {
			t.Fatal("parallel refreshes of one client must not end the session")
		}

		// The successor rotates normally; the chain continues.
		next, err := refresh(svc, results[0].RefreshToken, tid, ua)
		if err != nil {
			t.Fatalf("successor refresh: %v", err)
		}
		if next.RefreshToken == results[0].RefreshToken {
			t.Fatal("the successor must rotate")
		}

		// The original token is now two rotations old: no grace, the session
		// ends and the reuse is audited.
		if _, err := refresh(svc, rt, tid, ua); !errors.Is(err, sessiondom.ErrRefreshTokenUsed) {
			t.Fatalf("older token: want ErrRefreshTokenUsed, got %v", err)
		}
		if sessionActive(t, sid) {
			t.Fatal("an older token must end the session")
		}
		if reuseAudits(t, sid) != 1 {
			t.Fatal("the reuse must be audited once")
		}
		if _, err := refresh(svc, next.RefreshToken, tid, ua); err == nil {
			t.Fatal("after the reuse every token of the session is revoked")
		}
	})

	t.Run("after the grace the replaced token ends the session", func(t *testing.T) {
		svc := newService(30 * time.Second)
		u, tid := newMember(t)
		sid, rt := signIn(t, svc, u)
		if _, err := refresh(svc, rt, tid, ua); err != nil {
			t.Fatal(err)
		}
		if _, err := sqlDB.Exec(`UPDATE refresh_tokens SET used_at = NOW() - interval '31 seconds'
			WHERE session_id = $1 AND used_at IS NOT NULL`, sid.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := refresh(svc, rt, tid, ua); !errors.Is(err, sessiondom.ErrRefreshTokenUsed) {
			t.Fatalf("want ErrRefreshTokenUsed, got %v", err)
		}
		if sessionActive(t, sid) || reuseAudits(t, sid) != 1 {
			t.Fatal("a reuse after the grace must end the session and be audited")
		}
	})

	t.Run("another client within the grace ends the session", func(t *testing.T) {
		svc := newService(30 * time.Second)
		u, tid := newMember(t)
		sidA, rtA := signIn(t, svc, u)
		sidB, _ := signIn(t, svc, u)
		if _, err := refresh(svc, rtA, tid, ua); err != nil {
			t.Fatal(err)
		}
		if _, err := refresh(svc, rtA, tid, "curl/8.0"); !errors.Is(err, sessiondom.ErrRefreshTokenUsed) {
			t.Fatalf("want ErrRefreshTokenUsed, got %v", err)
		}
		if sessionActive(t, sidA) || reuseAudits(t, sidA) != 1 {
			t.Fatal("a different client must end the session and be audited")
		}
		// The user's other session is untouched.
		if !sessionActive(t, sidB) || reuseAudits(t, sidB) != 0 {
			t.Fatal("a reuse in one session must not end another session")
		}
	})

	t.Run("a successor of another session never qualifies", func(t *testing.T) {
		svc := newService(30 * time.Second)
		u, tid := newMember(t)
		sidA, rtA := signIn(t, svc, u)
		sidB, rtB := signIn(t, svc, u)
		if _, err := refresh(svc, rtA, tid, ua); err != nil {
			t.Fatal(err)
		}
		if _, err := refresh(svc, rtB, tid, ua); err != nil {
			t.Fatal(err)
		}
		// Point A's rotation record at B's live successor.
		if _, err := sqlDB.Exec(`UPDATE refresh_tokens SET successor_id =
				(SELECT id FROM refresh_tokens WHERE session_id = $2 AND used_at IS NULL)
			WHERE session_id = $1 AND used_at IS NOT NULL`, sidA.String(), sidB.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := refresh(svc, rtA, tid, ua); !errors.Is(err, sessiondom.ErrRefreshTokenUsed) {
			t.Fatalf("want ErrRefreshTokenUsed, got %v", err)
		}
		if sessionActive(t, sidA) {
			t.Fatal("session A must end")
		}
		if !sessionActive(t, sidB) {
			t.Fatal("session B must stay")
		}
	})

	t.Run("the grace never scopes a token to an organization the user is not in", func(t *testing.T) {
		svc := newService(30 * time.Second)
		u, tid := newMember(t)
		_, otherTenant := newMember(t) // an organization u is not a member of
		sid, rt := signIn(t, svc, u)
		first, err := refresh(svc, rt, tid, ua)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := refresh(svc, rt, otherTenant, ua); !errors.Is(err, ErrTenantAccessDenied) {
			t.Fatalf("want ErrTenantAccessDenied, got %v", err)
		}
		// A refusal is not a reuse: the session and the successor stay.
		if !sessionActive(t, sid) {
			t.Fatal("a refused organization must not end the session")
		}
		again, err := refresh(svc, rt, tid, ua)
		if err != nil || again.RefreshToken != first.RefreshToken {
			t.Fatalf("the grace must still hand out the same successor, err=%v", err)
		}
	})

	t.Run("grace off: the race loser ends the session", func(t *testing.T) {
		svc := newService(0)
		u, tid := newMember(t)
		sid, rt := signIn(t, svc, u)
		if _, err := refresh(svc, rt, tid, ua); err != nil {
			t.Fatal(err)
		}
		if _, err := refresh(svc, rt, tid, ua); !errors.Is(err, sessiondom.ErrRefreshTokenUsed) {
			t.Fatalf("want ErrRefreshTokenUsed, got %v", err)
		}
		if sessionActive(t, sid) || reuseAudits(t, sid) != 1 {
			t.Fatal("with the grace off any reuse ends the session")
		}
	})

	t.Run("a revoked session gets no grace", func(t *testing.T) {
		svc := newService(30 * time.Second)
		u, tid := newMember(t)
		sid, rt := signIn(t, svc, u)
		if _, err := refresh(svc, rt, tid, ua); err != nil {
			t.Fatal(err)
		}
		if err := svc.Logout(ctx, sid.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := refresh(svc, rt, tid, ua); err == nil {
			t.Fatal("a signed-out session must not be refreshed through the grace")
		}
	})
}
