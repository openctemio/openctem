package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
	"github.com/openctemio/openctem/api/pkg/totp"
)

// Turning two-factor off, and replacing the authenticator, against the real
// stores: users, tenants and memberships (the organization's requirement),
// user_mfa and its recovery codes, sessions and refresh tokens.
func TestMFAPolicyHold_DB(t *testing.T) {
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
	mfaRepo := postgres.NewUserMFARepository(db)
	cfg := config.AuthConfig{JWTSecret: "test-secret-test-secret-test-secret!", AccessTokenDuration: time.Minute,
		RefreshTokenDuration: time.Hour, SessionDuration: time.Hour}
	svc := NewAuthService(users, sessions, postgres.NewRefreshTokenRepository(sqlDB), tenants, nil, cfg, logger.NewNop())
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc.SetMFA(mfaRepo, cipher, "OpenCTEM")
	svc.passwordHasher = password.New(password.WithCost(4))

	const pw = "Policy-hold-db-pw-1"
	hash, err := svc.passwordHasher.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}

	newAccount := func(t *testing.T) *userdom.User {
		t.Helper()
		u, err := userdom.NewLocalUser("mph-"+shared.NewID().String()+"@example.com", "P", hash)
		if err != nil {
			t.Fatal(err)
		}
		u.VerifyEmail()
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		t.Cleanup(func() {
			_, _ = sqlDB.Exec(`DELETE FROM user_mfa_recovery_codes WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM user_mfa WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM sessions WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM tenant_members WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM users WHERE id = $1`, u.ID().String())
		})
		return u
	}
	joinOrg := func(t *testing.T, u *userdom.User, name string, required bool) {
		t.Helper()
		tn, err := tenantdom.NewTenant(name, "mph-"+shared.NewID().String()[24:], u.ID().String())
		if err != nil {
			t.Fatal(err)
		}
		st := tn.TypedSettings()
		st.Security.MFARequired = required
		st.Security.MFARequiredForAdmins = false
		if err := tn.UpdateSettings(st); err != nil {
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
			_, _ = sqlDB.Exec(`DELETE FROM tenant_members WHERE tenant_id = $1`, tn.ID().String())
			_, _ = sqlDB.Exec(`DELETE FROM tenants WHERE id = $1`, tn.ID().String())
		})
	}
	enroll := func(t *testing.T, u *userdom.User) (string, []string) {
		t.Helper()
		setup, err := svc.BeginMFASetup(ctx, u.ID().String())
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		code, _ := totp.Code(setup.Secret, time.Now())
		codes, err := svc.EnableMFA(ctx, auditapp.AuditContext{}, u.ID().String(), pw, code)
		if err != nil {
			t.Fatalf("enable: %v", err)
		}
		// Let the same 30 s window give another usable code.
		if _, err := sqlDB.Exec(`UPDATE user_mfa SET last_used_step = 0 WHERE user_id = $1`, u.ID().String()); err != nil {
			t.Fatal(err)
		}
		return setup.Secret, codes
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
	active := func(t *testing.T, sid string) bool {
		t.Helper()
		id, _ := shared.IDFromString(sid)
		s, err := sessions.GetByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return s.IsActive()
	}
	enabled := func(t *testing.T, u *userdom.User) bool {
		t.Helper()
		var on bool
		err := sqlDB.QueryRow(`SELECT enabled FROM user_mfa WHERE user_id = $1`, u.ID().String()).Scan(&on)
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		return on
	}
	unusedCodes := func(t *testing.T, u *userdom.User) int {
		t.Helper()
		var n int
		if err := sqlDB.QueryRow(`SELECT count(*) FROM user_mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, u.ID().String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("an organization that requires it: refused, named, no code spent", func(t *testing.T) {
		u := newAccount(t)
		joinOrg(t, u, "Free Org", false)
		joinOrg(t, u, "Strict Org", true)
		_, codes := enroll(t, u)
		before := unusedCodes(t, u)
		err := svc.DisableMFA(ctx, auditapp.AuditContext{}, u.ID().String(), pw, codes[0])
		var held *MFARequiredError
		if !errors.As(err, &held) {
			t.Fatalf("want MFARequiredError, got %v", err)
		}
		if len(held.Holders.Organizations) != 1 || held.Holders.Organizations[0] != "Strict Org" {
			t.Fatalf("holders = %+v, want only Strict Org", held.Holders)
		}
		if !enabled(t, u) || unusedCodes(t, u) != before {
			t.Fatal("a refused turn-off changed the factor or spent a code")
		}
	})

	t.Run("nobody requires it: off, other sessions ended, current kept", func(t *testing.T) {
		u := newAccount(t)
		joinOrg(t, u, "Free Org", false)
		secret, _ := enroll(t, u)
		cur, other := signIn(t, u), signIn(t, u)
		code, _ := totp.Code(secret, time.Now())
		if err := svc.DisableMFA(ctx, auditapp.AuditContext{SessionID: cur}, u.ID().String(), pw, code); err != nil {
			t.Fatalf("DisableMFA: %v", err)
		}
		if enabled(t, u) {
			t.Fatal("still enabled")
		}
		if !active(t, cur) || active(t, other) {
			t.Fatal("want the current session kept and the other ended")
		}
	})

	t.Run("replace: the old secret stops in the same write, codes replaced, other sessions ended", func(t *testing.T) {
		u := newAccount(t)
		joinOrg(t, u, "Strict Org", true)
		oldSecret, oldCodes := enroll(t, u)
		cur, other := signIn(t, u), signIn(t, u)
		ns, err := svc.BeginMFAReplacement(ctx, u.ID().String(), pw, oldCodes[0])
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		var stored string
		if err := sqlDB.QueryRow(`SELECT secret_encrypted FROM user_mfa WHERE user_id = $1`, u.ID().String()).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if got, _ := cipher.DecryptString(stored); got != oldSecret {
			t.Fatal("starting a replacement changed the active secret")
		}
		code, _ := totp.Code(ns.Secret, time.Now())
		fresh, err := svc.ConfirmMFAReplacement(ctx, auditapp.AuditContext{SessionID: cur}, u.ID().String(), code)
		if err != nil {
			t.Fatalf("confirm: %v", err)
		}
		if err := sqlDB.QueryRow(`SELECT secret_encrypted FROM user_mfa WHERE user_id = $1`, u.ID().String()).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if got, _ := cipher.DecryptString(stored); got != ns.Secret {
			t.Fatal("the new secret is not the active one")
		}
		if !enabled(t, u) || unusedCodes(t, u) != len(fresh) {
			t.Fatal("factor off or recovery codes not replaced")
		}
		if !active(t, cur) || active(t, other) {
			t.Fatal("want the current session kept and the other ended")
		}
		// A replacement cannot be confirmed twice.
		if ok, err := mfaRepo.ReplaceActive(ctx, u.ID(), 1, nil); err != nil || ok {
			t.Fatalf("second ReplaceActive = %v, %v; want false", ok, err)
		}
	})

	t.Run("ReplaceActive never turns on a factor that is off", func(t *testing.T) {
		u := newAccount(t)
		if err := mfaRepo.SavePendingSecret(ctx, u.ID(), "x"); err != nil {
			t.Fatal(err)
		}
		if ok, err := mfaRepo.ReplaceActive(ctx, u.ID(), 1, []string{"h"}); err != nil || ok {
			t.Fatalf("ReplaceActive on a disabled factor = %v, %v", ok, err)
		}
		if enabled(t, u) {
			t.Fatal("enabled by a replacement")
		}
	})
}
