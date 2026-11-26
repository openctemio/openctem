package auth

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/crypto"
	identityproviderdom "github.com/openctemio/openctem/server/pkg/domain/identityprovider"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/server/pkg/domain/user"
	"github.com/openctemio/openctem/server/pkg/domain/useridentity"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/password"
)

type stubPlatformAdmins struct {
	admin bool
	err   error
}

func (s stubPlatformAdmins) IsPlatformAdmin(context.Context, shared.ID) (bool, error) {
	return s.admin, s.err
}

type anyDomainVerified struct{}

func (anyDomainVerified) IsVerifiedDomain(context.Context, string, string) (bool, error) {
	return true, nil
}

func uniqueSuffix() string { return strings.ReplaceAll(shared.NewID().String(), "-", "") }

// An account an organization's SSO signed in, without a password, gets no
// password from forgot-password or from a set-password link issued before
// the sign-in. Password accounts are unaffected; only an active owner of the
// managing organization (and an active platform administrator) keeps
// forgot-password.
func TestManagedSignIn_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer sqlDB.Close()
	ctx := context.Background()
	if err := sqlDB.PingContext(ctx); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	db := &postgres.DB{DB: sqlDB}

	users := postgres.NewUserRepository(db)
	identities := postgres.NewUserIdentityRepository(db)
	tenants := postgres.NewTenantRepository(db)
	sessions := postgres.NewSessionRepository(sqlDB)
	refresh := postgres.NewRefreshTokenRepository(sqlDB)
	cfg := config.AuthConfig{JWTSecret: "test-secret-test-secret-test-secret!", AccessTokenDuration: time.Minute,
		RefreshTokenDuration: time.Hour, SessionDuration: time.Hour, PasswordResetDuration: time.Hour,
		PasswordMinLength: 8}

	newAuth := func(admins PlatformAdminLookup) *AuthService {
		a := NewAuthService(users, sessions, refresh, tenants, nil, cfg, logger.NewNop())
		a.SetManagedSignIn(users, admins)
		return a
	}
	sso := NewSSOService(nil, tenants, users, sessions, refresh, nil, cfg, logger.NewNop())
	sso.SetIdentityRepo(identities)
	sso.SetDomainVerifier(anyDomainVerified{})
	sso.SetOrganizationSignInStore(users)

	// newUser creates an account: password-less (an administrator's create)
	// when hash is "", else a password account.
	newUser := func(t *testing.T, hash string) *userdom.User {
		t.Helper()
		email := "msi-" + uniqueSuffix() + "@msi.example"
		var (
			u   *userdom.User
			err error
		)
		if hash == "" {
			u, err = userdom.NewProvisionedLocalUser(email, "Managed")
		} else {
			u, err = userdom.NewLocalUser(email, "Managed", hash)
		}
		if err != nil {
			t.Fatal(err)
		}
		u.VerifyEmail()
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		t.Cleanup(func() {
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM user_identities WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM tenant_members WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.ID().String())
		})
		return u
	}
	// newOrg creates an organization owned by owner.
	newOrg := func(t *testing.T, owner *userdom.User) *tenantdom.Tenant {
		t.Helper()
		org, err := tenantdom.NewTenant("Managed sign-in", "msi-"+uniqueSuffix()[20:], owner.ID().String())
		if err != nil {
			t.Fatal(err)
		}
		m, err := tenantdom.NewOwnerMembership(owner.ID(), org.ID())
		if err != nil {
			t.Fatal(err)
		}
		if err := tenants.CreateWithOwner(ctx, org, m); err != nil {
			t.Fatalf("create org: %v", err)
		}
		t.Cleanup(func() {
			_, _ = sqlDB.ExecContext(ctx, `UPDATE users SET sso_tenant_id = NULL WHERE sso_tenant_id = $1`, org.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM user_identities WHERE scope_tenant_id = $1`, org.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE tenant_id = $1`, org.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM sessions WHERE tenant_id = $1`, org.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, org.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, org.ID().String())
		})
		return org
	}
	// The organization whose SSO signs most test accounts in.
	org := newOrg(t, newUser(t, ""))

	// issueLink stores a set-password link on u, as an administrator's
	// create or a forgot-password does, and returns the raw token.
	issueLink := func(t *testing.T, u *userdom.User) string {
		t.Helper()
		raw, err := password.GenerateResetToken()
		if err != nil {
			t.Fatal(err)
		}
		u.SetPasswordResetToken(crypto.HashToken(raw), time.Now().Add(24*time.Hour))
		if err := users.Update(ctx, u); err != nil {
			t.Fatalf("store link: %v", err)
		}
		return raw
	}
	// signInByOIDC is a first OIDC sign-in through in's SSO: it claims the
	// account by its verified-domain email, binds the identity and records
	// the organization sign-on, in the callback's order.
	signInByOIDC := func(t *testing.T, u *userdom.User, in *tenantdom.Tenant) {
		t.Helper()
		info := &SSOUserInfo{Email: u.Email(), Name: u.Name(), EmailVerified: true,
			Issuer: "https://idp.example/" + uniqueSuffix(), Subject: uniqueSuffix()}
		got, err := sso.adoptExistingUser(ctx, in, u, info, identityproviderdom.ProviderOkta)
		if err != nil {
			t.Fatalf("SSO claim: %v", err)
		}
		if err := sso.recordOrganizationSignIn(ctx, got, in); err != nil {
			t.Fatalf("record organization sign-in: %v", err)
		}
	}
	// signInBySAMLEmailNameID is a SAML sign-in whose IdP sends only an
	// email NameID: no identity is bound, the sign-on is still recorded.
	signInBySAMLEmailNameID := func(t *testing.T, u *userdom.User) {
		t.Helper()
		if _, err := sso.completeFederatedLogin(ctx, org, u.Email(), u.Name(), "member", false,
			federatedBinding{}, useridentity.Key{}, ""); err != nil {
			t.Fatalf("SAML sign-in: %v", err)
		}
	}
	storedLink := func(t *testing.T, u *userdom.User) bool {
		t.Helper()
		var tok sql.NullString
		if err := sqlDB.QueryRowContext(ctx, `SELECT password_reset_token FROM users WHERE id = $1`, u.ID().String()).Scan(&tok); err != nil {
			t.Fatal(err)
		}
		return tok.Valid
	}
	hasPassword := func(t *testing.T, u *userdom.User) bool {
		t.Helper()
		var h sql.NullString
		if err := sqlDB.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = $1`, u.ID().String()).Scan(&h); err != nil {
			t.Fatal(err)
		}
		return h.Valid
	}
	const newPassword = "Managed-sign-in-pw-1"

	authSvc := newAuth(stubPlatformAdmins{})
	unknown, err := authSvc.ForgotPassword(ctx, ForgotPasswordInput{Email: "nobody-" + uniqueSuffix() + "@msi.example"})
	if err != nil {
		t.Fatalf("unknown address: %v", err)
	}
	refused := func(t *testing.T, a *AuthService, u *userdom.User) {
		t.Helper()
		res, err := a.ForgotPassword(ctx, ForgotPasswordInput{Email: u.Email()})
		if err != nil {
			t.Fatalf("forgot-password must answer as for any address, got %v", err)
		}
		if res.Token != "" {
			t.Fatal("a reset link was issued for an SSO-managed account")
		}
		if !reflect.DeepEqual(res, unknown) {
			t.Fatalf("answer %+v differs from the unknown-address answer %+v", res, unknown)
		}
		if storedLink(t, u) {
			t.Fatal("a reset token was stored for an SSO-managed account")
		}
	}
	recovers := func(t *testing.T, a *AuthService, u *userdom.User) {
		t.Helper()
		res, err := a.ForgotPassword(ctx, ForgotPasswordInput{Email: u.Email()})
		if err != nil || res.Token == "" {
			t.Fatalf("res=%+v err=%v, want a reset link", res, err)
		}
		if err := a.ResetPassword(ctx, ResetPasswordInput{Token: res.Token, NewPassword: newPassword}); err != nil {
			t.Fatalf("reset: %v", err)
		}
		if !hasPassword(t, u) {
			t.Fatal("no password after the reset")
		}
	}

	t.Run("SSO-claimed account without a password cannot reset", func(t *testing.T) {
		u := newUser(t, "")
		signInByOIDC(t, u, org)
		refused(t, authSvc, u)
	})

	t.Run("set-password link is void after the first SSO sign-in", func(t *testing.T) {
		u := newUser(t, "")
		raw := issueLink(t, u)
		signInByOIDC(t, u, org)
		if storedLink(t, u) {
			t.Fatal("the SSO sign-in left the set-password link stored")
		}
		err := authSvc.ResetPassword(ctx, ResetPasswordInput{Token: raw, NewPassword: newPassword})
		if !errors.Is(err, ErrInvalidResetToken) {
			t.Fatalf("set-password link after the SSO sign-in: got %v, want ErrInvalidResetToken", err)
		}
		if hasPassword(t, u) {
			t.Fatal("the account got a password")
		}
	})

	t.Run("SAML sign-in with an email NameID voids and refuses", func(t *testing.T) {
		u := newUser(t, "")
		raw := issueLink(t, u)
		signInBySAMLEmailNameID(t, u)
		if storedLink(t, u) {
			t.Fatal("the SAML sign-in left the set-password link stored")
		}
		if err := authSvc.ResetPassword(ctx, ResetPasswordInput{Token: raw, NewPassword: newPassword}); !errors.Is(err, ErrInvalidResetToken) {
			t.Fatalf("got %v, want ErrInvalidResetToken", err)
		}
		refused(t, authSvc, u)
	})

	t.Run("an account with a social identity, signed in by SAML email NameID, cannot reset", func(t *testing.T) {
		u := newUser(t, "")
		ident, err := useridentity.New(u.ID(), useridentity.Key{Issuer: "https://accounts.google.com", Subject: uniqueSuffix()})
		if err != nil {
			t.Fatal(err)
		}
		if err := identities.Create(ctx, ident); err != nil {
			t.Fatal(err)
		}
		signInBySAMLEmailNameID(t, u)
		refused(t, authSvc, u)
	})

	t.Run("a link stored on a managed account by any path sets no password", func(t *testing.T) {
		u := newUser(t, "")
		signInByOIDC(t, u, org)
		raw := issueLink(t, u)
		if err := authSvc.ResetPassword(ctx, ResetPasswordInput{Token: raw, NewPassword: newPassword}); !errors.Is(err, ErrInvalidResetToken) {
			t.Fatalf("got %v, want ErrInvalidResetToken", err)
		}
		if hasPassword(t, u) {
			t.Fatal("the account got a password")
		}
	})

	t.Run("password account is unaffected", func(t *testing.T) {
		hash, err := password.New(password.WithCost(4)).Hash("Existing-pw-123")
		if err != nil {
			t.Fatal(err)
		}
		u := newUser(t, hash)
		issueLink(t, u)
		// It linked the organization's SSO itself and signs in with it.
		if err := sso.recordOrganizationSignIn(ctx, u, org); err != nil {
			t.Fatal(err)
		}
		if !storedLink(t, u) {
			t.Fatal("an SSO sign-in voided a password account's link")
		}
		recovers(t, authSvc, u)
	})

	t.Run("owning a self-created organization does not exempt", func(t *testing.T) {
		u := newUser(t, "")
		signInByOIDC(t, u, org)
		newOrg(t, u) // the account creates an organization and owns it
		refused(t, authSvc, u)
	})

	t.Run("break-glass: an owner of the managing organization keeps recovery", func(t *testing.T) {
		u := newUser(t, "")
		owned := newOrg(t, u) // e.g. the first owner the console created
		raw := issueLink(t, u)
		signInByOIDC(t, u, owned)
		// The link from before the sign-in is void for an owner too ...
		if err := authSvc.ResetPassword(ctx, ResetPasswordInput{Token: raw, NewPassword: newPassword}); !errors.Is(err, ErrInvalidResetToken) {
			t.Fatalf("pre-sign-in link: got %v, want ErrInvalidResetToken", err)
		}
		// ... but the owner can ask for a new one and set a password.
		recovers(t, authSvc, u)
	})

	t.Run("an owner of a suspended or deleting managing organization is not exempt", func(t *testing.T) {
		for _, stmt := range []string{
			`UPDATE tenants SET status = 'suspended' WHERE id = $1`,
			`UPDATE tenants SET status = 'pending_deletion', deletion_due_at = now() + interval '7 days' WHERE id = $1`,
		} {
			u := newUser(t, "")
			owned := newOrg(t, u)
			signInByOIDC(t, u, owned)
			if _, err := sqlDB.ExecContext(ctx, stmt, owned.ID().String()); err != nil {
				t.Fatal(err)
			}
			refused(t, authSvc, u)
		}
	})

	t.Run("break-glass: an active platform administrator keeps forgot-password", func(t *testing.T) {
		u := newUser(t, "")
		signInByOIDC(t, u, org)
		res, err := newAuth(stubPlatformAdmins{admin: true}).ForgotPassword(ctx, ForgotPasswordInput{Email: u.Email()})
		if err != nil || res.Token == "" {
			t.Fatalf("platform administrator: res=%+v err=%v, want a reset link", res, err)
		}
	})

	t.Run("a failed break-glass lookup refuses with the same answer", func(t *testing.T) {
		u := newUser(t, "")
		signInByOIDC(t, u, org)
		refused(t, newAuth(stubPlatformAdmins{err: errors.New("db down")}), u)
	})

	t.Run("without the sign-in store a signed-in password-less account is refused", func(t *testing.T) {
		bare := NewAuthService(users, sessions, refresh, tenants, nil, cfg, logger.NewNop())
		u := newUser(t, "")
		signInByOIDC(t, u, org)
		refused(t, bare, u)
		// An account awaiting setup never signed in: its link still works.
		pending := newUser(t, "")
		raw := issueLink(t, pending)
		if err := bare.ResetPassword(ctx, ResetPasswordInput{Token: raw, NewPassword: newPassword}); err != nil {
			t.Fatalf("setup link: %v", err)
		}
	})

	t.Run("account awaiting setup keeps its link", func(t *testing.T) {
		u := newUser(t, "")
		raw := issueLink(t, u)
		if err := authSvc.ResetPassword(ctx, ResetPasswordInput{Token: raw, NewPassword: newPassword}); err != nil {
			t.Fatalf("setup link before any SSO sign-in: %v", err)
		}
	})
}
