package auth

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/server/pkg/domain/signup"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/server/pkg/domain/user"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/password"
)

// The personal organization against the real stores: one organization per
// account under concurrent sign-ins, members and invitations settle or
// defer the mark, and the rate bounds count real rows. Run with -race.
func TestPersonalOrganization_DB(t *testing.T) {
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
	tenants := postgres.NewTenantRepository(db)

	newAccount := func(t *testing.T) *userdom.User {
		t.Helper()
		u, err := userdom.NewOAuthUser("po-"+shared.NewID().String()+"@example.com", "Pat Owner", "", userdom.AuthProviderGoogle)
		if err != nil {
			t.Fatal(err)
		}
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		t.Cleanup(func() {
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM tenants WHERE created_by = $1`, u.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.ID().String())
		})
		return u
	}
	newOrg := func(t *testing.T, owner *userdom.User, prefix string) *tenantdom.Tenant {
		t.Helper()
		org, err := tenantdom.NewTenant("Other org", prefix+"-"+shared.NewID().String()[:8], owner.ID().String())
		if err != nil {
			t.Fatal(err)
		}
		m, _ := tenantdom.NewOwnerMembership(owner.ID(), org.ID())
		if err := tenants.CreateWithOwner(ctx, org, m); err != nil {
			t.Fatal(err)
		}
		return org
	}
	ownedOrgs := func(t *testing.T, u *userdom.User) int {
		t.Helper()
		var n int
		if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM tenant_members WHERE user_id = $1 AND role = 'owner'`, u.ID().String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	markStatus := func(t *testing.T, u *userdom.User) string {
		t.Helper()
		var s string
		if err := sqlDB.QueryRowContext(ctx, `SELECT status FROM personal_organizations WHERE user_id = $1`, u.ID().String()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	policy := signupdom.Static{Mode: signupdom.ModeSelfService, Accounts: signupdom.AccountsOpen, PersonalOrganization: true}
	newService := func() *PersonalOrganizations {
		p := NewPersonalOrganizations(tenants, policy, logger.NewNop())
		p.SetInvitationLookup(tenants)
		p.SetRates(tenantdom.PersonalOrgRates{}) // the rate case sets its own
		return p
	}

	t.Run("concurrent sign-ins make one organization", func(t *testing.T) {
		u := newAccount(t)
		p := newService()
		p.Reserve(ctx, u.ID(), signupdom.OutcomeSelfService)
		var wg sync.WaitGroup
		var mu sync.Mutex
		made := 0
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if p.Ensure(ctx, u, "198.51.100.9", "test") != nil {
					mu.Lock()
					made++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if made != 1 || ownedOrgs(t, u) != 1 {
			t.Fatalf("made=%d owned=%d, want 1 and 1", made, ownedOrgs(t, u))
		}
		if markStatus(t, u) != string(tenantdom.PersonalOrgCreated) {
			t.Fatal("mark not settled as created")
		}
		// A retried sign-up keeps the settled mark; a later sign-in makes nothing.
		p.Reserve(ctx, u.ID(), signupdom.OutcomeSelfService)
		if p.Ensure(ctx, u, "198.51.100.9", "test") != nil || ownedOrgs(t, u) != 1 {
			t.Fatal("a later sign-in made another organization")
		}
	})

	t.Run("a member settles the mark as skipped", func(t *testing.T) {
		u := newAccount(t)
		org := newOrg(t, newAccount(t), "po-else")
		p := newService()
		p.Reserve(ctx, u.ID(), signupdom.OutcomeSelfService)
		m, _ := tenantdom.NewMembership(u.ID(), org.ID(), tenantdom.RoleMember, nil)
		if err := tenants.CreateMembership(ctx, m); err != nil {
			t.Fatal(err)
		}
		if p.Ensure(ctx, u, "", "") != nil || ownedOrgs(t, u) != 0 {
			t.Fatal("a member got a personal organization")
		}
		if markStatus(t, u) != string(tenantdom.PersonalOrgSkipped) {
			t.Fatal("mark not settled as skipped")
		}
	})

	t.Run("an invitation leaves the mark pending", func(t *testing.T) {
		u := newAccount(t)
		inviter := newAccount(t)
		org := newOrg(t, inviter, "po-inv")
		p := newService()
		p.Reserve(ctx, u.ID(), signupdom.OutcomeSelfService)
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenant_invitations (tenant_id, email, role, token, invited_by, expires_at)
			VALUES ($1, $2, 'member', $3, $4, now() + interval '1 day')`,
			org.ID().String(), u.Email(), shared.NewID().String(), inviter.ID().String()); err != nil {
			t.Fatalf("invite: %v", err)
		}
		if p.Ensure(ctx, u, "", "") != nil || ownedOrgs(t, u) != 0 {
			t.Fatal("an invited person got a personal organization")
		}
		if markStatus(t, u) != string(tenantdom.PersonalOrgPending) {
			t.Fatal("an invitation must leave the mark pending")
		}
		// The store refuses on its own, inside its transaction.
		tn, _ := tenantdom.NewTenant("X", "po-x-"+shared.NewID().String()[:8], u.ID().String())
		mm, _ := tenantdom.NewOwnerMembership(u.ID(), tn.ID())
		err := tenants.CreatePersonalOrganization(ctx, tenantdom.PersonalOrgCreation{UserID: u.ID(), Email: u.Email(),
			Tenant: tn, Membership: mm, At: time.Now()})
		if !errors.Is(err, tenantdom.ErrPersonalOrgInvited) {
			t.Fatalf("store: %v, want ErrPersonalOrgInvited", err)
		}
	})

	t.Run("the prefix bound counts real creations", func(t *testing.T) {
		p := newService()
		p.SetRates(tenantdom.PersonalOrgRates{PerPrefix: 2, Window: time.Minute})
		var accounts []*userdom.User
		for range 3 {
			u := newAccount(t)
			accounts = append(accounts, u)
			p.Reserve(ctx, u.ID(), signupdom.OutcomeSelfService)
		}
		var before int
		_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM personal_organizations
			WHERE status = 'created' AND ip_prefix = '192.0.2.0/24' AND settled_at > now() - interval '1 minute'`).Scan(&before)
		if before != 0 {
			t.Skip("another run used the test prefix within the minute")
		}
		for i, u := range accounts {
			got := p.Ensure(ctx, u, "192.0.2.10", "")
			if (got != nil) != (i < 2) {
				t.Fatalf("creation %d: made=%v", i+1, got != nil)
			}
		}
		if markStatus(t, accounts[2]) != string(tenantdom.PersonalOrgPending) {
			t.Fatal("a bounded account must stay pending")
		}
	})

	// Password sign-up end to end: register (switch on), no organization
	// before the address is verified, then the first sign-in lands inside the
	// new organization as its owner.
	t.Run("password sign-up gets its organization after verification", func(t *testing.T) {
		cfg := config.AuthConfig{JWTSecret: "test-secret-test-secret-test-secret!", AccessTokenDuration: time.Minute,
			RefreshTokenDuration: time.Hour, SessionDuration: time.Hour, MaxActiveSessions: 10,
			EmailVerificationDuration: time.Hour, SignupMode: config.SignupModeOpen}
		audit := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
		svc := NewAuthService(users, postgres.NewSessionRepository(sqlDB), postgres.NewRefreshTokenRepository(sqlDB),
			tenants, audit, cfg, logger.NewNop())
		svc.passwordHasher = password.New(password.WithCost(4))
		svc.SetSignupPolicy(policy)
		p := newService()
		p.SetAuditService(audit)
		svc.SetPersonalOrganizations(p)

		email := "po-pw-" + shared.NewID().String() + "@example.com"
		const pw = "Personal-org-pw-1!"
		res, err := svc.Register(ctx, RegisterInput{Email: email, Password: pw, Name: "Robin Park"})
		if err != nil || res.User == nil || res.VerificationToken == "" {
			t.Fatalf("register: %+v %v", res, err)
		}
		u := res.User
		t.Cleanup(func() {
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM tenants WHERE created_by = $1`, u.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, u.ID().String())
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.ID().String())
		})
		if markStatus(t, u) != string(tenantdom.PersonalOrgPending) {
			t.Fatal("a self-service sign-up must be marked")
		}
		if _, err := svc.Login(ctx, LoginInput{Email: email, Password: pw, IPAddress: "198.51.100.20"}); !errors.Is(err, ErrEmailNotVerified) {
			t.Fatalf("unverified sign-in: %v", err)
		}
		if ownedOrgs(t, u) != 0 {
			t.Fatal("an organization was made before the address was verified")
		}
		if err := svc.VerifyEmail(ctx, res.VerificationToken); err != nil {
			t.Fatalf("verify: %v", err)
		}
		login, err := svc.Login(ctx, LoginInput{Email: email, Password: pw, IPAddress: "198.51.100.20"})
		if err != nil {
			t.Fatalf("sign-in: %v", err)
		}
		if len(login.Tenants) != 1 || login.Tenants[0].Role != tenantdom.RoleOwner.String() ||
			login.Tenants[0].TenantName != "Robin Park's organization" {
			t.Fatalf("sign-in must land in the new organization as owner: %+v", login.Tenants)
		}
		var via string
		if err := sqlDB.QueryRowContext(ctx, `SELECT COALESCE(metadata->>'via', '') FROM audit_logs WHERE tenant_id = $1 AND action = 'tenant.created'`,
			login.Tenants[0].TenantID).Scan(&via); err != nil || via != "personal_organization" {
			t.Fatalf("audit: %q %v", via, err)
		}
		// The next sign-in makes nothing more.
		again, err := svc.Login(ctx, LoginInput{Email: email, Password: pw, IPAddress: "198.51.100.20"})
		if err != nil || len(again.Tenants) != 1 {
			t.Fatalf("second sign-in: %+v %v", again, err)
		}
	})

	// Social sign-up end to end through the callback's sign-in step: a new
	// Google account owns its organization when the sign-in returns; an
	// invited one owns none.
	t.Run("social sign-up: new account lands in its organization, invited gets none", func(t *testing.T) {
		authCfg := config.AuthConfig{JWTSecret: "test-secret-test-secret-test-secret!", AccessTokenDuration: time.Minute,
			RefreshTokenDuration: time.Hour, SessionDuration: time.Hour}
		oauth := NewOAuthService(users, postgres.NewSessionRepository(sqlDB), postgres.NewRefreshTokenRepository(sqlDB),
			config.OAuthConfig{Enabled: true, Google: config.OAuthProviderConfig{Enabled: true, ClientID: "c", ClientSecret: "s"}},
			authCfg, logger.NewNop())
		oauth.SetIdentityRepo(postgres.NewUserIdentityRepository(db))
		oauth.SetSignupPolicy(policy)
		oauth.SetInvitationLookup(tenants)
		oauth.SetPersonalOrganizations(newService())
		// A social sign-in takes the second-factor step; without the gate wired it is refused.
		oauth.SetSecondFactorGate(noChallenge{})

		signInAs := func(t *testing.T, email string) *userdom.User {
			t.Helper()
			res, err := oauth.signIn(WithClientInfo(ctx, "198.51.100.30", "test"),
				&OAuthUserInfo{Email: email, Name: "Gale Chen", HD: "example.com"}, OAuthProviderGoogle, "")
			if err != nil || res.User == nil || res.RefreshToken == "" {
				t.Fatalf("social sign-in: %+v %v", res, err)
			}
			u := res.User
			t.Cleanup(func() {
				_, _ = sqlDB.ExecContext(ctx, `DELETE FROM tenants WHERE created_by = $1`, u.ID().String())
				_, _ = sqlDB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, u.ID().String())
				_, _ = sqlDB.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.ID().String())
			})
			return u
		}

		u := signInAs(t, "po-g-"+shared.NewID().String()+"@example.com")
		if ownedOrgs(t, u) != 1 {
			t.Fatal("a new social account must own its organization when the sign-in returns")
		}

		inviter := newAccount(t)
		org := newOrg(t, inviter, "po-ginv")
		invitedEmail := "po-gi-" + shared.NewID().String() + "@example.com"
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenant_invitations (tenant_id, email, role, token, invited_by, expires_at)
			VALUES ($1, $2, 'member', $3, $4, now() + interval '1 day')`,
			org.ID().String(), invitedEmail, shared.NewID().String(), inviter.ID().String()); err != nil {
			t.Fatalf("invite: %v", err)
		}
		invited := signInAs(t, invitedEmail)
		if ownedOrgs(t, invited) != 0 {
			t.Fatal("an invited person must get no extra organization")
		}
		var marks int
		_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM personal_organizations WHERE user_id = $1`, invited.ID().String()).Scan(&marks)
		if marks != 0 {
			t.Fatal("an invited sign-up must not be marked")
		}
	})

	// A refused social sign-in (the second-factor gate is not wired) creates
	// nothing: no organization row is left behind.
	t.Run("social sign-in refused for the unwired 2FA gate creates no organization", func(t *testing.T) {
		authCfg := config.AuthConfig{JWTSecret: "test-secret-test-secret-test-secret!", AccessTokenDuration: time.Minute,
			RefreshTokenDuration: time.Hour, SessionDuration: time.Hour}
		oauth := NewOAuthService(users, postgres.NewSessionRepository(sqlDB), postgres.NewRefreshTokenRepository(sqlDB),
			config.OAuthConfig{Enabled: true, Google: config.OAuthProviderConfig{Enabled: true, ClientID: "c", ClientSecret: "s"}},
			authCfg, logger.NewNop())
		oauth.SetIdentityRepo(postgres.NewUserIdentityRepository(db))
		oauth.SetSignupPolicy(policy)
		oauth.SetInvitationLookup(tenants)
		oauth.SetPersonalOrganizations(newService())
		// No SetSecondFactorGate: fail closed.
		email := "po-ng-" + shared.NewID().String() + "@example.com"
		t.Cleanup(func() {
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM tenants WHERE created_by IN (SELECT id FROM users WHERE email = $1)`, email)
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email = $1)`, email)
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM users WHERE email = $1`, email)
		})
		_, err := oauth.signIn(WithClientInfo(ctx, "198.51.100.31", "test"),
			&OAuthUserInfo{Email: email, Name: "Gale Chen", HD: "example.com"}, OAuthProviderGoogle, "")
		if !errors.Is(err, ErrOAuthExchangeFailed) {
			t.Fatalf("sign-in without the gate: %v", err)
		}
		var n int
		if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM tenant_members m JOIN users u ON u.id = m.user_id WHERE u.email = $1`, email).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("a refused sign-in left %d membership(s)", n)
		}
	})

	// L1: a domain claimed after the service read the domain facts is
	// caught inside the transaction.
	t.Run("a domain claim is rechecked in the transaction", func(t *testing.T) {
		owner := newAccount(t)
		org := newOrg(t, owner, "po-claim")
		domain := "po-claim-" + shared.NewID().String()[:8] + ".example.net"
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO verified_domains (id, tenant_id, domain, verification_token, status, purpose, verified_at)
			VALUES ($1, $2, $3, 'tok', 'verified', 'sso', now())`, shared.NewID().String(), org.ID().String(), domain); err != nil {
			t.Fatalf("claim: %v", err)
		}
		for _, host := range []string{domain, "mail." + domain} {
			u := newAccount(t)
			email := "po-c@" + host
			p := newService()
			p.Reserve(ctx, u.ID(), signupdom.OutcomeSelfService)
			tn, _ := tenantdom.NewTenant("X", "po-c-"+shared.NewID().String()[:8], u.ID().String())
			mm, _ := tenantdom.NewOwnerMembership(u.ID(), tn.ID())
			err := tenants.CreatePersonalOrganization(ctx, tenantdom.PersonalOrgCreation{UserID: u.ID(), Email: email,
				Tenant: tn, Membership: mm, At: time.Now()})
			if !errors.Is(err, tenantdom.ErrPersonalOrgDomainClaimed) || ownedOrgs(t, u) != 0 ||
				markStatus(t, u) != string(tenantdom.PersonalOrgPending) {
				t.Fatalf("%s: %v", host, err)
			}
		}
	})

	// L3 in the store: an old mark is not honored, in the read or the write.
	t.Run("an old mark is not honored", func(t *testing.T) {
		u := newAccount(t)
		newService().Reserve(ctx, u.ID(), signupdom.OutcomeSelfService)
		if _, err := sqlDB.ExecContext(ctx, `UPDATE personal_organizations SET reserved_at = now() - interval '31 days' WHERE user_id = $1`, u.ID().String()); err != nil {
			t.Fatal(err)
		}
		if ok, err := tenants.PersonalOrganizationPending(ctx, u.ID(), time.Now()); err != nil || ok {
			t.Fatalf("pending: %v %v", ok, err)
		}
		tn, _ := tenantdom.NewTenant("X", "po-o-"+shared.NewID().String()[:8], u.ID().String())
		mm, _ := tenantdom.NewOwnerMembership(u.ID(), tn.ID())
		err := tenants.CreatePersonalOrganization(ctx, tenantdom.PersonalOrgCreation{UserID: u.ID(), Email: u.Email(),
			Tenant: tn, Membership: mm, At: time.Now()})
		if !errors.Is(err, tenantdom.ErrPersonalOrgNotPending) || ownedOrgs(t, u) != 0 {
			t.Fatalf("create: %v", err)
		}
	})

	t.Run("an unmarked account gets nothing", func(t *testing.T) {
		u := newAccount(t)
		tn, _ := tenantdom.NewTenant("X", "po-y-"+shared.NewID().String()[:8], u.ID().String())
		mm, _ := tenantdom.NewOwnerMembership(u.ID(), tn.ID())
		err := tenants.CreatePersonalOrganization(ctx, tenantdom.PersonalOrgCreation{UserID: u.ID(), Email: u.Email(),
			Tenant: tn, Membership: mm, At: time.Now()})
		if !errors.Is(err, tenantdom.ErrPersonalOrgNotPending) || ownedOrgs(t, u) != 0 {
			t.Fatalf("unmarked: %v", err)
		}
		// An owner who is not the account is refused before anything is written.
		other := newAccount(t)
		bad, _ := tenantdom.NewOwnerMembership(other.ID(), tn.ID())
		if err := tenants.CreatePersonalOrganization(ctx, tenantdom.PersonalOrgCreation{UserID: u.ID(), Email: u.Email(),
			Tenant: tn, Membership: bad, At: time.Now()}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("owner mismatch: %v", err)
		}
	})
}

// noChallenge is a second-factor gate for an account with no factor.
type noChallenge struct{}

func (noChallenge) LinkedSignInChallenge(context.Context, *userdom.User, string, string) (*MFAChallengeInfo, error) {
	return nil, nil
}
