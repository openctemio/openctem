package integration

// The sign-up policy of a verified SSO domain (RFC-104), end to end on the
// database: sso_required refuses password sign-up for addresses on the
// domain, block_new_workspaces refuses organization creation for accounts on
// it, include_subdomains widens both, a lapsed claim stops every effect, and
// another organization cannot change the policy.

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	signupapp "github.com/openctemio/openctem/api/internal/app/signup"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
)

func TestDomainSignupPolicy(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	vdRepo := postgres.NewVerifiedDomainRepository(db)
	svc := domainverify.NewService(vdRepo, nil, logger.NewNop())
	ssoReady := true
	svc.SetSSOReadiness(func(context.Context, shared.ID) (bool, error) { return ssoReady, nil })

	tenantA := createTestTenant(t, db.DB, "dsp-a")
	tenantB := createTestTenant(t, db.DB, "dsp-b")
	domain := "dsp-" + uuid.NewString()[:8] + ".example"
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM verified_domains WHERE tenant_id IN ($1, $2)`, tenantA.String(), tenantB.String())
		cleanupTestData(db.DB, tenantA)
		cleanupTestData(db.DB, tenantB)
	})
	vd, err := verifieddomain.New(shared.NewID(), tenantA, domain, "tok-"+domain)
	if err != nil {
		t.Fatal(err)
	}
	vd.WithPurpose(verifieddomain.PurposeSSO)
	if err := vdRepo.Create(ctx, vd); err != nil {
		t.Fatal(err)
	}

	// A pending (unverified) claim has no policy.
	if _, _, err := svc.ChangeSignupPolicy(ctx, tenantA, vd.ID(), verifieddomain.SignupPolicy{
		Join: verifieddomain.JoinOff, JoinRole: "viewer", BlockNewWorkspaces: true,
	}); !errors.Is(err, verifieddomain.ErrPolicyNeedsSSOClaim) {
		t.Fatalf("an unverified claim must have no policy, got %v", err)
	}
	vd.MarkVerified(time.Now())
	if err := vdRepo.Update(ctx, vd); err != nil {
		t.Fatal(err)
	}

	// Another organization cannot change it (not found, nothing written).
	if _, _, err := svc.ChangeSignupPolicy(ctx, tenantB, vd.ID(), verifieddomain.SignupPolicy{
		Join: verifieddomain.JoinAuto, JoinRole: "member",
	}); !errors.Is(err, verifieddomain.ErrNotFound) {
		t.Fatalf("cross-tenant change must be not found, got %v", err)
	}

	// sso_required needs a working SSO connection.
	ssoReady = false
	if _, _, err := svc.ChangeSignupPolicy(ctx, tenantA, vd.ID(), verifieddomain.SignupPolicy{
		Join: verifieddomain.JoinOff, JoinRole: "viewer", SSORequired: true,
	}); !errors.Is(err, domainverify.ErrSSORequiredNeedsSSO) {
		t.Fatalf("sso_required without SSO must be refused, got %v", err)
	}
	ssoReady = true
	_, notify, err := svc.ChangeSignupPolicy(ctx, tenantA, vd.ID(), verifieddomain.SignupPolicy{
		Join: verifieddomain.JoinApproval, JoinRole: "viewer", SSORequired: true, BlockNewWorkspaces: true,
	})
	if err != nil || !notify {
		t.Fatalf("owner change: notify=%v err=%v", notify, err)
	}
	stored, _ := vdRepo.GetByID(ctx, tenantA, vd.ID())
	if p := stored.SignupPolicy(); !p.SSORequired || !p.BlockNewWorkspaces || p.Join != verifieddomain.JoinApproval {
		t.Fatalf("policy not stored: %+v", p)
	}

	// Sign-up under SIGNUP_MODE=open.
	repo := withStoredSignupPolicy(t, db, signupdom.Policy{Mode: signupdom.ModeSelfService, Accounts: signupdom.AccountsOpen})
	policy := signupapp.NewService(repo, nil, nil, nil, logger.NewNop())
	policy.SetCeiling(signupdom.CeilingOpen)
	auth := orgAuthService(db, config.SignupModeOpen)
	auth.SetSignupPolicy(policy)
	auth.SetSignupDomainPolicy(svc)
	register := func(email string) error {
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE email = $1`, email) })
		_, err := auth.Register(ctx, authapp.RegisterInput{Email: email, Password: "Correct-Horse-9!", Name: "R"})
		return err
	}
	rows := func(email string) int {
		var n int
		_ = db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = $1`, email).Scan(&n)
		return n
	}

	onDomain := "bob-" + uuid.NewString()[:6] + "@" + domain
	if err := register(onDomain); !errors.Is(err, authapp.ErrSignupSSORequired) || rows(onDomain) != 0 {
		t.Fatalf("password sign-up on an sso_required domain must be refused with nothing written: %v", err)
	}
	onSub := "eve-" + uuid.NewString()[:6] + "@eu." + domain
	if err := register(onSub); err != nil {
		t.Fatalf("a subdomain is not covered without include_subdomains: %v", err)
	}
	elsewhere := "cy-" + uuid.NewString()[:6] + "@other-" + domain
	if err := register(elsewhere); err != nil {
		t.Fatalf("another domain is unaffected: %v", err)
	}

	// block_new_workspaces: an existing account on the domain cannot create
	// an organization; one elsewhere can.
	blockedEmail, refresh := orgSelfServiceUserWithEmail(t, db, auth, "ann-"+uuid.NewString()[:6]+"@"+domain)
	_ = blockedEmail
	if _, err := auth.CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{RefreshToken: refresh, TeamName: "Shadow", TeamSlug: "shadow-" + uuid.NewString()[:8]}); !errors.Is(err, authapp.ErrTenantCreationDisabled) {
		t.Fatalf("an account on a blocking domain must not create an organization, got %v", err)
	}
	_, refreshOther := orgSelfServiceUser(t, db, auth)
	slug := "fine-" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, slug) })
	if _, err := auth.CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{RefreshToken: refreshOther, TeamName: "Fine", TeamSlug: slug}); err != nil {
		t.Fatalf("an account elsewhere may create an organization: %v", err)
	}

	// include_subdomains widens sso_required.
	if _, _, err := svc.ChangeSignupPolicy(ctx, tenantA, vd.ID(), verifieddomain.SignupPolicy{
		Join: verifieddomain.JoinApproval, JoinRole: "viewer", SSORequired: true, BlockNewWorkspaces: true, IncludeSubdomains: true,
	}); err != nil {
		t.Fatal(err)
	}
	onSub2 := "fay-" + uuid.NewString()[:6] + "@eu." + domain
	if err := register(onSub2); !errors.Is(err, authapp.ErrSignupSSORequired) || rows(onSub2) != 0 {
		t.Fatalf("include_subdomains must cover eu.%s: %v", domain, err)
	}

	// The capture notice lists accounts on the domain outside the claimant.
	users := postgres.NewUserRepository(db)
	got, err := users.ListActiveEmailsOnDomain(ctx, domain, true, tenantA, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, blockedEmail) || !slices.Contains(got, onSub) || slices.Contains(got, elsewhere) {
		t.Fatalf("accounts on the domain: %v", got)
	}
	var sent []string
	n, err := svc.NotifyCapture(ctx, stored, users, func(_ context.Context, to, _ string) error {
		sent = append(sent, to)
		return nil
	})
	if err != nil || n != len(sent) || n == 0 {
		t.Fatalf("capture notice: n=%d sent=%v err=%v", n, sent, err)
	}
	stored, _ = vdRepo.GetByID(ctx, tenantA, vd.ID())
	if stored.CaptureNotifiedAt() == nil {
		t.Fatal("the capture notice is recorded")
	}
	if n, _ := svc.NotifyCapture(ctx, stored, users, func(context.Context, string, string) error { return nil }); n != 0 {
		t.Fatal("the capture notice is sent once")
	}

	// The claim lapses: every effect stops at once.
	stored.MarkChecked(time.Now())
	if err := vdRepo.Update(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE verified_domains SET status = 'failed', lapsed_at = now() WHERE id = $1`, vd.ID().String()); err != nil {
		t.Fatal(err)
	}
	afterLapse := "gus-" + uuid.NewString()[:6] + "@" + domain
	if err := register(afterLapse); err != nil {
		t.Fatalf("a lapsed claim has no effect: %v", err)
	}
	if _, ok, _ := svc.SignupPolicyForEmail(ctx, afterLapse); ok {
		t.Fatal("a lapsed claim governs no address")
	}
}

// orgSelfServiceUserWithEmail is orgSelfServiceUser with a chosen address.
func orgSelfServiceUserWithEmail(t *testing.T, db *postgres.DB, svc *authapp.AuthService, email string) (string, string) {
	t.Helper()
	hash, err := password.New().Hash("Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name, password_hash, auth_provider, status, email_verified, created_at, updated_at)
		VALUES ($1, $2, 'Self', $3, 'local', 'active', true, NOW(), NOW())`, uuid.NewString(), email, hash); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE email = $1`, email) })
	res, err := svc.Login(context.Background(), authapp.LoginInput{Email: email, Password: "Correct-Horse-9!"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return email, res.RefreshToken
}
