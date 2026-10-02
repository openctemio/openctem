package integration

// The first organization at install time (bootstrap-admin -org-*) and the
// self-service organization paths, against a real Postgres. Organizations are
// created by the platform administrator by default (TENANT_CREATION_MODE=
// admin_only); self_service is an explicit opt-in and every path is audited.
//
// Requires DATABASE_URL pointing at a fully migrated database.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/api/internal/adminbootstrap"
	auditapp "github.com/openctemio/api/internal/app/audit"
	authapp "github.com/openctemio/api/internal/app/auth"
	tenantapp "github.com/openctemio/api/internal/app/tenant"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/password"
	"github.com/openctemio/api/pkg/validator"
)

// orgBootMailer records the set-password email instead of sending it.
type orgBootMailer struct {
	sentTo, token string
}

func (m *orgBootMailer) CanDeliverTo(context.Context, string) bool { return true }
func (m *orgBootMailer) SendAccountSetupEmail(_ context.Context, _, to, _, _, token string, _ time.Duration) error {
	m.sentTo, m.token = to, token
	return nil
}

func orgBootOptions(t *testing.T, db *postgres.DB) adminbootstrap.Options {
	t.Helper()
	if err := adminbootstrap.CheckSchema(context.Background(), db.DB); err != nil {
		t.Skipf("schema not migrated: %v", err)
	}
	s := uuid.NewString()[:8]
	o := adminbootstrap.Options{
		Email:         "orgboot-admin-" + s + "@example.com",
		BackupEmail:   "orgboot-bg-" + s + "@example.com",
		OrgName:       "Acme Security " + s,
		OrgOwnerEmail: "orgboot-owner-" + s + "@example.com",
		OrgOwnerName:  "Olive Owner",
		UIBaseURL:     "https://ctem.example.com/",
	}
	if err := o.Normalize(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, o.OrgSlug)
		_, _ = db.Exec(`DELETE FROM users WHERE email IN ($1, $2, $3)`, o.Email, o.BackupEmail, o.OrgOwnerEmail)
	})
	return o
}

func auditActions(t *testing.T, db *postgres.DB, tenantID string) map[string]int {
	t.Helper()
	rows, err := db.Query(`SELECT action, actor_email FROM audit_logs WHERE tenant_id = $1`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var action string
		var actor sql.NullString
		if err := rows.Scan(&action, &actor); err != nil {
			t.Fatal(err)
		}
		out[action]++
		out["actor:"+actor.String]++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestBootstrapAdminCreatesFirstOrganization runs bootstrap-admin with the
// -org-* options twice: the first run creates the administrators and the first
// organization through the tenant service (owner membership and role, audited
// tenant.created and user.created, a one-time link printed because there is
// no SMTP); the second run changes nothing.
func TestBootstrapAdminCreatesFirstOrganization(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	o := orgBootOptions(t, db)

	var out bytes.Buffer
	if err := adminbootstrap.Run(ctx, db.DB, o, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "=== Organization created ===") {
		t.Fatalf("no organization reported:\n%s", out.String())
	}
	m := regexp.MustCompile(`https://ctem\.example\.com/set-password\?token=(\S+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("set-password link not printed:\n%s", out.String())
	}

	var tenantID, createdBy string
	if err := db.QueryRow(`SELECT id, created_by FROM tenants WHERE slug = $1 AND name = $2`, o.OrgSlug, o.OrgName).
		Scan(&tenantID, &createdBy); err != nil {
		t.Fatalf("organization not created: %v", err)
	}
	var ownerID, ownerName string
	var pwHash, resetHash sql.NullString
	if err := db.QueryRow(`SELECT id, name, password_hash, password_reset_token FROM users WHERE email = $1`, o.OrgOwnerEmail).
		Scan(&ownerID, &ownerName, &pwHash, &resetHash); err != nil {
		t.Fatalf("owner account: %v", err)
	}
	if pwHash.Valid || ownerName != "Olive Owner" || createdBy != ownerID {
		t.Fatalf("owner: password set=%v name=%q created_by=%s", pwHash.Valid, ownerName, createdBy)
	}
	if resetHash.String != crypto.HashToken(m[1]) {
		t.Fatal("the printed link is not the one stored (hashed) on the owner account")
	}
	var role string
	if err := db.QueryRow(`SELECT role FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, tenantID, ownerID).Scan(&role); err != nil || role != "owner" {
		t.Fatalf("owner membership: %q %v", role, err)
	}
	var rbac int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE ur.tenant_id = $1 AND ur.user_id = $2 AND r.slug = 'owner'`, tenantID, ownerID).Scan(&rbac); err != nil || rbac != 1 {
		t.Fatalf("owner RBAC role: %d %v", rbac, err)
	}
	// Only the owner belongs to it: the platform administrators belong to no
	// organization.
	var members int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenant_members WHERE tenant_id = $1`, tenantID).Scan(&members); err != nil || members != 1 {
		t.Fatalf("members: %d %v", members, err)
	}
	acts := auditActions(t, db, tenantID)
	if acts["tenant.created"] != 1 || acts["user.created"] != 1 || acts["actor:"+adminbootstrap.AuditActor] < 2 {
		t.Fatalf("audit trail in the new organization: %v", acts)
	}

	out.Reset()
	if err := adminbootstrap.Run(ctx, db.DB, o, &out); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if strings.Contains(out.String(), "set-password") || strings.Contains(out.String(), "Password:") ||
		!strings.Contains(out.String(), "Organization "+o.OrgSlug+" already exists") {
		t.Fatalf("second run must change nothing:\n%s", out.String())
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenants WHERE slug = $1`, o.OrgSlug).Scan(&n); err != nil || n != 1 {
		t.Fatalf("tenants with the slug: %d %v", n, err)
	}
	if again := auditActions(t, db, tenantID); again["tenant.created"] != 1 || again["user.created"] != 1 {
		t.Fatalf("second run wrote audit events: %v", again)
	}
}

// With SMTP the owner's link is emailed and never printed.
func TestBootstrapAdminEmailsOwnerLink(t *testing.T) {
	db := openConsoleDB(t)
	o := orgBootOptions(t, db)
	mailer := &orgBootMailer{}
	o.OrgSetupMailer = mailer
	var out bytes.Buffer
	if err := adminbootstrap.Run(context.Background(), db.DB, o, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	if mailer.sentTo != o.OrgOwnerEmail || mailer.token == "" {
		t.Fatalf("link not emailed: %+v", mailer)
	}
	if strings.Contains(out.String(), mailer.token) || strings.Contains(out.String(), "set-password?token=") {
		t.Fatalf("an emailed link must not be printed:\n%s", out.String())
	}
}

// An owner email that already has an account makes that account the owner (no
// new account, no link). A platform administrator's account is refused and
// nothing is left behind.
func TestBootstrapAdminOrganizationOwners(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()

	t.Run("existing account", func(t *testing.T) {
		o := orgBootOptions(t, db)
		uid := uuid.NewString()
		if _, err := db.Exec(`INSERT INTO users (id, email, name, password_hash, auth_provider, status, email_verified, created_at, updated_at)
			VALUES ($1, $2, 'Existing', 'x', 'local', 'active', true, NOW(), NOW())`, uid, o.OrgOwnerEmail); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := adminbootstrap.Run(ctx, db.DB, o, &out); err != nil {
			t.Fatalf("run: %v\n%s", err, out.String())
		}
		if !strings.Contains(out.String(), "existing account") || strings.Contains(out.String(), "set-password") {
			t.Fatalf("existing owner:\n%s", out.String())
		}
		var role string
		if err := db.QueryRow(`SELECT tm.role FROM tenant_members tm JOIN tenants t ON t.id = tm.tenant_id
			WHERE t.slug = $1 AND tm.user_id = $2`, o.OrgSlug, uid).Scan(&role); err != nil || role != "owner" {
			t.Fatalf("existing account is not the owner: %q %v", role, err)
		}
	})

	t.Run("platform administrator refused", func(t *testing.T) {
		first := orgBootOptions(t, db)
		first.OrgName, first.OrgSlug, first.OrgOwnerEmail, first.OrgOwnerName = "", "", "", ""
		if err := adminbootstrap.Run(ctx, db.DB, first, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		// A second installation step names the first run's backup admin as owner.
		o := orgBootOptions(t, db)
		o.OrgOwnerEmail = first.BackupEmail
		var out bytes.Buffer
		err := adminbootstrap.Run(ctx, db.DB, o, &out)
		if err == nil || !strings.Contains(err.Error(), "platform administrator") {
			t.Fatalf("want a platform-administrator refusal, got %v\n%s", err, out.String())
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM tenants WHERE slug = $1`, o.OrgSlug).Scan(&n); err != nil || n != 0 {
			t.Fatalf("organization left behind: %d %v", n, err)
		}
	})

	t.Run("reserved slug", func(t *testing.T) {
		o := orgBootOptions(t, db)
		o.OrgSlug = "system"
		err := adminbootstrap.Run(ctx, db.DB, o, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("the System tenant's slug must be refused, got %v", err)
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = $1`, o.OrgOwnerEmail).Scan(&n); err != nil || n != 0 {
			t.Fatalf("owner account left behind: %d %v", n, err)
		}
	})
}

// orgSelfServiceUser creates a local account with a password and no
// organization, and signs it in (a global refresh token).
func orgSelfServiceUser(t *testing.T, db *postgres.DB, svc *authapp.AuthService) (email, refresh string) {
	t.Helper()
	email = "orgboot-self-" + uuid.NewString()[:8] + "@example.com"
	hash, err := password.New().Hash("Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name, password_hash, auth_provider, status, email_verified, created_at, updated_at)
		VALUES ($1, $2, 'Self', $3, 'local', 'active', true, NOW(), NOW())`, uuid.NewString(), email, hash); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM users WHERE email = $1`, email)
	})
	res, err := svc.Login(context.Background(), authapp.LoginInput{Email: email, Password: "Correct-Horse-9!"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return email, res.RefreshToken
}

func orgAuthService(db *postgres.DB, mode string) *authapp.AuthService {
	cfg := config.AuthConfig{
		TenantCreationMode:   mode,
		JWTSecret:            "orgboot-test-secret-orgboot-test-secret-0123456789",
		JWTIssuer:            "openctem-test",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: time.Hour,
		SessionDuration:      time.Hour,
		MaxActiveSessions:    10,
		PasswordMinLength:    8,
	}
	log := logger.NewNop()
	return authapp.NewAuthService(postgres.NewUserRepository(db), postgres.NewSessionRepository(db.DB),
		postgres.NewRefreshTokenRepository(db.DB), postgres.NewTenantRepository(db),
		auditapp.NewAuditService(postgres.NewAuditRepository(db), log), cfg, log)
}

// create-first-team: refused by default (admin_only); with the explicit
// self_service opt-in it creates the organization with its owner and audits
// tenant.created.
func TestCreateFirstTeamModes(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()

	for _, mode := range []string{"", config.TenantCreationAdminOnly} {
		svc := orgAuthService(db, config.TenantCreationSelfService) // sign in normally
		_, refresh := orgSelfServiceUser(t, db, svc)
		_, err := orgAuthService(db, mode).CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{
			RefreshToken: refresh, TeamName: "Sneaky", TeamSlug: "sneaky-" + uuid.NewString()[:8],
		})
		if !errors.Is(err, authapp.ErrTenantCreationDisabled) {
			t.Fatalf("mode %q: create-first-team must be refused, got %v", mode, err)
		}
	}

	svc := orgAuthService(db, config.TenantCreationSelfService)
	email, refresh := orgSelfServiceUser(t, db, svc)
	slug := "self-" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, slug) })
	res, err := svc.CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{
		RefreshToken: refresh, TeamName: "Self Team", TeamSlug: slug, IPAddress: "198.51.100.7", UserAgent: "test",
	})
	if err != nil {
		t.Fatalf("self_service create-first-team: %v", err)
	}
	if res.Tenant.Role != "owner" || res.Tenant.TenantSlug != slug {
		t.Fatalf("result: %+v", res.Tenant)
	}
	var rbac int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id JOIN users u ON u.id = ur.user_id
		WHERE ur.tenant_id = $1 AND u.email = $2 AND r.slug = 'owner'`, res.Tenant.TenantID, email).Scan(&rbac); err != nil || rbac != 1 {
		t.Fatalf("owner RBAC role: %d %v", rbac, err)
	}
	var actor, ip string
	if err := db.QueryRow(`SELECT actor_email, COALESCE(actor_ip::text, '') FROM audit_logs WHERE tenant_id = $1 AND action = 'tenant.created'`,
		res.Tenant.TenantID).Scan(&actor, &ip); err != nil {
		t.Fatalf("tenant.created not audited: %v", err)
	}
	if actor != email || !strings.HasPrefix(ip, "198.51.100.7") {
		t.Fatalf("audit actor %q ip %q", actor, ip)
	}
}

// POST /tenants: refused unless self_service; with it the organization is
// created and audited.
func TestCreateTenantModes(t *testing.T) {
	db := openConsoleDB(t)
	log := logger.NewNop()
	tenantSvc := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
		tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
	users := postgres.NewUserRepository(db)
	email, _ := orgSelfServiceUser(t, db, orgAuthService(db, config.TenantCreationSelfService))
	u, err := users.GetByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}

	post := func(selfService bool, slug string) *httptest.ResponseRecorder {
		h := handler.NewTenantHandler(tenantSvc, validator.New(), log)
		h.SetSelfServiceTenantCreation(selfService)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(`{"name":"Second Org","slug":"`+slug+`"}`))
		req = req.WithContext(context.WithValue(req.Context(), middleware.LocalUserKey, u))
		rec := httptest.NewRecorder()
		h.Create(rec, req)
		return rec
	}

	blocked := "blocked-" + uuid.NewString()[:8]
	if rec := post(false, blocked); rec.Code != http.StatusForbidden {
		t.Fatalf("admin_only: status %d %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenants WHERE slug = $1`, blocked).Scan(&n); err != nil || n != 0 {
		t.Fatalf("admin_only created an organization: %d %v", n, err)
	}

	open := "open-" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, open) })
	if rec := post(true, open); rec.Code != http.StatusCreated {
		t.Fatalf("self_service: status %d %s", rec.Code, rec.Body.String())
	}
	var tenantID string
	if err := db.QueryRow(`SELECT id FROM tenants WHERE slug = $1`, open).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if acts := auditActions(t, db, tenantID); acts["tenant.created"] != 1 || acts["actor:"+email] < 1 {
		t.Fatalf("POST /tenants not audited: %v", acts)
	}
}
