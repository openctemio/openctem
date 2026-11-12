package handler

// POST /api/v1/admin/platform-users/{user_id}/setup-link: on an installation
// that cannot send email, the platform administrator hands a new owner a new
// one-time set-password link (docs/architecture/organization-ownership-invitations.md,
// "Running without email"). Exercised through the real handler, provisioning
// service, auth service and repositories. The permission, fresh step-up, rate
// limit and admin audit are route middleware (admin_permissions_test.go,
// admin_step_up_inventory_test.go).
//
// Needs DATABASE_URL (CI's Test job provides one); skipped otherwise.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/auth"
	"github.com/openctemio/openctem/server/internal/app/tenant"
	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

func TestAdminOwnerSetupLink_NoEmail_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	if err := raw.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	pg := &postgres.DB{DB: raw}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(pg)
	userRepo := postgres.NewUserRepository(pg)
	tenants := tenant.NewTenantService(tenantRepo, log)
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(pg), log)
	authSvc := auth.NewAuthService(userRepo, postgres.NewSessionRepository(raw), postgres.NewRefreshTokenRepository(raw), tenantRepo, auditSvc,
		config.AuthConfig{JWTSecret: "owner-setup-link-test-secret-0123456789abcdef", JWTIssuer: "test",
			AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour}, log)

	const base = "https://app.example.test"
	newHandler := func(smtp bool) *AdminOrganizationHandler {
		prov := tenant.NewUserProvisioningService(tenantRepo, userRepo, nil, firstOwnerTestMailer{deliverable: smtp}, auditSvc, log)
		return NewAdminOrganizationHandler(postgres.NewAdminOrganizationRepository(pg), tenants, userRepo, validator.New(), log).
			WithUserProvisioning(prov).WithStepUp(recoveryStepUp{}).
			WithEmailDelivery(func() bool { return smtp }).WithAppBaseURL(base)
	}
	org := func() string {
		id := uuid.NewString()
		if _, err := raw.ExecContext(context.Background(), `INSERT INTO tenants (id, name, slug) VALUES ($1, 'Owner setup link IT', $2)`,
			id, "adm-sl-"+strings.ReplaceAll(id[:13], "-", "")); err != nil {
			t.Fatalf("seed org: %v", err)
		}
		t.Cleanup(func() {
			_, _ = raw.ExecContext(context.Background(), `DELETE FROM users WHERE id IN (SELECT user_id FROM tenant_members WHERE tenant_id = $1)`, id)
			for _, q := range []string{`DELETE FROM audit_log_chain WHERE tenant_id = $1`, `DELETE FROM audit_logs WHERE tenant_id = $1`,
				`DELETE FROM user_roles WHERE tenant_id = $1`, `DELETE FROM tenant_members WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`} {
				_, _ = raw.ExecContext(context.Background(), q, id)
			}
		})
		return id
	}
	withAdmin := func(req *http.Request) *http.Request {
		a, err := admin.NewAdminUser("sl-ops@op.example", "SL", admin.AdminRoleOpsAdmin, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.WithValue(req.Context(), middleware.AdminRoleKey, string(admin.AdminRoleOpsAdmin))
		return req.WithContext(context.WithValue(ctx, middleware.AdminUserKey, a))
	}
	// firstOwner creates the organization's first owner with email off and
	// returns the account id and the link shown at creation.
	firstOwner := func(orgID string) (string, string) {
		addr := "adm-sl-" + uuid.NewString()[:8] + "@it.test"
		t.Cleanup(func() { _, _ = raw.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, addr) })
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/tenants/"+orgID+"/users",
			strings.NewReader(`{"email":"`+addr+`","name":"Owner"}`))
		req.SetPathValue(middleware.AdminTenantParam, orgID)
		rec := httptest.NewRecorder()
		newHandler(false).CreateUser(rec, withAdmin(req))
		var out ProvisionedUserResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusCreated || out.SetupToken == "" {
			t.Fatalf("first owner: %d %s", rec.Code, rec.Body.String())
		}
		if out.SetupURL != base+"/set-password#token="+out.SetupToken {
			t.Fatalf("setup_url %q: want the web app's address of the token", out.SetupURL)
		}
		return out.User.ID, out.SetupToken
	}
	call := func(h *AdminOrganizationHandler, userID, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/platform-users/"+userID+"/setup-link", strings.NewReader(body))
		req.SetPathValue("user_id", userID)
		rec := httptest.NewRecorder()
		h.IssueOwnerSetupLink(rec, withAdmin(req))
		return rec
	}
	body := func(orgID string) string {
		return `{"organization_id":"` + orgID + `","reason":"The owner lost the first link; ticket 77"}`
	}
	setPassword := func(token string) error {
		return authSvc.ResetPassword(context.Background(), auth.ResetPasswordInput{Token: token, NewPassword: "Correct-Horse-Battery-9"})
	}

	t.Run("email off: a new link once, the old one revoked, the new one works once", func(t *testing.T) {
		id := org()
		userID, first := firstOwner(id)
		rec := call(newHandler(false), userID, body(id))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d (%s)", rec.Code, rec.Body.String())
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("Cache-Control %q, want no-store", cc)
		}
		var out ProvisionedUserResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.SetupToken == "" || out.SetupToken == first || out.EmailSent {
			t.Fatalf("answer %+v: want a new token, not emailed", out)
		}
		if out.SetupURL != base+"/set-password#token="+out.SetupToken {
			t.Fatalf("setup_url %q", out.SetupURL)
		}
		if err := setPassword(first); !errors.Is(err, auth.ErrInvalidResetToken) {
			t.Fatalf("the link shown at creation still works after a new one: err = %v", err)
		}
		if err := setPassword(out.SetupToken); err != nil {
			t.Fatalf("new link: %v", err)
		}
		if err := setPassword(out.SetupToken); !errors.Is(err, auth.ErrInvalidResetToken) {
			t.Fatalf("the new link worked twice: err = %v", err)
		}
		// Used now: no further link for this account.
		if rec := call(newHandler(false), userID, body(id)); rec.Code != http.StatusConflict {
			t.Fatalf("account in use: status %d, want 409", rec.Code)
		}
	})

	t.Run("an expired link is refused", func(t *testing.T) {
		id := org()
		userID, _ := firstOwner(id)
		rec := call(newHandler(false), userID, body(id))
		var out ProvisionedUserResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if _, err := raw.ExecContext(context.Background(), `UPDATE users SET password_reset_expires_at = now() - interval '1 minute' WHERE id = $1`, userID); err != nil {
			t.Fatal(err)
		}
		if err := setPassword(out.SetupToken); !errors.Is(err, auth.ErrInvalidResetToken) {
			t.Fatalf("expired link: err = %v", err)
		}
	})

	t.Run("email on: 409 EMAIL_AVAILABLE and the stored link is unchanged", func(t *testing.T) {
		id := org()
		userID, first := firstOwner(id)
		rec := call(newHandler(true), userID, body(id))
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "EMAIL_AVAILABLE") {
			t.Fatalf("status %d (%s), want 409 EMAIL_AVAILABLE", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "setup_token") {
			t.Fatal("a link was returned while email works")
		}
		if err := setPassword(first); err != nil {
			t.Fatalf("the refused call revoked the existing link: %v", err)
		}
	})

	t.Run("another organization's owner: 404, nothing issued", func(t *testing.T) {
		mine, other := org(), org()
		userID, first := firstOwner(other)
		if rec := call(newHandler(false), userID, body(mine)); rec.Code != http.StatusNotFound {
			t.Fatalf("status %d (%s), want 404", rec.Code, rec.Body.String())
		}
		if err := setPassword(first); err != nil {
			t.Fatalf("a refused call changed the other organization's link: %v", err)
		}
	})

	t.Run("an account in another organization too: 409", func(t *testing.T) {
		id, second := org(), org()
		userID, _ := firstOwner(id)
		if _, err := raw.ExecContext(context.Background(), `INSERT INTO tenant_members (id, tenant_id, user_id, role) VALUES ($1, $2, $3, 'member')`,
			uuid.NewString(), second, userID); err != nil {
			t.Fatalf("second membership: %v", err)
		}
		if rec := call(newHandler(false), userID, body(id)); rec.Code != http.StatusConflict {
			t.Fatalf("status %d (%s), want 409", rec.Code, rec.Body.String())
		}
	})

	t.Run("no reason: 400", func(t *testing.T) {
		id := org()
		userID, _ := firstOwner(id)
		if rec := call(newHandler(false), userID, `{"organization_id":"`+id+`"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", rec.Code)
		}
	})

	t.Run("the organization audit log records the issue, never the link", func(t *testing.T) {
		id := org()
		userID, _ := firstOwner(id)
		rec := call(newHandler(false), userID, body(id))
		var out ProvisionedUserResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		var n int
		if err := raw.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2
			AND metadata->>'setup_link_returned' = 'true' AND message LIKE 'New set-password link for the owner%'`, id, userID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("audit rows = %d, want 1", n)
		}
		var leaks int
		if err := raw.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND (message LIKE '%' || $2 || '%' OR metadata::text LIKE '%' || $2 || '%')`,
			id, out.SetupToken).Scan(&leaks); err != nil {
			t.Fatal(err)
		}
		if leaks != 0 {
			t.Fatal("the link is in the audit log")
		}
	})
}
