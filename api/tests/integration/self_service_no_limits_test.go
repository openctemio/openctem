package integration

// Self-service organizations get no limits (docs/architecture/plans-and-limits.md),
// against a real Postgres: neither create-first-team nor POST /tenants
// assigns a plan, and one person may create several organizations. Limits
// apply only where an operator sets them for an organization; a self-hosted
// install with self-service sign-up on must never cap new organizations on
// its own.
//
// Requires DATABASE_URL pointing at a fully migrated database.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func TestSelfServiceOrganizationsHaveNoLimits(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	log := logger.NewNop()

	svc := orgAuthService(db, config.SignupModeOpen)
	email, refresh := orgSelfServiceUser(t, db, svc)
	slug := "ss-" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, slug) })

	res, err := svc.CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{RefreshToken: refresh, TeamName: "First Team", TeamSlug: slug})
	if err != nil {
		t.Fatalf("first organization: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM tenant_plans WHERE tenant_id = $1`, res.Tenant.TenantID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("create-first-team must not assign a plan: %d %v", n, err)
	}

	// More organizations through POST /tenants: no per-person cap, no plan.
	u, err := postgres.NewUserRepository(db).GetByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	tenantSvc := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
		tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
	h := handler.NewTenantHandler(tenantSvc, validator.New(), log)
	h.SetSelfServiceTenantCreation(true)
	for i := 0; i < 2; i++ {
		s := "ss" + string(rune('a'+i)) + "-" + uuid.NewString()[:8]
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, s) })
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(`{"name":"Org `+s+`","slug":"`+s+`"}`))
		rec := httptest.NewRecorder()
		h.Create(rec, req.WithContext(context.WithValue(req.Context(), middleware.LocalUserKey, u)))
		if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
			t.Fatalf("POST /tenants #%d: %d %s", i+1, rec.Code, rec.Body)
		}
		if err := db.QueryRow(`SELECT count(*) FROM tenant_plans p JOIN tenants t ON t.id = p.tenant_id WHERE t.slug = $1`, s).Scan(&n); err != nil || n != 0 {
			t.Fatalf("POST /tenants must not assign a plan: %d %v", n, err)
		}
	}
}
