package integration

// Plans and limits (docs/architecture/plans-and-limits.md), against a real
// Postgres: a self-service organization starts on the Free plan, and one
// person owns at most the Free plan's free_teams_per_user (1 by default) when
// creating another through POST /tenants.
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
	"github.com/openctemio/openctem/api/internal/app/entitlement"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func TestFreePlanOnSelfServiceOrganizations(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	log := logger.NewNop()
	// The built-in defaults apply (free_teams_per_user = 1).
	if _, err := db.Exec(`DELETE FROM platform_settings WHERE key = $1`, plan.SettingKey); err != nil {
		t.Fatal(err)
	}
	ent := entitlement.NewService(postgres.NewPlanRepository(db), nil, nil, nil, log)

	svc := orgAuthService(db, config.TenantCreationSelfService)
	svc.SetFreePlan(ent)
	email, refresh := orgSelfServiceUser(t, db, svc)
	slug := "free-" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, slug) })

	res, err := svc.CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{RefreshToken: refresh, TeamName: "Free Team", TeamSlug: slug})
	if err != nil {
		t.Fatalf("first Free organization: %v", err)
	}
	var p string
	if err := db.QueryRow(`SELECT plan FROM tenant_plans WHERE tenant_id = $1`, res.Tenant.TenantID).Scan(&p); err != nil || p != "free" {
		t.Fatalf("plan of the new organization: %q %v", p, err)
	}

	// create-first-team serves people with no organization; a second one
	// goes through POST /tenants, where the cap applies: 403 PLAN_LIMIT,
	// nothing created.
	var n int
	u, err := postgres.NewUserRepository(db).GetByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	tenantSvc := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
		tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
	h := handler.NewTenantHandler(tenantSvc, validator.New(), log)
	h.SetSelfServiceTenantCreation(true)
	h.SetFreePlan(ent)
	slug3 := "free3-" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, slug3) })
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(`{"name":"Third Org","slug":"`+slug3+`"}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.LocalUserKey, u))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "PLAN_LIMIT") {
		t.Fatalf("POST /tenants over the Free cap: %d %s", rec.Code, rec.Body)
	}
	if err := db.QueryRow(`SELECT count(*) FROM tenants WHERE slug = $1`, slug3).Scan(&n); err != nil || n != 0 {
		t.Fatalf("refused organization was created: %d %v", n, err)
	}

	// A platform administrator moving the first organization to Pro frees
	// the Free slot.
	if _, err := db.Exec(`UPDATE tenant_plans SET plan = 'pro' WHERE tenant_id = $1`, res.Tenant.TenantID); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(`{"name":"Third Org","slug":"`+slug3+`"}`))
	h.Create(rec, req.WithContext(context.WithValue(req.Context(), middleware.LocalUserKey, u)))
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("Free slot freed, POST /tenants: %d %s", rec.Code, rec.Body)
	}
	if err := db.QueryRow(`SELECT count(*) FROM tenant_plans p JOIN tenants t ON t.id = p.tenant_id WHERE t.slug = $1 AND p.plan = 'free'`, slug3).Scan(&n); err != nil || n != 1 {
		t.Fatalf("POST /tenants organization must be Free: %d %v", n, err)
	}
}
