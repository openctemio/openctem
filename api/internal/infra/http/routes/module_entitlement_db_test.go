package routes

// Module entitlements end to end on a migrated database (RFC-064): the plan to
// module map and the platform grants decide what an organization may use; the
// route gate answers MODULE_NOT_ENABLED with reason not_entitled for that
// organization only, and an organization cannot switch on what it is not
// entitled to.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	entitlementapp "github.com/openctemio/openctem/api/internal/app/entitlement"
	moduleapp "github.com/openctemio/openctem/api/internal/app/module"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestModuleEntitlements_GateAndToggle(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping module entitlement DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	ctx := context.Background()
	if err := sqldb.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	db := &postgres.DB{DB: sqldb}

	planRepo := postgres.NewPlanRepository(db)
	ent := entitlementapp.NewService(planRepo, nil, nil, nil, logger.NewNop())
	ent.SetModuleRepository(planRepo)
	modules := moduleapp.NewModuleService(postgres.NewModuleRepository(db), logger.NewNop())
	modules.SetTenantModuleRepo(postgres.NewTenantModuleRepository(db))
	modules.SetEntitlements(ent)
	gate := middleware.NewModuleGate(modules, time.Minute)
	modules.SetModuleCacheInvalidator(gate)
	ent.SetModulesChangeNotifier(modules.NotifyEntitlementChange)

	newTenant := func(p plan.Plan) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
			id.String(), "ent "+id.String(), "ent-"+id.String()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenant_module_grants WHERE tenant_id = $1`, id.String())
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenant_modules WHERE tenant_id = $1`, id.String())
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenant_plans WHERE tenant_id = $1`, id.String())
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String())
		})
		if p != "" {
			if err := planRepo.SetTenantPlan(ctx, id, p, nil, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	ops, err := admin.NewAdminUser("ops@example.test", "Ops", admin.AdminRoleOpsAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}

	denied, other := newTenant(plan.Free), newTenant(plan.Free)
	// Nothing stored: everything entitled for both.
	if !gate.IsEnabled(ctx, denied.String(), moduledom.ModulePentest) {
		t.Fatal("pentest off before any entitlement change")
	}
	if err := ent.PutModuleGrant(ctx, ops, denied, entitlementapp.ModuleGrantInput{
		Module: moduledom.ModulePentest, Kind: plan.GrantDeny, Reason: "contract",
	}, "", ""); err != nil {
		t.Fatal(err)
	}

	serve := func(tenant shared.ID) (int, middleware.ModuleNotEnabledDetails) {
		h := gate.RequireModule(moduledom.ModulePentest)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		router := infrahttp.NewChiRouter()
		router.GET("/x", h.ServeHTTP)
		req := httptest.NewRequest(http.MethodGet, "/x", nil).
			WithContext(context.WithValue(ctx, middleware.TenantIDKey, tenant.String()))
		rec := httptest.NewRecorder()
		router.(interface{ Handler() http.Handler }).Handler().ServeHTTP(rec, req)
		var body struct {
			Details middleware.ModuleNotEnabledDetails `json:"details"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body.Details
	}

	// The deny applies at once (the grant invalidated the cache), to that
	// organization only.
	if code, d := serve(denied); code != http.StatusForbidden || d.Reason != middleware.ModuleReasonNotEntitled {
		t.Fatalf("denied organization: %d %+v, want 403 not_entitled", code, d)
	}
	if code, _ := serve(other); code != http.StatusOK {
		t.Fatalf("other organization: %d, want 200", code)
	}

	// The organization cannot switch it back on.
	_, err = modules.UpdateTenantModules(ctx, denied.String(),
		[]moduledom.TenantModuleUpdate{{ModuleID: moduledom.ModulePentest, IsEnabled: true}}, auditapp.AuditContext{})
	if !errors.Is(err, moduledom.ErrModuleNotEntitled) {
		t.Fatalf("enable a denied module: %v, want ErrModuleNotEntitled", err)
	}

	// Removing the deny restores it.
	if err := ent.DeleteModuleGrant(ctx, ops, denied, moduledom.ModulePentest, "contract ended", "", ""); err != nil {
		t.Fatal(err)
	}
	if code, _ := serve(denied); code != http.StatusOK {
		t.Fatalf("after removing the deny: %d, want 200", code)
	}

	// A plan mapping without pentest for Free, with a trial grant for one
	// organization. Restore the platform setting afterwards.
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(ctx, `DELETE FROM platform_settings WHERE key = $1`, plan.ModulesSettingKey)
	})
	_, _ = sqldb.ExecContext(ctx, `DELETE FROM platform_settings WHERE key = $1`, plan.ModulesSettingKey)
	super, err := admin.NewAdminUser("root@example.test", "Root", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ent.UpdatePlanModules(ctx, super, plan.PlanModules{
		plan.Free: {moduledom.ModuleAttackSurface}, plan.Pro: {plan.AllModules}, plan.Enterprise: {plan.AllModules},
	}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	trial := time.Now().Add(14 * 24 * time.Hour)
	if err := ent.PutModuleGrant(ctx, ops, denied, entitlementapp.ModuleGrantInput{
		Module: moduledom.ModulePentest, Kind: plan.GrantAdd, Reason: "14-day trial", ExpiresAt: &trial,
	}, "", ""); err != nil {
		t.Fatal(err)
	}
	if code, _ := serve(denied); code != http.StatusOK {
		t.Fatalf("trial organization: %d, want 200", code)
	}
	if code, d := serve(other); code != http.StatusForbidden || d.Reason != middleware.ModuleReasonNotEntitled {
		t.Fatalf("free organization without the trial: %d %+v, want 403 not_entitled", code, d)
	}
	enterprise := newTenant("")
	if code, _ := serve(enterprise); code != http.StatusOK {
		t.Fatalf("organization without a plan (Enterprise): %d, want 200", code)
	}
}
