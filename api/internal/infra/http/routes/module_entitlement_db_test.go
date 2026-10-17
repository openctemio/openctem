package routes

// Module entitlements end to end on a migrated database (RFC-064): every
// module is available unless the operator or the control plane denies it for
// one organization; the route gate answers MODULE_NOT_ENABLED for that
// organization only, and an organization cannot switch on what is denied. A module the
// organization loses enters 30 days of read-only grace: reads pass, writes get
// reason read_only_grace, jobs see it off; afterwards reason not_entitled.

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
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
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

	limRepo := postgres.NewLimitsRepository(db)
	ent := entitlementapp.NewService(limRepo, nil, logger.NewNop())
	ent.SetSources(entitlementapp.NewControlPlaneSource(limRepo))
	modules := moduleapp.NewModuleService(postgres.NewModuleRepository(db), logger.NewNop())
	modules.SetTenantModuleRepo(postgres.NewTenantModuleRepository(db))
	modules.SetEntitlements(ent)
	gate := middleware.NewModuleGate(modules, time.Minute)
	modules.SetModuleCacheInvalidator(gate)
	ent.SetModulesChangeNotifier(modules.NotifyEntitlementChange)

	newTenant := func() shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
			id.String(), "ent "+id.String(), "ent-"+id.String()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenant_feature_denies WHERE tenant_id = $1`, id.String())
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenant_module_grace WHERE tenant_id = $1`, id.String())
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenant_modules WHERE tenant_id = $1`, id.String())
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String())
		})
		return id
	}
	ops, err := admin.NewAdminUser("ops@example.test", "Ops", admin.AdminRoleOpsAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}

	denied, other := newTenant(), newTenant()
	// Nothing stored: everything entitled for both.
	if !gate.IsEnabled(ctx, denied.String(), moduledom.ModulePentest) {
		t.Fatal("pentest off before any entitlement change")
	}
	if err := ent.PutDeny(ctx, ops, denied, entitlementapp.DenyInput{
		Feature: moduledom.ModulePentest, Reason: "contract",
	}, "", ""); err != nil {
		t.Fatal(err)
	}

	serveMethod := func(method string, tenant shared.ID) (int, middleware.ModuleNotEnabledDetails) {
		h := gate.RequireModule(moduledom.ModulePentest)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		router := infrahttp.NewChiRouter()
		router.GET("/x", h.ServeHTTP)
		router.POST("/x", h.ServeHTTP)
		req := httptest.NewRequest(method, "/x", nil).
			WithContext(context.WithValue(ctx, middleware.TenantIDKey, tenant.String()))
		rec := httptest.NewRecorder()
		router.(interface{ Handler() http.Handler }).Handler().ServeHTTP(rec, req)
		var body struct {
			Details middleware.ModuleNotEnabledDetails `json:"details"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body.Details
	}
	serve := func(tenant shared.ID) (int, middleware.ModuleNotEnabledDetails) {
		return serveMethod(http.MethodGet, tenant)
	}
	write := func(tenant shared.ID) (int, middleware.ModuleNotEnabledDetails) {
		return serveMethod(http.MethodPost, tenant)
	}
	graceUntil := func(tenant shared.ID) (until time.Time, ok bool) {
		err := sqldb.QueryRowContext(ctx, `SELECT read_only_until FROM tenant_module_grace
			WHERE tenant_id = $1 AND module_id = $2`, tenant.String(), moduledom.ModulePentest).Scan(&until)
		return until, err == nil
	}
	// endGrace moves the grace into the past, as if 30 days went by.
	endGrace := func(tenant shared.ID) {
		t.Helper()
		if _, err := sqldb.ExecContext(ctx, `UPDATE tenant_module_grace SET read_only_until = now() - interval '1 second'
			WHERE tenant_id = $1`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		gate.Invalidate(tenant.String())
	}

	// The deny applies at once (the grant invalidated the cache), to that
	// organization only: 30 days of read-only grace start.
	until, ok := graceUntil(denied)
	if !ok || until.Before(time.Now().Add(limits.GracePeriod-time.Hour)) {
		t.Fatalf("grace after the deny: %v %v, want about 30 days", ok, until)
	}
	if code, _ := serve(denied); code != http.StatusOK {
		t.Fatalf("denied organization, read in grace: %d, want 200", code)
	}
	if code, d := write(denied); code != http.StatusForbidden || d.Reason != middleware.ModuleReasonReadOnlyGrace {
		t.Fatalf("denied organization, write in grace: %d %+v, want 403 read_only_grace", code, d)
	}
	if gate.IsEnabled(ctx, denied.String(), moduledom.ModulePentest) {
		t.Fatal("jobs must see a module in grace as off")
	}
	if code, _ := write(other); code != http.StatusOK {
		t.Fatalf("other organization: %d, want 200", code)
	}
	if _, ok := graceUntil(other); ok {
		t.Fatal("a deny on one organization started grace on another")
	}
	// After the grace: no access at all.
	endGrace(denied)
	if code, d := serve(denied); code != http.StatusForbidden || d.Reason != middleware.ModuleReasonNotEntitled {
		t.Fatalf("denied organization after grace: %d %+v, want 403 not_entitled", code, d)
	}

	// The organization cannot switch it back on.
	_, err = modules.UpdateTenantModules(ctx, denied.String(),
		[]moduledom.TenantModuleUpdate{{ModuleID: moduledom.ModulePentest, IsEnabled: true}}, auditapp.AuditContext{})
	if !errors.Is(err, moduledom.ErrModuleNotEntitled) {
		t.Fatalf("enable a denied module: %v, want ErrModuleNotEntitled", err)
	}

	// Removing the deny restores it.
	if err := ent.DeleteDeny(ctx, ops, denied, moduledom.ModulePentest, "contract ended", "", ""); err != nil {
		t.Fatal(err)
	}
	if code, _ := write(denied); code != http.StatusOK {
		t.Fatalf("after removing the deny: %d, want 200", code)
	}
	if _, ok := graceUntil(denied); ok {
		t.Fatal("regaining the module must end its grace")
	}

	// The control plane denies pentest to the other organization (its
	// source, its own rows): the same grace, then no access; the operator's
	// own deny list is untouched, and lifting it through the control plane
	// restores the module.
	call := entitlementapp.ControlPlaneCall{Subject: "test", TokenID: "jti-1", Reason: "service tier"}
	if err := ent.ApplyControlPlane(ctx, other, nil, []string{moduledom.ModulePentest}, call); err != nil {
		t.Fatal(err)
	}
	if _, ok := graceUntil(other); !ok {
		t.Fatal("a control-plane deny must start grace")
	}
	if code, _ := serve(other); code != http.StatusOK {
		t.Fatalf("other organization, read in grace: %d, want 200", code)
	}
	if code, d := write(other); code != http.StatusForbidden || d.Reason != middleware.ModuleReasonReadOnlyGrace {
		t.Fatalf("other organization, write in grace: %d %+v, want 403 read_only_grace", code, d)
	}
	endGrace(other)
	if code, d := serve(other); code != http.StatusForbidden || d.Reason != middleware.ModuleReasonNotEntitled {
		t.Fatalf("other organization after grace: %d %+v, want 403 not_entitled", code, d)
	}
	if code, _ := write(denied); code != http.StatusOK {
		t.Fatalf("the first organization is unaffected: %d", code)
	}
	if err := ent.ApplyControlPlane(ctx, other, nil, nil, call); err != nil {
		t.Fatal(err)
	}
	if code, _ := write(other); code != http.StatusOK {
		t.Fatalf("control plane lifted its deny: %d, want 200", code)
	}
	fresh := newTenant()
	if code, _ := write(fresh); code != http.StatusOK {
		t.Fatalf("an organization nobody limited: %d, want 200", code)
	}
}
