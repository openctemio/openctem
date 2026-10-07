package routes

// Scan runs follow the core scans module, not scan_workflows. A tenant on the
// asset_inventory or compliance preset (or minimal) has scan_workflows switched
// off; before this gate moved, the Scans Runs tab, a scan's run history, its
// task logs and run cancel all answered 403 MODULE_NOT_ENABLED for them. The
// module state comes from a migrated database through the real module
// service and gate; the templates keep their scan_workflows gate.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	moduleapp "github.com/openctemio/openctem/api/internal/app/module"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestScanRuns_FollowScansModuleOnPresets(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping module gate DB test")
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
	modules := moduleapp.NewModuleService(postgres.NewModuleRepository(db), logger.NewNop())
	modules.SetTenantModuleRepo(postgres.NewTenantModuleRepository(db))

	perms := []string{
		permission.ScanWorkflowsRead.String(), permission.ScanWorkflowsWrite.String(),
		permission.ScansRead.String(), permission.ScansWrite.String(),
	}
	const runID = "01a0f6e2-35a7-7cae-af10-874c1481fe6e"

	// The minimal preset has the same effect on scan_workflows; it is not
	// listed because applying it trips the 50-updates cap of
	// UpdateTenantModules, a separate defect.
	for _, preset := range []string{"asset_inventory", "compliance"} {
		t.Run(preset, func(t *testing.T) {
			tenant := shared.NewID().String()
			if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
				tenant, "runs-gate "+preset, "runs-gate-"+tenant); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenant_modules WHERE tenant_id = $1`, tenant)
				_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenant)
			})
			if _, err := modules.ApplyPreset(ctx, tenant, preset, auditapp.AuditContext{}); err != nil {
				t.Fatalf("apply preset: %v", err)
			}
			if !modules.TenantDisabledModules(ctx, tenant)["scan_workflows"] {
				t.Fatalf("preset %s left scan_workflows on; the test needs it off", preset)
			}

			router := infrahttp.NewChiRouter()
			as := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c := context.WithValue(r.Context(), middleware.IsAdminKey, false)
					c = context.WithValue(c, middleware.PermissionsKey, perms)
					c = context.WithValue(c, middleware.TenantIDKey, tenant)
					next.ServeHTTP(w, r.WithContext(c))
				})
			}
			// A nil service panics once the gates let the request through,
			// which is how "reached the handler" is observed.
			registerScanWorkflowRoutes(router, handler.NewScanWorkflowHandler(nil, nil, logger.NewNop()), as, nil,
				middleware.NewModuleGate(modules, 0))
			mux := router.(interface{ Handler() http.Handler }).Handler()
			serve := func(method, path string) (code int, body string, reached bool) {
				defer func() {
					if recover() != nil {
						reached = true
					}
				}()
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
				return rec.Code, rec.Body.String(), false
			}

			// Scan runs: every route passes the module gate.
			for _, rt := range []struct{ method, path string }{
				{http.MethodGet, "/api/v1/scan-runs/"},
				{http.MethodGet, "/api/v1/scan-runs/" + runID},
				{http.MethodGet, "/api/v1/scan-runs/" + runID + "/tasks"},
				{http.MethodGet, "/api/v1/scan-runs/" + runID + "/tasks/" + runID + "/logs"},
				{http.MethodGet, "/api/v1/scan-runs/" + runID + "/stages"},
				{http.MethodPost, "/api/v1/scan-runs/" + runID + "/cancel"},
			} {
				// The handler either panics on its nil service or answers
				// without one (the task log read); either way the gates passed.
				if code, body, reached := serve(rt.method, rt.path); !reached && code == http.StatusForbidden {
					t.Errorf("%s %s: %d %s, want it to pass the module gate", rt.method, rt.path, code, body)
				}
			}

			// Scan workflow templates keep the scan_workflows gate.
			code, body, reached := serve(http.MethodGet, "/api/v1/scan-workflows/")
			if reached || code != http.StatusForbidden || !strings.Contains(body, "MODULE_NOT_ENABLED") {
				t.Errorf("GET /scan-workflows: %d %s reached=%v, want 403 MODULE_NOT_ENABLED", code, body, reached)
			}
		})
	}
}

// Moving the module gate widens nothing across tenants: a member of a tenant
// on a preset without scan_workflows reads its own run and gets 404 for a run
// of another tenant.
func TestScanRuns_OtherTenantRunIsNotFound(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping module gate DB test")
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
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqldb.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	db := &postgres.DB{DB: sqldb}
	modules := moduleapp.NewModuleService(postgres.NewModuleRepository(db), logger.NewNop())
	modules.SetTenantModuleRepo(postgres.NewTenantModuleRepository(db))

	// seed adds a tenant on the asset_inventory preset with one run.
	seed := func() (tenant, run string) {
		tpl := shared.NewID().String()
		tenant, run = shared.NewID().String(), shared.NewID().String()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'runs-xt', $2)`, tenant, "runs-xt-"+tenant)
		exec(`INSERT INTO scan_workflows (id, tenant_id, name) VALUES ($1, $2, 'runs-xt')`, tpl, tenant)
		exec(`INSERT INTO scan_runs (id, tenant_id, scan_workflow_id, trigger_type) VALUES ($1, $2, $3, 'manual')`, run, tenant, tpl)
		t.Cleanup(func() {
			for _, q := range []string{
				`DELETE FROM scan_runs WHERE tenant_id = $1`,
				`DELETE FROM scan_workflows WHERE tenant_id = $1`,
				`DELETE FROM tenant_modules WHERE tenant_id = $1`,
				`DELETE FROM tenants WHERE id = $1`,
			} {
				_, _ = sqldb.ExecContext(ctx, q, tenant)
			}
		})
		if _, err := modules.ApplyPreset(ctx, tenant, "asset_inventory", auditapp.AuditContext{}); err != nil {
			t.Fatalf("apply preset: %v", err)
		}
		return tenant, run
	}
	tenantA, runA := seed()
	_, runB := seed()

	svc := scanrun.NewService(postgres.NewScanWorkflowRepository(db), postgres.NewScanWorkflowStepRepository(db),
		postgres.NewScanRunRepository(db), postgres.NewStepRunRepository(db), nil, nil, nil, logger.NewNop())
	router := infrahttp.NewChiRouter()
	as := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := context.WithValue(r.Context(), middleware.IsAdminKey, false)
			c = context.WithValue(c, middleware.PermissionsKey, []string{permission.ScansRead.String()})
			c = context.WithValue(c, middleware.TenantIDKey, tenantA)
			next.ServeHTTP(w, r.WithContext(c))
		})
	}
	registerScanWorkflowRoutes(router, handler.NewScanWorkflowHandler(svc, nil, logger.NewNop()), as, nil,
		middleware.NewModuleGate(modules, 0))
	mux := router.(interface{ Handler() http.Handler }).Handler()
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}

	if code, body := get("/api/v1/scan-runs/" + runA); code != http.StatusOK {
		t.Fatalf("own run: %d %s, want 200", code, body)
	}
	for _, p := range []string{"", "/tasks", "/stages"} {
		if code, body := get("/api/v1/scan-runs/" + runB + p); code != http.StatusNotFound {
			t.Errorf("other tenant's run%s: %d %s, want 404", p, code, body)
		}
	}
}
