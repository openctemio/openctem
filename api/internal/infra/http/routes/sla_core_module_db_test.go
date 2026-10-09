package routes

// SLA is a core module: every finding carries an SLA deadline, so the policy
// reads behind the SLA badges must answer for every organization. Before, an
// organization with the sla module off (by a toggle or a preset) got
// 403 MODULE_NOT_ENABLED from /assets/{id}/sla-policy while its findings still
// showed SLA badges. The module state comes from a migrated database through
// the real module service and gate.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	moduleapp "github.com/openctemio/openctem/api/internal/app/module"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestSLAPolicyRoutes_AnswerWhateverTheModuleState(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping SLA module DB test")
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

	newTenant := func(t *testing.T) string {
		t.Helper()
		tenant := shared.NewID().String()
		if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
			tenant, "sla-core "+tenant, "sla-core-"+tenant); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenant_modules WHERE tenant_id = $1`, tenant)
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenant)
		})
		return tenant
	}

	cases := map[string]func(t *testing.T, tenant string){
		// A row left by an organization that switched SLA off before it
		// became core: ignored.
		"stale off override": func(t *testing.T, tenant string) {
			if _, err := sqldb.ExecContext(ctx,
				`INSERT INTO tenant_modules (tenant_id, module_id, is_enabled) VALUES ($1, 'sla', FALSE)`, tenant); err != nil {
				t.Fatal(err)
			}
		},
		// A preset that does not list sla.
		"asset_inventory preset": func(t *testing.T, tenant string) {
			if _, err := modules.ApplyPreset(ctx, tenant, "asset_inventory", auditapp.AuditContext{}); err != nil {
				t.Fatalf("apply preset: %v", err)
			}
		},
	}

	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			tenant := newTenant(t)
			setup(t, tenant)

			// A member with only the read permissions the routes ask for.
			perms := []string{permission.SLARead.String(), permission.AssetsRead.String()}
			as := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c := context.WithValue(r.Context(), middleware.IsAdminKey, false)
					c = context.WithValue(c, middleware.PermissionsKey, perms)
					c = context.WithValue(c, middleware.TenantIDKey, tenant)
					next.ServeHTTP(w, r.WithContext(c))
				})
			}
			router := infrahttp.NewChiRouter()
			// A nil service panics once the gates let the request through,
			// which is how "reached the handler" is observed.
			registerSLARoutes(router, handler.NewSLAHandler(nil, nil, logger.NewNop()), as, nil)
			gate := middleware.NewModuleGate(modules, 0)
			if !gate.IsEnabled(ctx, tenant, moduledom.ModuleSLA) {
				t.Fatalf("module gate reports sla off for %s", name)
			}
			mux := router.(interface{ Handler() http.Handler }).Handler()

			const assetID = "01a0f6e2-35a7-7cae-af10-874c1481fe6e"
			for _, path := range []string{
				"/api/v1/assets/" + assetID + "/sla-policy/",
				"/api/v1/sla-policies/",
				"/api/v1/sla-policies/default",
			} {
				func() {
					reached := false
					rec := httptest.NewRecorder()
					func() {
						defer func() {
							if recover() != nil {
								reached = true
							}
						}()
						mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
					}()
					if !reached && rec.Code == http.StatusForbidden {
						t.Errorf("GET %s: %d %s, want it to reach the handler", path, rec.Code, rec.Body.String())
					}
				}()
			}
		})
	}

	t.Run("cannot be switched off", func(t *testing.T) {
		tenant := newTenant(t)
		_, err := modules.UpdateTenantModules(ctx, tenant,
			[]moduledom.TenantModuleUpdate{{ModuleID: moduledom.ModuleSLA, IsEnabled: false}}, auditapp.AuditContext{})
		if !errors.Is(err, moduledom.ErrCoreModuleCannotBeDisabled) {
			t.Fatalf("disable sla: err = %v, want ErrCoreModuleCannotBeDisabled", err)
		}
	})
}
