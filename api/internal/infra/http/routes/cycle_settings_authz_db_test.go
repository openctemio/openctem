package routes

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// The CTEM cycle policy lives under the token singleton: the organization
// comes from the credential (no tenant in the path to point elsewhere), only an
// owner/admin may read or change it, and a write lands in the caller's
// organization only.
func TestCycleSettingsAuthz_AdminOnlyAndTokenTenant(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping cycle settings authz DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	tenantA, tenantB := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tenantA, tenantB} {
		if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'cycle-policy', $2)`, id.String(), "cyclepol-"+id.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA.String(), tenantB.String()) })

	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.UserIDKey, shared.NewID().String())
			ctx = context.WithValue(ctx, middleware.TenantIDKey, tenantA.String())
			ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
			ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{"ctem_cycles:read", "ctem_cycles:write"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	router := infrahttp.NewChiRouter()
	svc := tenantapp.NewTenantService(postgres.NewTenantRepository(pg), log)
	registerCycleSettingsRoutes(router, handler.NewTenantHandler(svc, validator.New(), log), Middleware(auth), nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	do := func(method string, admin bool, body string) (int, string) {
		req, _ := http.NewRequestWithContext(context.Background(), method, srv.URL+"/api/v1/organization/settings/cycles", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if admin {
			req.Header.Set("X-Test-Admin", "1")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if status, body := do(http.MethodPut, false, `{"enforce_coverage_slo":true}`); status != http.StatusForbidden {
		t.Fatalf("member PUT cycle policy = %d, want 403 (%s)", status, body)
	}
	if status, body := do(http.MethodGet, false, ""); status != http.StatusForbidden {
		t.Fatalf("member GET cycle policy = %d, want 403 (%s)", status, body)
	}
	if status, body := do(http.MethodGet, true, ""); status != http.StatusOK || !strings.Contains(body, `"enforce_coverage_slo":false`) {
		t.Fatalf("admin GET default cycle policy = %d (%s)", status, body)
	}
	if status, body := do(http.MethodPut, true, `{"enforce_coverage_slo":true,"tenant_id":"`+tenantB.String()+`"}`); status != http.StatusBadRequest {
		t.Fatalf("unknown field must be refused: %d (%s)", status, body)
	}
	if status, body := do(http.MethodPut, true, `{"enforce_coverage_slo":true}`); status != http.StatusOK || !strings.Contains(body, `"enforce_coverage_slo":true`) {
		t.Fatalf("admin PUT cycle policy = %d (%s)", status, body)
	}
	var a, b sql.NullString
	_ = db.QueryRow(`SELECT settings->'cycles'->>'enforce_coverage_slo' FROM tenants WHERE id = $1`, tenantA.String()).Scan(&a)
	_ = db.QueryRow(`SELECT settings->'cycles'->>'enforce_coverage_slo' FROM tenants WHERE id = $1`, tenantB.String()).Scan(&b)
	if a.String != "true" || b.String == "true" {
		t.Fatalf("policy written to the wrong organization: A=%q B=%q", a.String, b.String)
	}
}
