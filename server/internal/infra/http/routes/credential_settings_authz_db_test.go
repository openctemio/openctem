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

	cst "github.com/openctemio/openctem/server/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/server/internal/app/leakedsecretpolicy"
	tenantapp "github.com/openctemio/openctem/server/internal/app/tenant"
	infrahttp "github.com/openctemio/openctem/server/internal/infra/http"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

// The leaked-credential policy lives under the token singleton: the
// organization comes from the credential, only an owner/admin may read or
// change it, a write lands in the caller's organization only, and the
// resolver the import uses then answers per organization (A keeps nothing,
// B still follows the platform default).
func TestCredentialSettingsAuthz_AdminOnlyAndTokenTenant(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping credential settings authz DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	tenantA, tenantB := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tenantA, tenantB} {
		if _, err := db.ExecContext(context.Background(), `INSERT INTO tenants (id, name, slug) VALUES ($1, 'cred-policy', $2)`, id.String(), "credpol-"+id.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA.String(), tenantB.String())
	})

	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.UserIDKey, shared.NewID().String())
			ctx = context.WithValue(ctx, middleware.TenantIDKey, tenantA.String())
			ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
			ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{"settings:read", "settings:write", "findings:credentials:read"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	router := infrahttp.NewChiRouter()
	tenants := postgres.NewTenantRepository(pg)
	svc := tenantapp.NewTenantService(tenants, log)
	platform := leakedsecretpolicy.NewService(cst.NewRepo(), cst.Recorder(&cst.Audit{}, &cst.Notifier{}), false, log)
	h := handler.NewTenantHandler(svc, validator.New(), log)
	h.SetLeakedSecretDefault(platform)
	registerCredentialSettingsRoutes(router, h, Middleware(auth), nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	do := func(method string, admin bool, body string) (int, string) {
		req, _ := http.NewRequestWithContext(context.Background(), method, srv.URL+"/api/v1/organization/settings/credentials", strings.NewReader(body))
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

	if status, body := do(http.MethodPut, false, `{"store_secret_values":true}`); status != http.StatusForbidden {
		t.Fatalf("member PUT credential policy = %d, want 403 (%s)", status, body)
	}
	if status, body := do(http.MethodGet, false, ""); status != http.StatusForbidden {
		t.Fatalf("member GET credential policy = %d, want 403 (%s)", status, body)
	}
	if status, body := do(http.MethodGet, true, ""); status != http.StatusOK ||
		!strings.Contains(body, `"platform_default":true`) || !strings.Contains(body, `"effective":true`) || strings.Contains(body, "store_secret_values") {
		t.Fatalf("admin GET default credential policy = %d (%s)", status, body)
	}
	if status, body := do(http.MethodPut, true, `{"store_secret_values":false,"tenant_id":"`+tenantB.String()+`"}`); status != http.StatusBadRequest {
		t.Fatalf("unknown field must be refused: %d (%s)", status, body)
	}
	if status, body := do(http.MethodPut, true, `{"store_secret_values":false}`); status != http.StatusOK ||
		!strings.Contains(body, `"store_secret_values":false`) || !strings.Contains(body, `"effective":false`) {
		t.Fatalf("admin PUT credential policy = %d (%s)", status, body)
	}
	var a, b sql.NullString
	_ = db.QueryRowContext(context.Background(), `SELECT settings->'credentials'->>'store_secret_values' FROM tenants WHERE id = $1`, tenantA.String()).Scan(&a)
	_ = db.QueryRowContext(context.Background(), `SELECT settings->'credentials'->>'store_secret_values' FROM tenants WHERE id = $1`, tenantB.String()).Scan(&b)
	if a.String != "false" || b.Valid {
		t.Fatalf("policy written to the wrong organization: A=%q B=%q", a.String, b.String)
	}
	r := leakedsecretpolicy.NewResolver(platform, tenants, log)
	if r.StoresSecretValues(context.Background(), tenantA) || !r.StoresSecretValues(context.Background(), tenantB) {
		t.Fatal("resolver: A chose off, B follows the self-managed default (on)")
	}
}
