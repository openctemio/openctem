package routes

// "Retest now" authorization (RFC-039 §8.3) over the real route registration,
// middleware chain (permission gate + DataScopeGuard), handler, service and a
// migrated database:
//   - findings:verify is required (a member holding only findings:write is 403);
//   - a finding of ANOTHER tenant is 404, and nothing is queued;
//   - a restricted member gets 404 for a finding outside their data scope;
//   - an in-scope member with findings:verify gets 202 and one retest.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	tenantsvc "github.com/openctemio/openctem/api/internal/app/tenant"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/validation"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type rtNucleiOnline struct{}

func (rtNucleiOnline) HasNucleiValidationSensor(context.Context, shared.ID) (bool, error) {
	return true, nil
}

type rtHarness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server

	tenantA, tenantB               shared.ID
	verifier, writer, scoped       shared.ID
	assetA1, assetA2, assetB       shared.ID
	findingA1, findingA2, findingB shared.ID
}

func newRetestAuthzHarness(t *testing.T) *rtHarness {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping retest authz DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	h := &rtHarness{t: t, db: db}
	h.seed()

	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(pg),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	prevGuard := dataScopeGuardMiddleware
	dataScopeGuardMiddleware = middleware.DataScopeGuard(enforcer)
	t.Cleanup(func() { dataScopeGuardMiddleware = prevGuard })

	cmds := postgres.NewCommandRepository(pg)
	svc := retestapp.NewService(postgres.NewFindingRetestRepository(pg), postgres.NewFindingRepository(pg),
		postgres.NewAssetRepository(pg), cmds, validation.NewCommandDispatcher(cmds, realProbeGate(pg, log), log), rtNucleiOnline{}, log)

	router := infrahttp.NewChiRouter()
	registerFindingRetestRoutes(router, handler.NewFindingRetestHandler(svc, log), Middleware(h.auth), nil)
	tenantSvc := tenantsvc.NewTenantService(postgres.NewTenantRepository(pg), log)
	registerRetestSettingsRoutes(router, handler.NewTenantHandler(tenantSvc, validator.New(), log), Middleware(h.auth), nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

// auth stands in for UnifiedAuth: the caller is always in tenant A; the test
// names the user and their permissions.
func (h *rtHarness) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
		ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantA.String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
		ctx = context.WithValue(ctx, middleware.PermissionsKey, strings.Split(r.Header.Get("X-Test-Perms"), ","))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *rtHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func (h *rtHarness) seed() {
	h.tenantA, h.tenantB = shared.NewID(), shared.NewID()
	h.verifier, h.writer, h.scoped = shared.NewID(), shared.NewID(), shared.NewID()
	h.assetA1, h.assetA2, h.assetB = shared.NewID(), shared.NewID(), shared.NewID()
	h.findingA1, h.findingA2, h.findingB = shared.NewID(), shared.NewID(), shared.NewID()

	for _, tid := range []shared.ID{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tid.String(), "rt-"+tid.String())
		// Each tenant authorizes its domain for active checks (RFC-036 §6.3).
		h.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', '*.example.com', 'active')`, tid.String())
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tid := range []shared.ID{h.tenantA, h.tenantB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM commands WHERE tenant_id = $1`, tid.String())
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String())
		}
		for _, u := range []shared.ID{h.verifier, h.writer, h.scoped} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})
	for _, u := range []shared.ID{h.verifier, h.writer, h.scoped} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'member')`, u.String(), u.String()+"@rt.test")
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u.String(), h.tenantA.String())
	}
	assets := []struct {
		id     shared.ID
		tenant shared.ID
		name   string
	}{{h.assetA1, h.tenantA, "a1.example.com"}, {h.assetA2, h.tenantA, "a2.example.com"}, {h.assetB, h.tenantB, "b.example.com"}}
	for _, a := range assets {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'domain', 'active')`,
			a.id.String(), a.tenant.String(), a.name)
	}
	findings := []struct{ id, tenant, asset shared.ID }{
		{h.findingA1, h.tenantA, h.assetA1}, {h.findingA2, h.tenantA, h.assetA2}, {h.findingB, h.tenantB, h.assetB},
	}
	for _, f := range findings {
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'dast', 'nuclei', 'exposed-panel', 'hit', 'high', $1::text, 'confirmed')`,
			f.id.String(), f.tenant.String(), f.asset.String())
	}
	// The scoped member's data scope is asset A1 only; the verifier and the
	// writer hold both of tenant A's assets, so their checks are about
	// permissions, not data scope (a member with no scope row sees nothing).
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.scoped.String(), h.tenantA.String(), h.assetA1.String())
	for _, u := range []shared.ID{h.verifier, h.writer} {
		for _, a := range []shared.ID{h.assetA1, h.assetA2} {
			h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
				u.String(), h.tenantA.String(), a.String())
		}
	}
}

func (h *rtHarness) do(user shared.ID, perms []permission.Permission, method, path string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	names := make([]string, 0, len(perms))
	for _, p := range perms {
		names = append(names, p.String())
	}
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("X-Test-Perms", strings.Join(names, ","))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (h *rtHarness) retests(finding shared.ID) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM finding_retests WHERE finding_id = $1`, finding.String()).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

var (
	rtVerifyPerms = []permission.Permission{permission.FindingsRead, permission.FindingsWrite, permission.FindingsVerify} //nolint:gochecknoglobals // fixture
	rtWritePerms  = []permission.Permission{permission.FindingsRead, permission.FindingsWrite, permission.FindingsStatus} //nolint:gochecknoglobals // fixture
)

func TestRetestAuthz_RequiresFindingsVerify(t *testing.T) {
	h := newRetestAuthzHarness(t)
	status, body := h.do(h.writer, rtWritePerms, http.MethodPost, "/api/v1/findings/"+h.findingA1.String()+"/retests")
	if status != http.StatusForbidden {
		t.Fatalf("member without findings:verify: POST retest = %d, want 403 (%s)", status, body)
	}
	if n := h.retests(h.findingA1); n != 0 {
		t.Fatalf("a refused request queued %d retests", n)
	}
	// Reading the history only needs findings:read.
	if status, body := h.do(h.writer, rtWritePerms, http.MethodGet, "/api/v1/findings/"+h.findingA1.String()+"/retests"); status != http.StatusOK {
		t.Fatalf("GET retests with findings:read = %d (%s)", status, body)
	}
}

func TestRetestAuthz_CrossTenantFindingIsNotFound(t *testing.T) {
	h := newRetestAuthzHarness(t)
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		status, body := h.do(h.verifier, rtVerifyPerms, method, "/api/v1/findings/"+h.findingB.String()+"/retests")
		if status != http.StatusNotFound {
			t.Errorf("%s another tenant's finding = %d, want 404 (%s)", method, status, body)
		}
		if strings.Contains(body, "b.example.com") || strings.Contains(body, "exposed-panel") {
			t.Errorf("%s leaked the other tenant's finding: %s", method, body)
		}
	}
	if n := h.retests(h.findingB); n != 0 {
		t.Fatalf("a cross-tenant request queued %d retests", n)
	}
	var cmds int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM commands WHERE tenant_id IN ($1, $2)`, h.tenantA.String(), h.tenantB.String()).Scan(&cmds)
	if cmds != 0 {
		t.Fatalf("a cross-tenant request queued %d commands", cmds)
	}
}

func TestRetestAuthz_OutOfDataScopeIsNotFound(t *testing.T) {
	h := newRetestAuthzHarness(t)
	status, body := h.do(h.scoped, rtVerifyPerms, http.MethodPost, "/api/v1/findings/"+h.findingA2.String()+"/retests")
	if status != http.StatusNotFound {
		t.Fatalf("restricted member, out-of-scope finding: POST = %d, want 404 (%s)", status, body)
	}
	if n := h.retests(h.findingA2); n != 0 {
		t.Fatalf("an out-of-scope request queued %d retests", n)
	}
	// In scope, with findings:verify: accepted.
	status, body = h.do(h.scoped, rtVerifyPerms, http.MethodPost, "/api/v1/findings/"+h.findingA1.String()+"/retests")
	if status != http.StatusAccepted {
		t.Fatalf("restricted member, in-scope finding: POST = %d, want 202 (%s)", status, body)
	}
	var out handler.FindingRetestResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.Status != "pending" || out.RequestedBy != h.scoped.String() || out.TemplateID != "exposed-panel" {
		t.Fatalf("response = %+v (%v)", out, err)
	}
	status, body = h.do(h.scoped, rtVerifyPerms, http.MethodGet, "/api/v1/findings/"+h.findingA1.String()+"/retests")
	if status != http.StatusOK || !strings.Contains(body, out.ID) {
		t.Fatalf("GET retests = %d %s", status, body)
	}
}

// The organization's auto-retest settings live under the token singleton: the
// tenant comes from the credential (there is no tenant in the path to point
// at another organization), and only an owner/admin may read or change them.
func TestRetestSettingsAuthz_AdminOnlyAndTokenTenant(t *testing.T) {
	h := newRetestAuthzHarness(t)
	put := func(admin bool) (int, string) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, h.srv.URL+"/api/v1/organization/settings/retest",
			strings.NewReader(`{"auto_enabled":true,"daily_cap":5}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", h.verifier.String())
		req.Header.Set("X-Test-Perms", "findings:read,findings:verify")
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
	if status, body := put(false); status != http.StatusForbidden {
		t.Fatalf("member PUT retest settings = %d, want 403 (%s)", status, body)
	}
	if status, body := put(true); status != http.StatusOK || !strings.Contains(body, `"auto_enabled":true`) {
		t.Fatalf("admin PUT retest settings = %d (%s)", status, body)
	}
	var enabledA, enabledB sql.NullString
	_ = h.db.QueryRow(`SELECT settings->'retest'->>'auto_enabled' FROM tenants WHERE id = $1`, h.tenantA.String()).Scan(&enabledA)
	_ = h.db.QueryRow(`SELECT settings->'retest'->>'auto_enabled' FROM tenants WHERE id = $1`, h.tenantB.String()).Scan(&enabledB)
	if enabledA.String != "true" || enabledB.String == "true" {
		t.Fatalf("settings written to the wrong organization: A=%q B=%q", enabledA.String, enabledB.String)
	}
}

// realProbeGate is the production active-probe gate over the test database:
// scope exclusions, attribution and scan zones.
func realProbeGate(pg *postgres.DB, log *logger.Logger) *scanapp.Service {
	scope := scopeapp.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg),
		postgres.NewAssetRepository(pg), log)
	return scanapp.NewTargetGate(scope, easmapp.NewActiveGate(postgres.NewAttributionRepository(pg), postgres.NewAssetRepository(pg), scope, postgres.NewEASMSeedRepository(pg)), postgres.NewScanZoneRepository(pg), nil, log)
}
