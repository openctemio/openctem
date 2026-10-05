package routes

// Threat models, business-service asset links, business-unit asset links and
// a CTEM cycle's scope snapshot over the real routes and a migrated database,
// for a data-scoped member, an administrator and a second tenant. These read
// asset-keyed rows through ids the route guard never sees, so a member
// restricted to one asset read other assets' names and threat paths, and
// changed out-of-scope assets' effective criticality by linking them.
// Research doc 15, L-10.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/threatmodel"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type l10cHarness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server

	tenantA, tenantB               string
	admin, scoped                  string
	assetIn, assetOut, assetB      string
	outName                        string
	modelTenant, modelIn, modelOut string
	threatIn, threatOut            string
	service, bu, cycle             string
}

func (h *l10cHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func newL10cHarness(t *testing.T) *l10cHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping L-10 context scope DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &l10cHarness{t: t, db: sqldb}
	h.seed()

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	assetRepo := postgres.NewAssetRepository(db)
	tm := threatmodel.NewService(postgres.NewThreatModelRepository(db), nil, assetRepo, nil, nil, nil, log)
	tm.SetDataScope(enforcer)
	bu := app.NewBusinessUnitService(postgres.NewBusinessUnitRepository(db), assetRepo, log)
	bu.SetDataScope(enforcer)

	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantA)
			ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
			ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{
				permission.AssetsRead.String(), permission.AssetsWrite.String(),
				permission.BusinessServicesRead.String(), permission.BusinessServicesWrite.String(),
				permission.CTEMCyclesRead.String(),
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	pass := Middleware(func(next http.Handler) http.Handler { return next })
	registerThreatModelRoutes(router, handler.NewThreatModelHandler(tm, log), auth, nil, pass)
	registerBusinessServiceRoutes(router, handler.NewBusinessServiceHandler(sqldb, log).WithDataScope(enforcer), auth, nil, pass)
	registerBusinessUnitRoutes(router, handler.NewBusinessUnitHandler(bu, log), auth, nil, pass)
	registerCTEMCycleRoutes(router, handler.NewCTEMCycleHandler(sqldb, nil, log).WithDataScope(enforcer), auth, nil, pass)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *l10cHarness) seed() {
	id := func() string { return shared.NewID().String() }
	h.tenantA, h.tenantB = id(), id()
	h.admin, h.scoped = id(), id()
	h.assetIn, h.assetOut, h.assetB = id(), id(), id()
	h.modelTenant, h.modelIn, h.modelOut = id(), id(), id()
	h.threatIn, h.threatOut = id(), id()
	h.service, h.bu, h.cycle = id(), id(), id()
	h.outName = "l10c-out-of-scope-" + h.assetOut[:8] + ".example.com"

	for _, tn := range []string{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn, "l10c-"+tn)
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tn := range []string{h.tenantA, h.tenantB} {
			for _, q := range []string{
				`DELETE FROM threat_model_threats WHERE tenant_id = $1`, `DELETE FROM threat_models WHERE tenant_id = $1`,
				`DELETE FROM ctem_cycles WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`,
			} {
				_, _ = h.db.ExecContext(ctx, q, tn)
			}
		}
		for _, u := range []string{h.admin, h.scoped} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{h.admin, h.scoped} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'l10c')`, u, u+"@l10c.test")
	}
	for aid, a := range map[string][2]string{
		h.assetIn:  {h.tenantA, "l10c-in-" + h.assetIn[:8] + ".example.com"},
		h.assetOut: {h.tenantA, h.outName},
		h.assetB:   {h.tenantB, "l10c-b-" + h.assetB[:8] + ".example.com"},
	} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			aid, a[0], a[1])
	}
	// Threat models: a tenant-wide one with one threat per asset, and a
	// crown-jewel model per asset.
	h.exec(`INSERT INTO threat_models (id, tenant_id, scope_type, name) VALUES ($1, $2, 'tenant', 'l10c tenant')`, h.modelTenant, h.tenantA)
	h.exec(`INSERT INTO threat_models (id, tenant_id, scope_type, scope_ref_id, name) VALUES ($1, $2, 'crown_jewel', $3, 'l10c in')`, h.modelIn, h.tenantA, h.assetIn)
	h.exec(`INSERT INTO threat_models (id, tenant_id, scope_type, scope_ref_id, name) VALUES ($1, $2, 'crown_jewel', $3, $4)`, h.modelOut, h.tenantA, h.assetOut, "Threat model: "+h.outName)
	h.exec(`INSERT INTO threat_model_threats (id, tenant_id, threat_model_id, target_asset_id, technique_id, tactic, hop_index, chain_fingerprint, mitigation_id, status_reason) VALUES ($1::uuid, $2, $3, $4, 'T1190', 'initial-access', 0, $1::text, '', '')`,
		h.threatIn, h.tenantA, h.modelTenant, h.assetIn)
	h.exec(`INSERT INTO threat_model_threats (id, tenant_id, threat_model_id, target_asset_id, technique_id, tactic, hop_index, chain_fingerprint, mitigation_id, status_reason) VALUES ($1::uuid, $2, $3, $4, 'T1133', 'initial-access', 0, $1::text, '', '')`,
		h.threatOut, h.tenantA, h.modelTenant, h.assetOut)

	h.exec(`INSERT INTO business_services (id, tenant_id, name) VALUES ($1, $2, 'l10c service')`, h.service, h.tenantA)
	for _, a := range []string{h.assetIn, h.assetOut} {
		h.exec(`INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1, $2, $3)`, h.tenantA, h.service, a)
	}
	h.exec(`INSERT INTO business_units (id, tenant_id, name) VALUES ($1, $2, 'l10c bu')`, h.bu, h.tenantA)
	h.exec(`INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1, $2, $3, $4)`, id(), h.tenantA, h.bu, h.assetOut)

	h.exec(`INSERT INTO ctem_cycles (id, tenant_id, name, created_by) VALUES ($1, $2, 'l10c cycle', $3)`, h.cycle, h.tenantA, h.admin)
	for _, a := range []string{h.assetIn, h.assetOut} {
		h.exec(`INSERT INTO ctem_cycle_scope_snapshots (cycle_id, asset_id) VALUES ($1, $2)`, h.cycle, a)
	}
	// scoped may see assetIn only.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.scoped, h.tenantA, h.assetIn)
}

func (h *l10cHarness) do(user string, admin bool, method, path string, body any) (int, string) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rdr)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", user)
	if admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (h *l10cHarness) expect(user string, admin bool, method, path string, body any, want int) string {
	h.t.Helper()
	status, out := h.do(user, admin, method, path, body)
	if status != want {
		h.t.Errorf("%s %s (admin=%v) = %d, want %d (%.200s)", method, path, admin, status, want, out)
	}
	return out
}

func (h *l10cHarness) leaksOut(body string) bool {
	return strings.Contains(body, h.assetOut) || strings.Contains(body, h.outName)
}

func TestThreatModels_DataScope_DB(t *testing.T) {
	h := newL10cHarness(t)

	body := h.expect(h.scoped, false, http.MethodGet, "/api/v1/threat-models/", nil, http.StatusOK)
	if h.leaksOut(body) || strings.Contains(body, h.modelOut) || !strings.Contains(body, h.modelIn) {
		t.Errorf("model list for the member: %.400s, want the in-scope crown jewel and not the out-of-scope one", body)
	}
	if body := h.expect(h.admin, true, http.MethodGet, "/api/v1/threat-models/", nil, http.StatusOK); !strings.Contains(body, h.modelOut) {
		t.Errorf("model list for the admin misses the out-of-scope model: %.300s", body)
	}
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/threat-models/"+h.modelOut, nil, http.StatusNotFound)
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/threat-models/"+h.modelOut+"/coverage", nil, http.StatusNotFound)

	body = h.expect(h.scoped, false, http.MethodGet, "/api/v1/threat-models/"+h.modelTenant, nil, http.StatusOK)
	if strings.Contains(body, h.threatOut) || h.leaksOut(body) || !strings.Contains(body, h.threatIn) {
		t.Errorf("tenant model for the member: %.500s, want only the in-scope threat", body)
	}
	body = h.expect(h.scoped, false, http.MethodGet, "/api/v1/threat-models/"+h.modelTenant+"/coverage", nil, http.StatusOK)
	if strings.Contains(body, "T1133") || !strings.Contains(body, "T1190") {
		t.Errorf("coverage for the member counts the out-of-scope threat: %.500s", body)
	}
	if body := h.expect(h.admin, true, http.MethodGet, "/api/v1/threat-models/"+h.modelTenant, nil, http.StatusOK); !strings.Contains(body, h.threatOut) {
		t.Errorf("tenant model for the admin misses a threat: %.300s", body)
	}

	// Generating a crown-jewel model names the asset: out of scope → 404.
	body = h.expect(h.scoped, false, http.MethodPost, "/api/v1/threat-models/generate",
		map[string]any{"scope_type": "crown_jewel", "scope_ref_id": h.assetOut}, http.StatusNotFound)
	if h.leaksOut(body) {
		t.Errorf("generate leaked the asset name: %s", body)
	}
	h.expect(h.admin, true, http.MethodPost, "/api/v1/threat-models/generate",
		map[string]any{"scope_type": "crown_jewel", "scope_ref_id": h.assetB}, http.StatusNotFound)
}

func TestBusinessContextLinks_DataScope_DB(t *testing.T) {
	h := newL10cHarness(t)
	svc := "/api/v1/business-services/" + h.service + "/assets"

	body := h.expect(h.scoped, false, http.MethodGet, svc, nil, http.StatusOK)
	if h.leaksOut(body) || !strings.Contains(body, h.assetIn) {
		t.Errorf("business-service assets for the member: %.400s", body)
	}
	if body := h.expect(h.admin, true, http.MethodGet, svc, nil, http.StatusOK); !strings.Contains(body, h.assetOut) {
		t.Errorf("business-service assets for the admin miss one: %.300s", body)
	}
	h.expect(h.scoped, false, http.MethodDelete, svc+"/"+h.assetOut, nil, http.StatusNotFound)
	h.expect(h.scoped, false, http.MethodDelete, svc+"/"+h.assetIn, nil, http.StatusNoContent)
	h.expect(h.scoped, false, http.MethodPost, svc, map[string]any{"asset_id": h.assetOut}, http.StatusNotFound)
	h.expect(h.scoped, false, http.MethodPost, svc, map[string]any{"asset_id": h.assetIn}, http.StatusNoContent)
	h.expect(h.admin, true, http.MethodPost, svc, map[string]any{"asset_id": h.assetB}, http.StatusNotFound)

	// Business unit links change an asset's effective criticality.
	bu := "/api/v1/business-units/" + h.bu + "/assets"
	h.expect(h.scoped, false, http.MethodDelete, bu+"/"+h.assetOut, nil, http.StatusNotFound)
	if status, body := h.do(h.scoped, false, http.MethodPost, bu, map[string]any{"asset_id": h.assetOut}); status/100 == 2 {
		t.Errorf("BU link of an out-of-scope asset = %d (%s), want refused", status, body)
	}
	var n int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM business_unit_assets WHERE business_unit_id = $1 AND asset_id = $2`, h.bu, h.assetOut).Scan(&n)
	if n != 1 {
		t.Errorf("the member changed an out-of-scope asset's BU link (rows=%d)", n)
	}

	body = h.expect(h.scoped, false, http.MethodGet, "/api/v1/ctem-cycles/"+h.cycle+"/scope", nil, http.StatusOK)
	if h.leaksOut(body) || !strings.Contains(body, h.assetIn) {
		t.Errorf("cycle scope for the member: %.400s", body)
	}
	if body := h.expect(h.admin, true, http.MethodGet, "/api/v1/ctem-cycles/"+h.cycle+"/scope", nil, http.StatusOK); !strings.Contains(body, h.assetOut) {
		t.Errorf("cycle scope for the admin misses an asset: %.300s", body)
	}
}
