package routes

// Components (SBOM) and repository branches over the real routes, services
// and a migrated database, for a data-scoped member, an administrator and a
// second tenant. The route guard only sees /assets/{id}/..., so these paths
// (a component id, ?asset_id=, a dependency id, /repositories/{id}/branches)
// went unscoped: a member restricted to one repository read the names and
// risk of every asset using a package and wrote components and branches on
// any asset. Research doc 15, L-10.

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

	assetsvc "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/datascope"
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

type cbsHarness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server

	tenantA, tenantB       string
	admin, scoped          string
	repoIn, repoOut, repoB string
	shared, outOnly        string // components: used by both repos / by repoOut only
	depOut                 string // asset_components row of repoOut
	outName                string
}

func (h *cbsHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func newCBSHarness(t *testing.T) *cbsHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping component/branch scope DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &cbsHarness{t: t, db: sqldb}
	h.seed()

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	assetRepo := postgres.NewAssetRepository(db)
	compRepo := postgres.NewComponentRepository(db)
	compSvc := assetsvc.NewComponentService(compRepo, assetRepo, log)
	compSvc.SetDataScope(enforcer)
	sbom := assetsvc.NewSBOMImportService(compRepo, assetRepo, log)
	sbom.SetDataScope(enforcer)
	assetSvc := assetsvc.NewAssetService(assetRepo, log)
	assetSvc.SetDataScope(enforcer)
	branchH := handler.NewBranchHandler(assetsvc.NewBranchService(postgres.NewBranchRepository(db), log), validator.New(), log)
	branchH.SetAssetService(assetSvc)

	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantA)
			ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
			ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{
				permission.ComponentsRead.String(), permission.ComponentsWrite.String(), permission.ComponentsDelete.String(),
				permission.AssetsRead.String(), permission.AssetsWrite.String(), permission.AssetsDelete.String(),
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	pass := Middleware(func(next http.Handler) http.Handler { return next })
	registerComponentRoutes(router, handler.NewComponentHandler(compSvc, sbom, validator.New(), log), auth, nil, pass)
	registerBranchRoutes(router, branchH, auth, nil, pass)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *cbsHarness) seed() {
	id := func() string { return shared.NewID().String() }
	h.tenantA, h.tenantB = id(), id()
	h.admin, h.scoped = id(), id()
	h.repoIn, h.repoOut, h.repoB = id(), id(), id()
	h.shared, h.outOnly, h.depOut = id(), id(), id()
	h.outName = "github.com/cbs/out-of-scope-" + h.repoOut[:8]

	for _, tn := range []string{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn, "cbs-"+tn)
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tn := range []string{h.tenantA, h.tenantB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, c := range []string{h.shared, h.outOnly} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM components WHERE id = $1`, c)
		}
		for _, u := range []string{h.admin, h.scoped} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{h.admin, h.scoped} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'cbs')`, u, u+"@cbs.test")
	}
	for aid, a := range map[string][2]string{
		h.repoIn:  {h.tenantA, "github.com/cbs/in-scope-" + h.repoIn[:8]},
		h.repoOut: {h.tenantA, h.outName},
		h.repoB:   {h.tenantB, "github.com/cbs/tenant-b-" + h.repoB[:8]},
	} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'repository', 'private', 'high')`,
			aid, a[0], a[1])
		h.exec(`INSERT INTO asset_repositories (asset_id) VALUES ($1)`, aid)
		h.exec(`INSERT INTO repository_branches (repository_id, name, is_default) VALUES ($1, 'main', true)`, aid)
	}
	for cid, name := range map[string]string{h.shared: "cbs-shared", h.outOnly: "cbs-out-only"} {
		h.exec(`INSERT INTO components (id, purl, name, version, ecosystem) VALUES ($1, $2, $3, '1.0.0', 'npm')`,
			cid, "pkg:npm/"+name+"-"+cid[:8]+"@1.0.0", name+"-"+cid[:8])
	}
	link := func(dep, asset, comp string) {
		h.exec(`INSERT INTO asset_components (id, tenant_id, asset_id, component_id, name, version, ecosystem, dependency_type)
			VALUES ($1, $2, $3, $4, $5, '1.0.0', 'npm', 'direct')`, dep, h.tenantA, asset, comp, "cbs-"+comp)
	}
	link(shared.NewID().String(), h.repoIn, h.shared)
	link(h.depOut, h.repoOut, h.shared)
	link(shared.NewID().String(), h.repoOut, h.outOnly)
	// scoped may see repoIn only.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.scoped, h.tenantA, h.repoIn)
}

func (h *cbsHarness) do(user string, admin bool, method, path string, body any) (int, string) {
	h.t.Helper()
	var rdr io.Reader
	if s, ok := body.(string); ok {
		rdr = strings.NewReader(s)
	} else if body != nil {
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

func (h *cbsHarness) expect(user string, admin bool, method, path string, body any, want int) string {
	h.t.Helper()
	status, out := h.do(user, admin, method, path, body)
	if status != want {
		h.t.Errorf("%s %s as %s = %d, want %d (%.200s)", method, path, map[bool]string{true: "admin", false: "scoped member"}[admin], status, want, out)
	}
	return out
}

func TestComponents_DataScope_DB(t *testing.T) {
	h := newCBSHarness(t)

	// Reverse lookup: the member sees only the in-scope repository.
	body := h.expect(h.scoped, false, http.MethodGet, "/api/v1/components/"+h.shared+"/assets", nil, http.StatusOK)
	if strings.Contains(body, h.outName) || strings.Contains(body, h.repoOut) {
		t.Errorf("reverse lookup leaked the out-of-scope repository: %.400s", body)
	}
	if !strings.Contains(body, h.repoIn) {
		t.Errorf("reverse lookup misses the in-scope repository: %.400s", body)
	}
	if body := h.expect(h.admin, true, http.MethodGet, "/api/v1/components/"+h.shared+"/assets", nil, http.StatusOK); !strings.Contains(body, h.repoOut) {
		t.Errorf("the administrator lost the out-of-scope repository: %.300s", body)
	}

	// ?asset_id= (not seen by the route guard).
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/components?asset_id="+h.repoOut, nil, http.StatusNotFound)
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/components?asset_id="+h.repoIn, nil, http.StatusOK)
	h.expect(h.admin, true, http.MethodGet, "/api/v1/components?asset_id="+h.repoB, nil, http.StatusNotFound)

	// The plain list only holds components of in-scope assets.
	body = h.expect(h.scoped, false, http.MethodGet, "/api/v1/components?per_page=100", nil, http.StatusOK)
	if strings.Contains(body, h.outOnly) || !strings.Contains(body, h.shared) {
		t.Errorf("component list for the member: %.400s, want the shared component and not the out-of-scope one", body)
	}

	// Writes on an out-of-scope asset are refused; on an in-scope one they work.
	h.expect(h.scoped, false, http.MethodPut, "/api/v1/components/"+h.depOut, map[string]any{"manifest_path": "x"}, http.StatusNotFound)
	h.expect(h.scoped, false, http.MethodDelete, "/api/v1/components/"+h.depOut, nil, http.StatusNotFound)
	newComp := func(asset string) map[string]any {
		return map[string]any{"asset_id": asset, "name": "cbs-new-" + asset[:8], "version": "2.0.0", "ecosystem": "npm"}
	}
	h.expect(h.scoped, false, http.MethodPost, "/api/v1/components", newComp(h.repoOut), http.StatusNotFound)
	h.expect(h.scoped, false, http.MethodPost, "/api/v1/components", newComp(h.repoIn), http.StatusCreated)
	h.expect(h.admin, true, http.MethodPost, "/api/v1/components", newComp(h.repoB), http.StatusNotFound)
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"cbs-sbom","version":"1.0.0","purl":"pkg:npm/cbs-sbom@1.0.0"}]}`
	h.expect(h.scoped, false, http.MethodPost, "/api/v1/components/import?asset_id="+h.repoOut, sbom, http.StatusNotFound)

	var stillThere int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM asset_components WHERE id = $1`, h.depOut).Scan(&stillThere)
	if stillThere != 1 {
		t.Error("the member deleted a component of an out-of-scope asset")
	}
}

func TestBranches_DataScope_DB(t *testing.T) {
	h := newCBSHarness(t)
	for _, p := range []string{"/", "/default"} {
		h.expect(h.scoped, false, http.MethodGet, "/api/v1/repositories/"+h.repoOut+"/branches"+p, nil, http.StatusNotFound)
		h.expect(h.scoped, false, http.MethodGet, "/api/v1/repositories/"+h.repoIn+"/branches"+p, nil, http.StatusOK)
		h.expect(h.admin, true, http.MethodGet, "/api/v1/repositories/"+h.repoB+"/branches"+p, nil, http.StatusNotFound)
		h.expect(h.admin, true, http.MethodGet, "/api/v1/repositories/"+h.repoOut+"/branches"+p, nil, http.StatusOK)
	}
	h.expect(h.scoped, false, http.MethodPost, "/api/v1/repositories/"+h.repoOut+"/branches", map[string]any{"name": "feature/x"}, http.StatusNotFound)
	var n int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM repository_branches WHERE repository_id = $1`, h.repoOut).Scan(&n)
	if n != 1 {
		t.Errorf("the out-of-scope repository has %d branches, want 1", n)
	}
}
