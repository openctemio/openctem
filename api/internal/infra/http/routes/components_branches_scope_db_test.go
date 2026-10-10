package routes

// Software components (RFC-070) and repository branches over the real
// routes, services and a migrated database, for a data-scoped member, an
// administrator and a second tenant. The route guard only sees
// /assets/{id}/..., so the component paths (a package id, ?asset_id=, the
// graph and paths of an asset, /repositories/{id}/branches) must apply the
// data scope themselves: a member restricted to one repository must not
// learn the names, counts or vulnerabilities of packages that only
// out-of-scope assets use. Research doc 15, L-10.

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

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
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
	shared, outOnly, bOnly string // packages: used by both repos / by repoOut only / tenant B's
	sharedV, outOnlyV      string // their versions
	outName, outOnlyName   string
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
	compSvc := assetapp.NewComponentService(compRepo, assetRepo, log)
	compSvc.SetDataScope(enforcer)
	sbom := assetapp.NewSBOMImportService(compRepo, assetRepo, log)
	sbom.SetDataScope(enforcer)
	assetSvc := assetapp.NewAssetService(assetRepo, log)
	assetSvc.SetDataScope(enforcer)
	branchH := handler.NewBranchHandler(assetapp.NewBranchService(postgres.NewBranchRepository(db), log), validator.New(), log)
	branchH.SetAssetService(assetSvc)

	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantA)
			ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
			ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{
				permission.ComponentsRead.String(), permission.ComponentsWrite.String(),
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
	h.outName = "github.com/cbs/out-of-scope-" + h.repoOut[:8]

	for _, tn := range []string{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn, "cbs-"+tn)
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tn := range []string{h.tenantA, h.tenantB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tn)
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
	sfx := h.repoOut[:8]
	var bV string
	h.shared, h.sharedV = testdb.SeedPackageVersion(h.t, h.db, h.tenantA, "pkg:npm/cbs-shared-"+sfx+"@1.0.0")
	h.outOnlyName = "cbs-out-only-" + sfx
	h.outOnly, h.outOnlyV = testdb.SeedPackageVersion(h.t, h.db, h.tenantA, "pkg:npm/"+h.outOnlyName+"@1.0.0")
	h.bOnly, bV = testdb.SeedPackageVersion(h.t, h.db, h.tenantB, "pkg:pypi/cbs-b-only-"+sfx+"@2.0.0")
	testdb.SeedPackageLink(h.t, h.db, h.tenantA, h.repoIn, h.shared, h.sharedV, "package-lock.json", "direct")
	parent := testdb.SeedPackageLink(h.t, h.db, h.tenantA, h.repoOut, h.outOnly, h.outOnlyV, "package-lock.json", "direct")
	child := testdb.SeedPackageLink(h.t, h.db, h.tenantA, h.repoOut, h.shared, h.sharedV, "package-lock.json", "transitive")
	h.exec(`INSERT INTO asset_software_edges (tenant_id, asset_id, parent_id, child_id) VALUES ($1, $2, $3, $4)`,
		h.tenantA, h.repoOut, parent, child)
	testdb.SeedPackageLink(h.t, h.db, h.tenantB, h.repoB, h.bOnly, bV, "requirements.txt", "direct")
	finding := func(asset, version, severity string) {
		fid := shared.NewID().String()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, component_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, $3, $4, 'sca', 'trivy', 'm', $5, $6, 'new')`, fid, h.tenantA, asset, version, severity, "fp-"+fid)
	}
	finding(h.repoIn, h.sharedV, "high")
	finding(h.repoOut, h.sharedV, "critical")
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

type cbsList struct {
	Data []struct {
		ID              string         `json:"id"`
		Assets          int            `json:"assets"`
		Vulnerabilities map[string]int `json:"vulnerabilities"`
	} `json:"data"`
	Total  int `json:"total"`
	Facets map[string][]struct {
		Value string
		Count int
	} `json:"facets"`
}

func (h *cbsHarness) list(user string, admin bool, query string) cbsList {
	h.t.Helper()
	body := h.expect(user, admin, http.MethodGet, "/api/v1/components"+query, nil, http.StatusOK)
	var out cbsList
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		h.t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

func TestComponents_DataScope_DB(t *testing.T) {
	h := newCBSHarness(t)

	// The list, its counts and its facets only see in-scope assets.
	member := h.list(h.scoped, false, "?per_page=100&facets=true")
	if member.Total != 1 || len(member.Data) != 1 || member.Data[0].ID != h.shared {
		t.Fatalf("member list = %+v, want only the shared package", member)
	}
	if member.Data[0].Assets != 1 || member.Data[0].Vulnerabilities["critical"] != 0 || member.Data[0].Vulnerabilities["high"] != 1 {
		t.Errorf("member counts = %+v: the out-of-scope asset and its critical finding must not count", member.Data[0])
	}
	if eco := member.Facets["ecosystem"]; len(eco) != 1 || eco[0].Count != 1 {
		t.Errorf("member ecosystem facet = %+v", eco)
	}
	admin := h.list(h.admin, true, "?per_page=100")
	if admin.Total != 2 {
		t.Errorf("admin list total = %d, want 2 (tenant B's package excluded)", admin.Total)
	}
	for _, p := range admin.Data {
		if p.ID == h.bOnly {
			t.Error("tenant B's package listed for tenant A")
		}
		if p.ID == h.shared && (p.Assets != 2 || p.Vulnerabilities["critical"] != 1) {
			t.Errorf("admin shared counts = %+v", p)
		}
	}
	if body := h.expect(h.scoped, false, http.MethodGet, "/api/v1/components/summary", nil, http.StatusOK); !strings.Contains(body, `"packages":1`) {
		t.Errorf("member summary = %s", body)
	}
	if body := h.expect(h.scoped, false, http.MethodGet, "/api/v1/components?q="+h.outOnlyName, nil, http.StatusOK); strings.Contains(body, h.outOnly) {
		t.Errorf("search found the out-of-scope package: %.300s", body)
	}

	// Detail: a package without an in-scope link is not found.
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/components/"+h.outOnly, nil, http.StatusNotFound)
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/components/"+h.outOnly+"/versions", nil, http.StatusNotFound)
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/components/"+h.outOnly+"/vulnerabilities", nil, http.StatusNotFound)
	h.expect(h.admin, true, http.MethodGet, "/api/v1/components/"+h.outOnly, nil, http.StatusOK)
	h.expect(h.admin, true, http.MethodGet, "/api/v1/components/"+h.bOnly, nil, http.StatusNotFound)
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/components/"+h.shared+"/versions", nil, http.StatusOK)

	// A version (the id findings carry): visible through an in-scope link only.
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/components/versions/"+h.outOnlyV, nil, http.StatusNotFound)
	h.expect(h.admin, true, http.MethodGet, "/api/v1/components/versions/"+h.outOnlyV, nil, http.StatusOK)
	if body := h.expect(h.scoped, false, http.MethodGet, "/api/v1/components/versions/"+h.sharedV, nil, http.StatusOK); !strings.Contains(body, h.shared) {
		t.Errorf("version detail = %.300s", body)
	}

	// Where used: the member sees only the in-scope repository.
	body := h.expect(h.scoped, false, http.MethodGet, "/api/v1/components/"+h.shared+"/assets", nil, http.StatusOK)
	if strings.Contains(body, h.outName) || strings.Contains(body, h.repoOut) || !strings.Contains(body, h.repoIn) {
		t.Errorf("where-used for the member: %.400s", body)
	}
	if body := h.expect(h.admin, true, http.MethodGet, "/api/v1/components/"+h.shared+"/assets", nil, http.StatusOK); !strings.Contains(body, h.repoOut) {
		t.Errorf("the administrator lost the out-of-scope repository: %.300s", body)
	}
	if body := h.expect(h.scoped, false, http.MethodGet, "/api/v1/components/"+h.shared+"/vulnerabilities", nil, http.StatusOK); strings.Contains(body, `"critical"`) {
		t.Errorf("the out-of-scope critical finding leaked: %.300s", body)
	}

	// ?asset_id=, the asset's components, graph and paths.
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/components?asset_id="+h.repoOut, nil, http.StatusNotFound)
	h.expect(h.scoped, false, http.MethodGet, "/api/v1/components?asset_id="+h.repoIn, nil, http.StatusOK)
	h.expect(h.admin, true, http.MethodGet, "/api/v1/components?asset_id="+h.repoB, nil, http.StatusNotFound)
	for _, p := range []string{"/components", "/dependency-graph", "/dependency-paths?version_id=" + h.sharedV} {
		h.expect(h.scoped, false, http.MethodGet, "/api/v1/assets/"+h.repoOut+p, nil, http.StatusNotFound)
		h.expect(h.admin, true, http.MethodGet, "/api/v1/assets/"+h.repoB+p, nil, http.StatusNotFound)
	}
	graph := h.expect(h.admin, true, http.MethodGet, "/api/v1/assets/"+h.repoOut+"/dependency-graph", nil, http.StatusOK)
	if strings.Count(graph, `"version_id"`) != 2 || strings.Count(graph, `"from"`) != 1 {
		t.Errorf("graph = %.500s, want 2 nodes and 1 edge", graph)
	}
	paths := h.expect(h.admin, true, http.MethodGet, "/api/v1/assets/"+h.repoOut+"/dependency-paths?version_id="+h.sharedV, nil, http.StatusOK)
	if !strings.Contains(paths, h.outOnlyName) {
		t.Errorf("paths = %.500s, want the path through the direct package", paths)
	}

	// SBOM import: an out-of-scope asset is refused; a preview writes nothing.
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"cbs-sbom","version":"1.0.0","purl":"pkg:npm/cbs-sbom-` + h.repoIn[:8] + `@1.0.0"}]}`
	h.expect(h.scoped, false, http.MethodPost, "/api/v1/components/import?asset_id="+h.repoOut, sbom, http.StatusNotFound)
	// (The import route is rate limited to a burst of 3: one refusal, a preview, an import.)
	count := func() int {
		var n int
		_ = h.db.QueryRow(`SELECT count(*) FROM asset_software WHERE asset_id = $1 AND source = 'package'`, h.repoIn).Scan(&n)
		return n
	}
	before := count()
	if body := h.expect(h.scoped, false, http.MethodPost, "/api/v1/components/import?dry_run=true&asset_id="+h.repoIn, sbom, http.StatusOK); !strings.Contains(body, `"added":1`) {
		t.Errorf("preview = %s", body)
	}
	if count() != before {
		t.Fatal("a preview wrote package links")
	}
	h.expect(h.scoped, false, http.MethodPost, "/api/v1/components/import?asset_id="+h.repoIn, sbom, http.StatusOK)
	if count() != before+1 {
		t.Errorf("import wrote %d links, want %d", count(), before+1)
	}
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM software_products WHERE purl_name LIKE 'cbs-sbom-%' AND tenant_id IS NULL`).Scan(&n)
	if n != 0 {
		t.Error("an SBOM upload created a global catalog product")
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
