package routes

// Leaked credentials, active CVEs and an access group's asset list over the
// real routes, services and a migrated database, for a data-scoped member,
// an administrator and a second tenant. None of these paths has an asset id
// the route guard sees, and each read the whole tenant: a member restricted
// to one asset listed every leaked credential (and could reveal or resolve
// it), every CVE with its affected-asset counts, and the assets of any team
// (GET /groups/{g}/assets needs only groups:read, a member default).
// Research doc 15, L-10.

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
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

type l10Harness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server

	tenantA, tenantB   string
	admin, scoped      string
	assetIn, assetOut  string
	assetB             string
	credIn, credOut    string // leaked credentials on assetIn / assetOut
	credNoAsset, credB string
	cveIn, cveOut      string // CVE ids with findings on assetIn / assetOut only
	groupA             string
}

func (h *l10Harness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func newL10Harness(t *testing.T) *l10Harness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping L-10 read scope DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &l10Harness{t: t, db: sqldb}
	h.seed()

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)

	credSvc := app.NewCredentialImportService(postgres.NewExposureRepository(db), postgres.NewExposureStateHistoryRepository(db), log)
	credSvc.SetDataScope(enforcer)
	vulnSvc := app.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), postgres.NewFindingRepository(db), log)
	vulnSvc.SetDataScope(enforcer)
	groupSvc := app.NewGroupService(postgres.NewGroupRepository(db), log,
		app.WithAccessControlRepository(postgres.NewAccessControlRepository(db)),
		app.WithGroupDataScope(enforcer))

	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantA)
			ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
			ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{
				permission.CredentialsRead.String(), permission.CredentialsWrite.String(),
				permission.CredentialsReveal.String(), permission.VulnerabilitiesRead.String(),
				permission.GroupsRead.String(),
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	pass := Middleware(func(next http.Handler) http.Handler { return next })
	credH := handler.NewCredentialImportHandler(credSvc, validator.New(), log)
	credH.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
	registerCredentialRoutes(router, credH, auth, nil, pass)
	registerVulnerabilityRoutes(router, handler.NewVulnerabilityHandler(vulnSvc, validator.New(), log), nil, nil, nil, auth, nil)
	registerGroupRoutes(router, handler.NewGroupHandler(groupSvc, validator.New(), log), auth, nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *l10Harness) seed() {
	id := func() string { return shared.NewID().String() }
	h.tenantA, h.tenantB = id(), id()
	h.admin, h.scoped = id(), id()
	h.assetIn, h.assetOut, h.assetB = id(), id(), id()
	h.credIn, h.credOut, h.credNoAsset, h.credB = id(), id(), id(), id()
	h.groupA = id()
	sfx := strings.ReplaceAll(h.tenantA, "-", "")[:10]
	h.cveIn, h.cveOut = "CVE-2099-1"+sfx[:4], "CVE-2099-2"+sfx[:4]

	for _, tn := range []string{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn, "l10-"+tn)
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tn := range []string{h.tenantA, h.tenantB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id = $1`, tn)
			_, _ = h.db.ExecContext(ctx, `DELETE FROM findings WHERE tenant_id = $1`, tn)
			_, _ = h.db.ExecContext(ctx, `DELETE FROM exposure_events WHERE tenant_id = $1`, tn)
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		_, _ = h.db.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE cve_id = ANY($1)`, "{"+h.cveIn+","+h.cveOut+"}")
		for _, u := range []string{h.admin, h.scoped} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{h.admin, h.scoped} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'l10')`, u, u+"@l10.test")
	}
	for aid, tn := range map[string]string{h.assetIn: h.tenantA, h.assetOut: h.tenantA, h.assetB: h.tenantB} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			aid, tn, "l10-"+aid+".example.com")
	}
	cred := func(cid, tn string, asset any) {
		h.exec(`INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, severity, state, title, details, fingerprint, source)
			VALUES ($1::uuid, $2, $3, 'credential_leaked', 'high', 'active', $4, '{"identifier":"l10-user@example.com"}', $1::text, 'l10')`,
			cid, tn, asset, "l10 leak "+cid)
	}
	cred(h.credIn, h.tenantA, h.assetIn)
	cred(h.credOut, h.tenantA, h.assetOut)
	cred(h.credNoAsset, h.tenantA, nil)
	cred(h.credB, h.tenantB, h.assetB)

	for cve, asset := range map[string]string{h.cveIn: h.assetIn, h.cveOut: h.assetOut} {
		vid := id()
		h.exec(`INSERT INTO vulnerabilities (id, cve_id, title, severity) VALUES ($1, $2, $2, 'high')`, vid, cve)
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, vulnerability_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, $4, 'sca', 'l10-tool', 'l10 cve finding', 'high', $1::text, 'new')`,
			id(), h.tenantA, asset, vid)
	}

	h.exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'l10-group', $3)`, h.groupA, h.tenantA, "l10-"+h.groupA)
	for _, a := range []string{h.assetIn, h.assetOut} {
		h.exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`, a, h.groupA)
	}
	// scoped may see assetIn only (and is not a member of groupA).
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.scoped, h.tenantA, h.assetIn)
}

func (h *l10Harness) do(user string, admin bool, method, path string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, strings.NewReader(`{}`))
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

func (h *l10Harness) get(user string, admin bool, path string) string {
	h.t.Helper()
	status, body := h.do(user, admin, http.MethodGet, path)
	if status != http.StatusOK {
		h.t.Fatalf("GET %s = %d (%.200s)", path, status, body)
	}
	return body
}

func TestCredentials_DataScope_DB(t *testing.T) {
	h := newL10Harness(t)

	for _, p := range []string{"/api/v1/credentials/?per_page=100", "/api/v1/credentials/identities?per_page=100"} {
		body := h.get(h.scoped, false, p)
		if strings.Contains(body, h.credOut) || strings.Contains(body, h.credNoAsset) || strings.Contains(body, h.credB) {
			t.Errorf("%s leaked an out-of-scope credential: %.400s", p, body)
		}
	}
	if body := h.get(h.scoped, false, "/api/v1/credentials/?per_page=100"); !strings.Contains(body, h.credIn) {
		t.Errorf("the member misses the in-scope credential: %.300s", body)
	}
	if body := h.get(h.scoped, false, "/api/v1/credentials/stats"); !strings.Contains(body, `"total":1`) {
		t.Errorf("stats for the member: %s, want total 1", body)
	}
	body := h.get(h.admin, true, "/api/v1/credentials/?per_page=100")
	if !strings.Contains(body, h.credOut) || !strings.Contains(body, h.credNoAsset) || strings.Contains(body, h.credB) {
		t.Errorf("admin list: %.400s, want both tenant A leaks incl. the asset-less one, not tenant B's", body)
	}

	// By id: out of scope, asset-less and foreign answer 404 to the member.
	for _, c := range []string{h.credOut, h.credNoAsset, h.credB} {
		for _, op := range []struct{ method, path string }{
			{http.MethodGet, "/api/v1/credentials/" + c},
			{http.MethodPost, "/api/v1/credentials/" + c + "/resolve"},
			{http.MethodPost, "/api/v1/credentials/" + c + "/reveal"},
		} {
			if status, body := h.do(h.scoped, false, op.method, op.path); status != http.StatusNotFound {
				t.Errorf("%s %s as the member = %d, want 404 (%.200s)", op.method, op.path, status, body)
			}
		}
	}
	if status, _ := h.do(h.scoped, false, http.MethodGet, "/api/v1/credentials/"+h.credIn); status != http.StatusOK {
		t.Errorf("GET the in-scope credential = %d, want 200", status)
	}
	if status, _ := h.do(h.admin, true, http.MethodGet, "/api/v1/credentials/"+h.credB); status != http.StatusNotFound {
		t.Errorf("admin GET another tenant's credential = %d, want 404", status)
	}
	var state string
	_ = h.db.QueryRow(`SELECT state FROM exposure_events WHERE id = $1`, h.credOut).Scan(&state)
	if state != "active" {
		t.Errorf("the member resolved an out-of-scope credential (state %s)", state)
	}
}

func TestActiveCVEs_DataScope_DB(t *testing.T) {
	h := newL10Harness(t)
	body := h.get(h.scoped, false, "/api/v1/vulnerabilities/active?per_page=100")
	if strings.Contains(body, h.cveOut) || !strings.Contains(body, h.cveIn) {
		t.Errorf("active CVEs for the member: %.400s, want only %s", body, h.cveIn)
	}
	if body := h.get(h.scoped, false, "/api/v1/vulnerabilities/active/stats"); !strings.Contains(body, `"total":1`) {
		t.Errorf("active CVE stats for the member: %s, want total 1", body)
	}
	body = h.get(h.admin, true, "/api/v1/vulnerabilities/active?per_page=100")
	if !strings.Contains(body, h.cveOut) || !strings.Contains(body, h.cveIn) {
		t.Errorf("active CVEs for the admin miss one: %.400s", body)
	}
}

func TestGroupAssets_DataScope_DB(t *testing.T) {
	h := newL10Harness(t)
	body := h.get(h.scoped, false, "/api/v1/groups/"+h.groupA+"/assets")
	if strings.Contains(body, h.assetOut) || !strings.Contains(body, h.assetIn) || !strings.Contains(body, `"total_count":1`) {
		t.Errorf("group assets for the member: %.400s, want only the in-scope asset", body)
	}
	body = h.get(h.admin, true, "/api/v1/groups/"+h.groupA+"/assets")
	if !strings.Contains(body, h.assetOut) || !strings.Contains(body, `"total_count":2`) {
		t.Errorf("group assets for the admin: %.400s, want both", body)
	}
}
