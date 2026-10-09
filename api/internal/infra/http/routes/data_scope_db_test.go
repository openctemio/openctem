package routes

// Layer 2 data scope (access groups → user_accessible_assets) over the real
// route registration, handlers, services and a migrated database.
//
// Each test reproduces one bypass from the 2026-10 data-scope audit (finding
// F4): a member whose scope is group A (asset A1) could read and change
// group B's asset B1 and finding FB through by-id routes, sub-resources,
// bulk-by-id actions and indirect lists. The same requests are also made as
// an administrator, as a member holding a full-data role (both see the whole
// tenant) and as members with no scope row, who see nothing: there is no
// "see everything" mode for them, whatever the organization's legacy
// members_without_group_see value says (owner decision D2, research doc 15
// L-04). Migration 000910 made 'everything' impossible to store; that the
// value is not read is pinned by the SQL builder tests.

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

	webendpointapp "github.com/openctemio/openctem/api/internal/app/webendpoint"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/attack"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/app/module"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// Markers that only appear in group B's rows, so a response body that
// contains one has leaked out-of-scope data.
const (
	dsMarkerAssetB   = "dsb-b1.example.com"
	dsMarkerFindingB = "dsB-SECRET finding on B1"
	dsMarkerExpB     = "dsB-SECRET exposure on B1"
	dsMarkerAssetA   = "dsa-a1.example.com"
	dsMarkerFindingA = "dsA finding on A1"
)

type dsHarness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server

	// memberFree and memberStrict have no scope row; memberFull has none
	// either but holds a has_full_data_access role.
	tenant, owner, memberA, memberFree, memberStrict, memberFull shared.ID
	assetA, assetB, findingA, findingB                           shared.ID
	exposureA, exposureB, group                                  shared.ID
}

// dsMemberPerms is what a generous custom "member" role holds: every
// permission the probed routes need, so a 404 can only come from data scope.
var dsMemberPerms = []string{ //nolint:gochecknoglobals // test fixture
	permission.AssetsRead.String(), permission.AssetsWrite.String(), permission.AssetsDelete.String(),
	permission.FindingsRead.String(), permission.FindingsWrite.String(), permission.FindingsDelete.String(),
	permission.FindingsStatus.String(), permission.FindingsTriage.String(), permission.FindingsAssign.String(),
	permission.FindingsBulkUpdate.String(), permission.FindingsVerify.String(),
	permission.FindingsComment.String(), permission.FindingsSeverity.String(),
	permission.AssetGroupsRead.String(), permission.DashboardRead.String(),
	permission.ExposuresRead.String(), permission.ExposuresWrite.String(), permission.ExposuresTriage.String(),
	permission.ExposuresDelete.String(),
}

// dsAuth is a stand-in for UnifiedAuth: the test names the caller in headers.
func (h *dsHarness) dsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
		ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenant.String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
		perms := dsMemberPerms
		if p := r.Header.Get("X-Test-Perms"); p != "" {
			perms = strings.Split(p, ",")
		}
		ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func passthrough(next http.Handler) http.Handler { return next }

func newDSHarness(t *testing.T) *dsHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping data-scope DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &dsHarness{t: t, db: sqldb}
	h.seed()

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	v := validator.New()
	tenantRepo := postgres.NewTenantRepository(db)

	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	enforcer.SetAdminLookup(func(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
		m, err := tenantRepo.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return false, err
		}
		return m.IsOwner() || m.IsAdmin(), nil
	})

	assetRepo := postgres.NewAssetRepository(db)
	findingRepo := postgres.NewFindingRepository(db)
	accessRepo := postgres.NewAccessControlRepository(db)

	assetSvc := asset.NewAssetService(assetRepo, log)
	assetSvc.SetAccessControlRepository(accessRepo)
	assetSvc.SetDataScope(enforcer)
	assetSvc.SetRepositoryExtensionRepository(postgres.NewRepositoryExtensionRepository(db))

	vulnSvc := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), findingRepo, log)
	vulnSvc.SetCommentRepository(postgres.NewFindingCommentRepository(db))
	vulnSvc.SetAccessControlRepository(accessRepo)
	vulnSvc.SetAssigneeChecker(accessRepo)
	vulnSvc.SetDataScope(enforcer)
	vulnSvc.SetAssetRepository(assetRepo)
	vulnSvc.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))

	groupSvc := asset.NewAssetGroupService(postgres.NewAssetGroupRepository(db), log)
	groupSvc.SetDataScope(enforcer)

	surfaceSvc := attack.NewSurfaceService(assetRepo, postgres.NewAssetRelationshipRepository(db), log)
	surfaceSvc.SetFindingRiskCounter(findingRepo)
	surfaceSvc.SetDataScope(enforcer)

	expSvc := exposure.NewExposureService(postgres.NewExposureRepository(db), postgres.NewExposureStateHistoryRepository(db), log)
	expSvc.SetDataScope(enforcer)

	dashSvc := module.NewDashboardService(postgres.NewDashboardRepository(sqldb), log)
	dashSvc.SetDataScope(enforcer)
	dashSvc.SetAggregateCheck(func(ctx context.Context) bool {
		return middleware.HasPermission(ctx, permission.DashboardAggregate.String())
	})

	notifSvc := integration.NewNotificationService(postgres.NewNotificationRepository(db), nil, log)
	notifSvc.SetDataScope(enforcer)

	// The guard is installed on the token-tenant chain exactly as Register does.
	prevGuard := dataScopeGuardMiddleware
	dataScopeGuardMiddleware = middleware.DataScopeGuard(enforcer)
	t.Cleanup(func() { dataScopeGuardMiddleware = prevGuard })

	router := infrahttp.NewChiRouter()
	auth := Middleware(h.dsAuth)
	assetHandler := handler.NewAssetHandler(assetSvc, v, log)
	assetHandler.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
	registerAssetRoutes(router, assetHandler, auth, nil)
	importHandler := handler.NewAssetImportHandler(asset.NewAssetImportService(assetRepo, log), log)
	importHandler.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
	registerAssetImportRoutes(router, importHandler, auth, nil)
	registerVulnerabilityRoutes(router, handler.NewVulnerabilityHandler(vulnSvc, v, log), nil, nil, nil, auth, nil)
	registerAssetGroupRoutes(router, handler.NewAssetGroupHandler(groupSvc, v, log), auth, nil)
	registerAttackSurfaceRoutes(router, handler.NewAttackSurfaceHandler(surfaceSvc, log), auth, nil, passthrough)
	registerExposureRoutes(router, handler.NewExposureHandler(expSvc, nil, v, log), auth, nil, passthrough)
	registerDashboardRoutes(router, handler.NewDashboardHandler(dashSvc, log), auth, nil)
	registerNotificationRoutes(router, handler.NewNotificationHandler(notifSvc, log), auth, nil)

	// Asset sub-resources outside /assets/<uuid>: services, state history,
	// relationships, relationship suggestions, dedup reviews.
	relRepo := postgres.NewAssetRelationshipRepository(db)
	svcHandler := handler.NewAssetServiceHandler(postgres.NewAssetServiceRepository(db), assetRepo, v, log).SetDataScope(enforcer)
	historyHandler := handler.NewAssetStateHistoryHandler(postgres.NewAssetStateHistoryRepository(db), assetRepo, v, log).SetDataScope(enforcer)
	relSvc := asset.NewAssetRelationshipService(relRepo, assetRepo, log)
	relSvc.SetDataScope(enforcer)
	suggSvc := asset.NewRelationshipSuggestionService(postgres.NewRelationshipSuggestionRepository(db), assetRepo, relRepo, log)
	suggSvc.SetDataScope(enforcer)
	dedupHandler := handler.NewAdminDedupHandler(postgres.NewAssetDedupRepository(db), log).SetDataScope(enforcer)
	registerAssetServiceRoutes(router, svcHandler, auth, nil)
	registerWebEndpointRoutes(router, handler.NewWebEndpointHandler(webendpointapp.NewService(postgres.NewWebEndpointRepository(db), enforcer), nil, log), auth, nil)
	registerAssetStateHistoryRoutes(router, historyHandler, auth, nil)
	registerAssetRelationshipRoutes(router, handler.NewAssetRelationshipHandler(relSvc, v, log), auth, nil, passthrough)
	registerRelationshipSuggestionRoutes(router, handler.NewRelationshipSuggestionHandler(suggSvc, log), auth, nil)
	registerAssetDedupRoutes(router, dedupHandler, auth, nil)
	// A sub-resource with no scope code of its own: the guard alone covers it.
	router.Group("/api/v1/assets/{id}/owners", func(r Router) {
		r.GET("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	}, buildTokenTenantMiddlewares(auth, nil)...)

	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *dsHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func (h *dsHarness) seed() {
	h.tenant = shared.NewID()
	h.owner, h.memberA, h.memberFree, h.memberStrict, h.memberFull = shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	h.assetA, h.assetB = shared.NewID(), shared.NewID()
	h.findingA, h.findingB = shared.NewID(), shared.NewID()
	h.exposureA, h.exposureB, h.group = shared.NewID(), shared.NewID(), shared.NewID()
	t := h.tenant.String()

	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, t, "ds-"+t)
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, t)
		for _, u := range []shared.ID{h.owner, h.memberA, h.memberFree, h.memberStrict, h.memberFull} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})
	for u, role := range map[shared.ID]string{h.owner: "owner", h.memberA: "member", h.memberFree: "member", h.memberStrict: "member", h.memberFull: "member"} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, u.String(), u.String()+"@ds.test", role)
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, u.String(), t, role)
		// The team role comes from the system role held (v_user_effective_role).
		roleID := map[string]string{"owner": "00000000-0000-0000-0000-000000000001", "member": "00000000-0000-0000-0000-000000000003"}[role]
		h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, u.String(), t, roleID)
	}
	// memberFull: a "Global Reader" custom role with full data access.
	fullRole := shared.NewID()
	h.exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level, has_full_data_access) VALUES ($1, $2, $3, 'Global Reader', 30, TRUE)`,
		fullRole.String(), t, "ds-global-reader-"+fullRole.String()[:8])
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, h.memberFull.String(), t, fullRole.String())
	for id, name := range map[shared.ID]string{h.assetA: dsMarkerAssetA, h.assetB: dsMarkerAssetB} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			id.String(), t, name)
	}
	for id, f := range map[shared.ID][2]string{h.findingA: {h.assetA.String(), dsMarkerFindingA}, h.findingB: {h.assetB.String(), dsMarkerFindingB}} {
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'sast', 'ds-tool', $4, 'high', $1::text, 'confirmed')`, id.String(), t, f[0], f[1])
	}
	for id, e := range map[shared.ID][2]string{h.exposureA: {h.assetA.String(), "dsA exposure on A1"}, h.exposureB: {h.assetB.String(), dsMarkerExpB}} {
		h.exec(`INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, title, fingerprint, source, severity, state)
			VALUES ($1::uuid, $2, $3, 'port_open', $4, $1::text, 'ds', 'high', 'active')`, id.String(), t, e[0], e[1])
	}
	h.exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'ds-group')`, h.group.String(), t)
	h.exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2), ($1, $3)`,
		h.group.String(), h.assetA.String(), h.assetB.String())
	h.exec(`INSERT INTO finding_comments (finding_id, author_id, content, tenant_id) VALUES ($1, $2, $3, $4)`,
		h.findingB.String(), h.owner.String(), "dsB-SECRET comment", t)
	// The new-finding notices the platform broadcasts to the whole tenant.
	for id, msg := range map[shared.ID]string{h.findingA: dsMarkerFindingA, h.findingB: dsMarkerFindingB} {
		h.exec(`INSERT INTO notifications (tenant_id, audience, notification_type, title, body, severity, resource_type, resource_id)
			VALUES ($1, 'all', 'finding_new', 'New high finding', $2, 'high', 'finding', $3)`, t, msg, id.String())
	}
	// memberA's scope is asset A1 (what group membership materializes).
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberA.String(), t, h.assetA.String())
}

// do sends a request as user (admin when isAdmin) and returns status + body.
func (h *dsHarness) do(user shared.ID, isAdmin bool, method, path string, body any) (int, string) {
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
	req.Header.Set("X-Test-User", user.String())
	if isAdmin {
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

func (h *dsHarness) findingState(id shared.ID) (status, severity, assignee string) {
	h.t.Helper()
	var a sql.NullString
	if err := h.db.QueryRow(`SELECT status, severity, assigned_to::text FROM findings WHERE id = $1`, id.String()).
		Scan(&status, &severity, &a); err != nil {
		h.t.Fatal(err)
	}
	return status, severity, a.String
}

// --- By-id reads and sub-resources -----------------------------------------

func TestDataScope_ByIDReads_OutOfScopeIs404(t *testing.T) {
	h := newDSHarness(t)
	b, fb := h.assetB.String(), h.findingB.String()
	paths := []string{
		"/api/v1/assets/" + b,
		"/api/v1/assets/" + b + "/full",             // was BYPASS (full B1 body)
		"/api/v1/assets/" + b + "/findings",         // was BYPASS (listed FB)
		"/api/v1/assets/" + b + "/owners",           // sub-resource without scope code
		"/api/v1/findings/" + fb,                    // already honored
		"/api/v1/findings/" + fb + "/comments",      // was BYPASS (owner's comment)
		"/api/v1/findings/" + fb + "/dataflows",     // was BYPASS
		"/api/v1/exposures/" + h.exposureB.String(), // was BYPASS
	}
	for _, p := range paths {
		status, body := h.do(h.memberA, false, http.MethodGet, p, nil)
		if status != http.StatusNotFound {
			t.Errorf("memberA GET %s = %d, want 404 (body %.200s)", p, status, body)
		}
		if strings.Contains(body, dsMarkerAssetB) || strings.Contains(body, dsMarkerFindingB) || strings.Contains(body, "dsB-SECRET") {
			t.Errorf("memberA GET %s leaked group-B data: %.200s", p, body)
		}
	}
	// In-scope rows stay readable for the scoped member.
	for _, p := range []string{
		"/api/v1/assets/" + h.assetA.String(),
		"/api/v1/assets/" + h.assetA.String() + "/full",
		"/api/v1/assets/" + h.assetA.String() + "/findings",
		"/api/v1/assets/" + h.assetA.String() + "/owners",
		"/api/v1/findings/" + h.findingA.String(),
		"/api/v1/findings/" + h.findingA.String() + "/comments",
		"/api/v1/exposures/" + h.exposureA.String(),
	} {
		if status, body := h.do(h.memberA, false, http.MethodGet, p, nil); status != http.StatusOK {
			t.Errorf("memberA GET in-scope %s = %d, want 200 (body %.200s)", p, status, body)
		}
	}
}

func TestDataScope_ByIDReads_AdminAndUnrestrictedUnchanged(t *testing.T) {
	h := newDSHarness(t)
	b, fb := h.assetB.String(), h.findingB.String()
	for _, who := range []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"owner", h.owner, true}, {"full-data role", h.memberFull, false}} {
		for _, p := range []string{
			"/api/v1/assets/" + b,
			"/api/v1/assets/" + b + "/full",
			"/api/v1/assets/" + b + "/findings",
			"/api/v1/assets/" + b + "/owners",
			"/api/v1/findings/" + fb,
			"/api/v1/findings/" + fb + "/comments",
			"/api/v1/exposures/" + h.exposureB.String(),
		} {
			if status, body := h.do(who.user, who.admin, http.MethodGet, p, nil); status != http.StatusOK {
				t.Errorf("%s GET %s = %d, want 200 (body %.200s)", who.name, p, status, body)
			}
		}
	}
}

// --- By-id writes ----------------------------------------------------------

func TestDataScope_ByIDWrites_OutOfScopeIs404AndUnchanged(t *testing.T) {
	h := newDSHarness(t)
	fb := "/api/v1/findings/" + h.findingB.String()
	writes := []struct {
		method, path string
		body         any
	}{
		{http.MethodPatch, fb + "/status", map[string]any{"status": "in_progress"}},
		{http.MethodPatch, fb + "/severity", map[string]any{"severity": "low"}},
		{http.MethodPatch, fb + "/triage", map[string]any{"reason": "x"}},
		{http.MethodPut, fb + "/tags", map[string]any{"tags": []string{"pwned"}}},
		{http.MethodPost, fb + "/assign", map[string]any{"user_id": h.memberA.String()}},
		{http.MethodPost, fb + "/comments", map[string]any{"content": "hi"}},
		{http.MethodDelete, fb, nil},
		{http.MethodPut, "/api/v1/assets/" + h.assetB.String(), map[string]any{"description": "pwned"}},
		{http.MethodPost, "/api/v1/assets/" + h.assetB.String() + "/archive", nil},
		{http.MethodDelete, "/api/v1/assets/" + h.assetB.String(), nil},
		{http.MethodPost, "/api/v1/exposures/" + h.exposureB.String() + "/resolve", map[string]any{"reason": "x"}},
	}
	for _, w := range writes {
		status, body := h.do(h.memberA, false, w.method, w.path, w.body)
		if status != http.StatusNotFound {
			t.Errorf("memberA %s %s = %d, want 404 (body %.200s)", w.method, w.path, status, body)
		}
		if strings.Contains(body, dsMarkerFindingB) || strings.Contains(body, dsMarkerAssetB) {
			t.Errorf("memberA %s %s returned group-B data: %.200s", w.method, w.path, body)
		}
	}
	if st, sev, as := h.findingState(h.findingB); st != "confirmed" || sev != "high" || as != "" {
		t.Errorf("FB changed by an out-of-scope member: status=%s severity=%s assignee=%q", st, sev, as)
	}
	var desc sql.NullString
	var status string
	_ = h.db.QueryRow(`SELECT description, status FROM assets WHERE id = $1`, h.assetB.String()).Scan(&desc, &status)
	if desc.String == "pwned" || status != "active" {
		t.Errorf("B1 changed by an out-of-scope member: description=%q status=%s", desc.String, status)
	}
	var expState string
	_ = h.db.QueryRow(`SELECT state FROM exposure_events WHERE id = $1`, h.exposureB.String()).Scan(&expState)
	if expState != "active" {
		t.Errorf("exposure B changed by an out-of-scope member: state=%s", expState)
	}

	// The same member can still change their own group's finding.
	if status, body := h.do(h.memberA, false, http.MethodPatch, "/api/v1/findings/"+h.findingA.String()+"/severity",
		map[string]any{"severity": "low"}); status != http.StatusOK {
		t.Errorf("memberA PATCH in-scope severity = %d, want 200 (body %.200s)", status, body)
	}
	// And an admin can change group B's.
	if status, body := h.do(h.owner, true, http.MethodPatch, fb+"/severity", map[string]any{"severity": "medium"}); status != http.StatusOK {
		t.Errorf("owner PATCH FB severity = %d, want 200 (body %.200s)", status, body)
	}
}

func TestDataScope_BulkByID_SkipsOutOfScope(t *testing.T) {
	h := newDSHarness(t)
	ids := []string{h.findingA.String(), h.findingB.String()}

	status, body := h.do(h.memberA, false, http.MethodPost, "/api/v1/findings/bulk/status",
		map[string]any{"finding_ids": ids, "status": "in_progress"})
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d (body %.300s)", status, body)
	}
	if st, _, _ := h.findingState(h.findingB); st != "confirmed" {
		t.Errorf("bulk status changed out-of-scope FB to %s", st)
	}
	if st, _, _ := h.findingState(h.findingA); st != "in_progress" {
		t.Errorf("bulk status did not change in-scope FA (status %s)", st)
	}
	if !strings.Contains(body, h.findingB.String()+": not found") {
		t.Errorf("bulk status should report FB exactly like a missing id; body %.300s", body)
	}

	status, body = h.do(h.memberA, false, http.MethodPost, "/api/v1/findings/bulk/assign",
		map[string]any{"finding_ids": ids, "user_id": h.memberA.String()})
	if status != http.StatusOK {
		t.Fatalf("bulk assign = %d (body %.300s)", status, body)
	}
	if _, _, as := h.findingState(h.findingB); as != "" {
		t.Errorf("bulk assign assigned out-of-scope FB to %s", as)
	}
	if _, _, as := h.findingState(h.findingA); as != h.memberA.String() {
		t.Errorf("bulk assign did not assign in-scope FA (assignee %q)", as)
	}

	// Asset bulk status: B1 is skipped, A1 is archived.
	status, body = h.do(h.memberA, false, http.MethodPost, "/api/v1/assets/bulk/status",
		map[string]any{"asset_ids": []string{h.assetA.String(), h.assetB.String()}, "status": "inactive"})
	if status != http.StatusOK {
		t.Fatalf("asset bulk status = %d (body %.300s)", status, body)
	}
	var sa, sb string
	_ = h.db.QueryRow(`SELECT status FROM assets WHERE id = $1`, h.assetA.String()).Scan(&sa)
	_ = h.db.QueryRow(`SELECT status FROM assets WHERE id = $1`, h.assetB.String()).Scan(&sb)
	if sa != "inactive" || sb != "active" {
		t.Errorf("asset bulk status: A1=%s (want inactive) B1=%s (want active)", sa, sb)
	}

	// The owner's bulk call still reaches group B.
	status, body = h.do(h.owner, true, http.MethodPost, "/api/v1/findings/bulk/status",
		map[string]any{"finding_ids": []string{h.findingB.String()}, "status": "in_progress"})
	if status != http.StatusOK {
		t.Fatalf("owner bulk status = %d (body %.300s)", status, body)
	}
	if st, _, _ := h.findingState(h.findingB); st != "in_progress" {
		t.Errorf("owner bulk status did not change FB (status %s)", st)
	}
}

// --- Indirect lists --------------------------------------------------------

func TestDataScope_IndirectLists_FilterForScopedMemberOnly(t *testing.T) {
	h := newDSHarness(t)
	g := h.group.String()
	lists := []struct {
		path   string
		marker string // group-B marker the list must not show to memberA
		keep   string // group-A marker it must still show
	}{
		{"/api/v1/asset-groups/" + g + "/assets", dsMarkerAssetB, dsMarkerAssetA},
		{"/api/v1/asset-groups/" + g + "/findings", dsMarkerFindingB, dsMarkerFindingA},
		{"/api/v1/exposures", dsMarkerExpB, "dsA exposure on A1"},
		{"/api/v1/dashboard/stats", dsMarkerFindingB, dsMarkerFindingA},
		{"/api/v1/attack-surface/attack-paths", h.assetB.String(), h.assetA.String()},
		{"/api/v1/attack-surface/stats", dsMarkerAssetB, dsMarkerAssetA},
		{"/api/v1/notifications", dsMarkerFindingB, dsMarkerFindingA},
	}
	for _, l := range lists {
		status, body := h.do(h.memberA, false, http.MethodGet, l.path, nil)
		if status != http.StatusOK {
			t.Errorf("memberA GET %s = %d (body %.200s)", l.path, status, body)
			continue
		}
		if strings.Contains(body, l.marker) {
			t.Errorf("memberA GET %s leaked group-B row %q", l.path, l.marker)
		}
		if !strings.Contains(body, l.keep) {
			t.Errorf("memberA GET %s lost in-scope row %q (body %.300s)", l.path, l.keep, body)
		}
		// Admins and full-data roles keep the full, tenant-wide view.
		for _, who := range []struct {
			name  string
			user  shared.ID
			admin bool
		}{{"owner", h.owner, true}, {"full-data role", h.memberFull, false}} {
			status, body := h.do(who.user, who.admin, http.MethodGet, l.path, nil)
			if status != http.StatusOK || !strings.Contains(body, l.marker) || !strings.Contains(body, l.keep) {
				t.Errorf("%s GET %s = %d, want both rows (body %.300s)", who.name, l.path, status, body)
			}
		}
	}

	// Unread badge counts the same rows the inbox shows.
	_, a := h.do(h.memberA, false, http.MethodGet, "/api/v1/notifications/unread-count", nil)
	_, o := h.do(h.owner, true, http.MethodGet, "/api/v1/notifications/unread-count", nil)
	if !strings.Contains(a, `"count":1`) || !strings.Contains(o, `"count":2`) {
		t.Errorf("unread counts: memberA %s (want 1), owner %s (want 2)", a, o)
	}
}

// --- Members without a scope row see nothing ---------------------------------

// A member with no scope row sees nothing on every list, by-id read (404,
// never 403), count, search and export, while the owner and a full-data role
// see the whole tenant.
func TestDataScope_ScopelessMember_SeesNothingEverywhere(t *testing.T) {
	h := newDSHarness(t)
	a, b := h.assetA.String(), h.assetB.String()
	fa, fb := h.findingA.String(), h.findingB.String()
	byID := []string{
		"/api/v1/assets/" + a, "/api/v1/assets/" + b,
		"/api/v1/assets/" + b + "/full",
		"/api/v1/assets/" + b + "/findings",
		"/api/v1/assets/" + b + "/owners",
		"/api/v1/findings/" + fa, "/api/v1/findings/" + fb,
		"/api/v1/findings/" + fb + "/comments",
		"/api/v1/exposures/" + h.exposureA.String(), "/api/v1/exposures/" + h.exposureB.String(),
	}
	// Lists, searches, counts and exports: none may carry a row of A or B.
	reads := []string{
		"/api/v1/assets?per_page=100",
		"/api/v1/assets?search=example.com",
		"/api/v1/assets/stats",
		"/api/v1/findings?per_page=100",
		"/api/v1/findings?search=finding",
		"/api/v1/findings/stats",
		"/api/v1/exposures",
		"/api/v1/notifications",
		"/api/v1/asset-groups/" + h.group.String() + "/assets",
		"/api/v1/asset-groups/" + h.group.String() + "/findings",
		"/api/v1/dashboard/stats",
	}
	markers := []string{dsMarkerAssetA, dsMarkerAssetB, dsMarkerFindingA, dsMarkerFindingB, dsMarkerExpB, "dsA exposure on A1"}
	for _, u := range []shared.ID{h.memberFree, h.memberStrict} {
		for _, p := range byID {
			if status, body := h.do(u, false, http.MethodGet, p, nil); status != http.StatusNotFound {
				t.Errorf("scopeless member GET %s = %d, want 404 (body %.200s)", p, status, body)
			}
		}
		for _, p := range reads {
			status, body := h.do(u, false, http.MethodGet, p, nil)
			if status != http.StatusOK && status != http.StatusNotFound {
				t.Errorf("scopeless member GET %s = %d (body %.200s)", p, status, body)
				continue
			}
			for _, m := range markers {
				if strings.Contains(body, m) {
					t.Errorf("scopeless member GET %s leaked %q (body %.300s)", p, m, body)
				}
			}
		}
		// Stats count nothing.
		if _, body := h.do(u, false, http.MethodGet, "/api/v1/findings/stats", nil); !strings.Contains(body, `"total":0`) {
			t.Errorf("scopeless member finding stats not empty: %.300s", body)
		}
		if _, body := h.do(u, false, http.MethodGet, "/api/v1/assets/stats", nil); !strings.Contains(body, `"total":0`) {
			t.Errorf("scopeless member asset stats not empty: %.300s", body)
		}
	}
	// Owner and full-data role: unchanged, the whole tenant.
	for _, who := range []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"owner", h.owner, true}, {"full-data role", h.memberFull, false}} {
		for _, p := range byID {
			if status, body := h.do(who.user, who.admin, http.MethodGet, p, nil); status != http.StatusOK {
				t.Errorf("%s GET %s = %d, want 200 (body %.200s)", who.name, p, status, body)
			}
		}
		for _, l := range []struct{ path, marker string }{
			{"/api/v1/assets?per_page=100", dsMarkerAssetB},
			{"/api/v1/findings?per_page=100", dsMarkerFindingB},
			{"/api/v1/exposures", dsMarkerExpB},
		} {
			if _, body := h.do(who.user, who.admin, http.MethodGet, l.path, nil); !strings.Contains(body, l.marker) {
				t.Errorf("%s GET %s lost %q", who.name, l.path, l.marker)
			}
		}
	}
}

// --- Real-time push and WebSocket channels -----------------------------------

func TestDataScope_PushRecipientsAndFindingChannels(t *testing.T) {
	h := newDSHarness(t)
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewNotificationRepository(db)
	tenantRepo := postgres.NewTenantRepository(db)

	recipients := func(findingID shared.ID) map[shared.ID]bool {
		n := notification.NewNotification(notification.NotificationParams{
			TenantID: h.tenant, Audience: notification.AudienceAll, NotificationType: notification.TypeFindingNew,
			Severity: "high", Title: "t", ResourceType: "finding", ResourceID: &findingID,
		})
		ids, err := repo.ListRecipients(context.Background(), n)
		if err != nil {
			t.Fatal(err)
		}
		out := map[shared.ID]bool{}
		for _, id := range ids {
			out[id] = true
		}
		return out
	}
	rb := recipients(h.findingB)
	if rb[h.memberA] || rb[h.memberFree] || !rb[h.owner] || !rb[h.memberFull] {
		t.Errorf("push for FB: memberA=%v memberFree=%v (want false) owner=%v memberFull=%v (want true)",
			rb[h.memberA], rb[h.memberFree], rb[h.owner], rb[h.memberFull])
	}
	// A member with no scope row gets no finding push.
	if ra := recipients(h.findingA); !ra[h.memberA] || ra[h.memberFree] || ra[h.memberStrict] {
		t.Errorf("push for FA: memberA=%v (want true) memberFree=%v memberStrict=%v (want false)",
			ra[h.memberA], ra[h.memberFree], ra[h.memberStrict])
	}

	// WebSocket finding:{id}/triage:{id} subscriptions resolve the user's
	// scope from their membership (no request context).
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), nil, logger.NewNop())
	enforcer.SetAdminLookup(func(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
		m, err := tenantRepo.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return false, err
		}
		return m.IsOwner() || m.IsAdmin(), nil
	})
	ctx := context.Background()
	if enforcer.AssertFindingForUser(ctx, h.tenant, h.memberA, h.findingB) == nil {
		t.Error("memberA may subscribe to finding:FB")
	}
	if err := enforcer.AssertFindingForUser(ctx, h.tenant, h.memberA, h.findingA); err != nil {
		t.Errorf("memberA refused finding:FA: %v", err)
	}
	if err := enforcer.AssertFindingForUser(ctx, h.tenant, h.owner, h.findingB); err != nil {
		t.Errorf("owner refused finding:FB: %v", err)
	}
	if enforcer.AssertFindingForUser(ctx, h.tenant, h.memberFree, h.findingB) == nil {
		t.Error("a member without a scope row may subscribe to finding:FB")
	}
	if err := enforcer.AssertFindingForUser(ctx, h.tenant, h.memberFull, h.findingB); err != nil {
		t.Errorf("full-data role refused finding:FB: %v", err)
	}
}

// --- Repository paths not reached over HTTP above ----------------------------

func TestDataScope_AffectedAssets(t *testing.T) {
	h := newDSHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}

	// One CVE affecting both assets.
	vulnID := shared.NewID()
	cve := "CVE-2099-" + vulnID.String()[:8]
	h.exec(`INSERT INTO vulnerabilities (id, cve_id, title) VALUES ($1, $2, 'ds cve')`, vulnID.String(), cve)
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE id = $1`, vulnID.String())
	})
	h.exec(`UPDATE findings SET vulnerability_id = $1 WHERE id IN ($2, $3)`, vulnID.String(), h.findingA.String(), h.findingB.String())

	repo := postgres.NewFindingRepository(db)
	scope := &shared.DataScope{TenantID: h.tenant, UserID: h.memberA}
	res, err := repo.ListAffectedAssetsByVulnerabilityID(ctx, h.tenant, vulnID, true, pagination.New(1, 20), scope)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || len(res.Data) != 1 || res.Data[0].AssetID != h.assetA.String() {
		t.Errorf("scoped affected assets = total %d rows %+v, want only A1", res.Total, res.Data)
	}
	res, err = repo.ListAffectedAssetsByVulnerabilityID(ctx, h.tenant, vulnID, true, pagination.New(1, 20), nil)
	if err != nil || res.Total != 2 {
		t.Errorf("unscoped affected assets = %d (err %v), want 2", res.Total, err)
	}
}

// --- Asset sub-resources outside /assets/<uuid> -------------------------------
//
// Services, state history, relationships, relationship suggestions and dedup
// reviews hang off assets but live under their own prefixes, so the by-id
// guard on /api/v1/assets/<uuid> never saw them. A scoped member must see and
// change only the rows of assets in their scope; a row that links an in-scope
// asset to an out-of-scope one (a relationship, a suggestion, a dedup review)
// is out of scope, because returning it would reveal the other asset.

const (
	dsMarkerAssetA2 = "dsa-a2.example.com"
	dsMarkerSvcA    = "dsA-svc"
	dsMarkerSvcB    = "dsB-SECRET-svc"
	dsMarkerHistA   = "dsA-hist"
	dsMarkerHistB   = "dsB-SECRET-hist"
	dsMarkerSuggA   = "dsA-suggestion"
	dsMarkerSuggB   = "dsB-SECRET-suggestion"
	dsMarkerLogA    = "dsA-merged-name"
	dsMarkerLogB    = "dsB-SECRET-merged-name"
)

type dsSubresources struct {
	assetA2, svcA, svcB, histA, histB, relAA, relAB shared.ID
	suggAA, suggAB, reviewAA, reviewAB              shared.ID
}

// seedSubresources adds a second in-scope asset A2 and, for each kind of
// sub-resource, one row that stays inside memberA's scope and one that
// reaches group B's asset B1.
func (h *dsHarness) seedSubresources() dsSubresources {
	h.t.Helper()
	t := h.tenant.String()
	r := dsSubresources{
		assetA2: shared.NewID(), svcA: shared.NewID(), svcB: shared.NewID(),
		histA: shared.NewID(), histB: shared.NewID(), relAA: shared.NewID(), relAB: shared.NewID(),
		suggAA: shared.NewID(), suggAB: shared.NewID(), reviewAA: shared.NewID(), reviewAB: shared.NewID(),
	}
	a1, a2, b1 := h.assetA.String(), r.assetA2.String(), h.assetB.String()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
		a2, t, dsMarkerAssetA2)
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberA.String(), t, a2)
	h.exec(`INSERT INTO asset_services (id, tenant_id, asset_id, port, protocol, name, service_type, is_public, exposure)
		VALUES ($1, $3, $4, 443, 'tcp', $5, 'https', TRUE, 'public'), ($2, $3, $6, 8443, 'tcp', $7, 'https', TRUE, 'public')`,
		r.svcA.String(), r.svcB.String(), t, a1, dsMarkerSvcA, b1, dsMarkerSvcB)
	h.exec(`INSERT INTO asset_state_history (id, tenant_id, asset_id, change_type, new_value, reason, source, changed_at)
		VALUES ($1, $3, $4, 'appeared', $5, $5, 'scan', NOW()), ($2, $3, $6, 'appeared', $7, $7, 'scan', NOW())`,
		r.histA.String(), r.histB.String(), t, a1, dsMarkerHistA, b1, dsMarkerHistB)
	h.exec(`INSERT INTO asset_relationships (id, tenant_id, source_asset_id, target_asset_id, relationship_type)
		VALUES ($1, $3, $4, $5, 'depends_on'), ($2, $3, $4, $6, 'depends_on')`,
		r.relAA.String(), r.relAB.String(), t, a1, a2, b1)
	h.exec(`INSERT INTO relationship_suggestions (id, tenant_id, source_asset_id, target_asset_id, relationship_type, reason, status)
		VALUES ($1, $3, $4, $5, 'contains', $7, 'pending'), ($2, $3, $4, $6, 'contains', $8, 'pending')`,
		r.suggAA.String(), r.suggAB.String(), t, a1, a2, b1, dsMarkerSuggA, dsMarkerSuggB)
	h.exec(`INSERT INTO asset_dedup_review (id, tenant_id, normalized_name, asset_type, keep_asset_id, keep_asset_name, merge_asset_ids, merge_asset_names, status)
		VALUES ($1, $3, 'dsa', 'domain', $4, $5, ARRAY[$6]::uuid[], ARRAY[$7], 'pending'),
		       ($2, $3, 'dsb', 'domain', $8, $9, ARRAY[$4]::uuid[], ARRAY[$5], 'pending')`,
		r.reviewAA.String(), r.reviewAB.String(), t, a1, dsMarkerAssetA, a2, dsMarkerAssetA2, b1, dsMarkerAssetB)
	h.exec(`INSERT INTO asset_merge_log (tenant_id, kept_asset_id, kept_asset_name, merged_asset_name, correlation_type, action)
		VALUES ($1, $2, $3, $4, 'admin_review', 'merge'), ($1, $5, $6, $7, 'admin_review', 'merge')`,
		t, a1, dsMarkerAssetA, dsMarkerLogA, b1, dsMarkerAssetB, dsMarkerLogB)
	return r
}

func dsLeaksB(body string) bool {
	for _, m := range []string{dsMarkerAssetB, dsMarkerSvcB, dsMarkerHistB, dsMarkerSuggB, dsMarkerLogB, "dsB-SECRET"} {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

func TestDataScope_SubresourceLists_FilterForScopedMemberOnly(t *testing.T) {
	h := newDSHarness(t)
	r := h.seedSubresources()
	lists := []struct {
		path string
		keep string // in-scope row the scoped member must still see
		hide string // out-of-scope row the scoped member must not see
	}{
		{"/api/v1/services", dsMarkerSvcA, dsMarkerSvcB},
		{"/api/v1/services/public", dsMarkerSvcA, dsMarkerSvcB},
		{"/api/v1/state-history", dsMarkerHistA, dsMarkerHistB},
		{"/api/v1/state-history/appearances", dsMarkerHistA, dsMarkerHistB},
		{"/api/v1/assets/" + h.assetA.String() + "/relationships", r.relAA.String(), r.relAB.String()},
		{"/api/v1/relationships/suggestions", dsMarkerSuggA, dsMarkerSuggB},
		{"/api/v1/assets/dedup/reviews", r.reviewAA.String(), r.reviewAB.String()},
		{"/api/v1/assets/dedup/merge-log", dsMarkerLogA, dsMarkerLogB},
	}
	for _, l := range lists {
		status, body := h.do(h.memberA, false, http.MethodGet, l.path, nil)
		if status != http.StatusOK {
			t.Errorf("memberA GET %s = %d (body %.200s)", l.path, status, body)
			continue
		}
		if strings.Contains(body, l.hide) || dsLeaksB(body) {
			t.Errorf("memberA GET %s leaked an out-of-scope row: %.400s", l.path, body)
		}
		if !strings.Contains(body, l.keep) {
			t.Errorf("memberA GET %s lost the in-scope row %q (body %.300s)", l.path, l.keep, body)
		}
		for _, who := range []struct {
			name  string
			user  shared.ID
			admin bool
		}{{"owner", h.owner, true}, {"full-data role", h.memberFull, false}} {
			status, body := h.do(who.user, who.admin, http.MethodGet, l.path, nil)
			if status != http.StatusOK || !strings.Contains(body, l.keep) || !strings.Contains(body, l.hide) {
				t.Errorf("%s GET %s = %d, want both rows (body %.300s)", who.name, l.path, status, body)
			}
		}
		// A member with no scope row sees neither row.
		if _, body := h.do(h.memberFree, false, http.MethodGet, l.path, nil); strings.Contains(body, l.keep) || strings.Contains(body, l.hide) {
			t.Errorf("scopeless member GET %s saw rows (body %.300s)", l.path, body)
		}
	}

	// Aggregates count only in-scope rows for the scoped member.
	counts := []struct {
		path, member, owner string
	}{
		{"/api/v1/services/stats", `"total_services":1`, `"total_services":2`},
		{"/api/v1/state-history/stats", `"appeared":1`, `"appeared":2`},
		{"/api/v1/state-history/timeline", `"appeared":1`, `"appeared":2`},
		{"/api/v1/state-history/counts", `"appeared":1`, `"appeared":2`},
		{"/api/v1/relationships/suggestions/count", `"count":1`, `"count":2`},
		{"/api/v1/relationships/usage-stats", `"id":"depends_on"`, `"id":"depends_on"`},
	}
	for _, c := range counts {
		_, m := h.do(h.memberA, false, http.MethodGet, c.path, nil)
		_, o := h.do(h.owner, true, http.MethodGet, c.path, nil)
		if !strings.Contains(m, c.member) || !strings.Contains(o, c.owner) {
			t.Errorf("GET %s: memberA %.300s (want %s); owner %.300s (want %s)", c.path, m, c.member, o, c.owner)
		}
	}
	_, m := h.do(h.memberA, false, http.MethodGet, "/api/v1/relationships/usage-stats", nil)
	if !strings.Contains(m, `"id":"depends_on","direct"`) || dsUsageCount(t, m, "depends_on") != 1 {
		t.Errorf("usage-stats for memberA counts depends_on = %d, want 1 (body %.300s)", dsUsageCount(t, m, "depends_on"), m)
	}
	_, o := h.do(h.owner, true, http.MethodGet, "/api/v1/relationships/usage-stats", nil)
	if dsUsageCount(t, o, "depends_on") != 2 {
		t.Errorf("usage-stats for owner counts depends_on = %d, want 2", dsUsageCount(t, o, "depends_on"))
	}
}

func dsUsageCount(t *testing.T, body, typ string) int64 {
	t.Helper()
	var out struct {
		Data []struct {
			ID    string `json:"id"`
			Count int64  `json:"count"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return -1
	}
	for _, d := range out.Data {
		if d.ID == typ {
			return d.Count
		}
	}
	return -1
}

func TestDataScope_SubresourceByID_OutOfScopeIs404AndUnchanged(t *testing.T) {
	h := newDSHarness(t)
	r := h.seedSubresources()
	reqs := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v1/services/" + r.svcB.String(), nil},
		{http.MethodPut, "/api/v1/services/" + r.svcB.String(), map[string]any{"name": "pwned"}},
		{http.MethodDelete, "/api/v1/services/" + r.svcB.String(), nil},
		{http.MethodGet, "/api/v1/state-history/" + r.histB.String(), nil},
		{http.MethodGet, "/api/v1/relationships/" + r.relAB.String(), nil},
		{http.MethodPut, "/api/v1/relationships/" + r.relAB.String(), map[string]any{"description": "pwned"}},
		{http.MethodDelete, "/api/v1/relationships/" + r.relAB.String(), nil},
		{http.MethodPost, "/api/v1/relationships/suggestions/" + r.suggAB.String() + "/approve", nil},
		{http.MethodPost, "/api/v1/relationships/suggestions/" + r.suggAB.String() + "/dismiss", nil},
		{http.MethodPatch, "/api/v1/relationships/suggestions/" + r.suggAB.String() + "/type", map[string]any{"relationship_type": "depends_on"}},
		{http.MethodPost, "/api/v1/assets/dedup/reviews/" + r.reviewAB.String() + "/approve", nil},
		{http.MethodPost, "/api/v1/assets/dedup/reviews/" + r.reviewAB.String() + "/reject", nil},
	}
	for _, q := range reqs {
		status, body := h.do(h.memberA, false, q.method, q.path, q.body)
		if status != http.StatusNotFound {
			t.Errorf("memberA %s %s = %d, want 404 (body %.200s)", q.method, q.path, status, body)
		}
		if dsLeaksB(body) {
			t.Errorf("memberA %s %s returned group-B data: %.200s", q.method, q.path, body)
		}
	}
	var n int
	var name, desc, suggStatus, suggType, reviewStatus sql.NullString
	_ = h.db.QueryRow(`SELECT name FROM asset_services WHERE id = $1`, r.svcB.String()).Scan(&name)
	if name.String != dsMarkerSvcB {
		t.Errorf("service B changed or deleted by an out-of-scope member: name=%q", name.String)
	}
	_ = h.db.QueryRow(`SELECT description FROM asset_relationships WHERE id = $1`, r.relAB.String()).Scan(&desc)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM asset_relationships WHERE id = $1`, r.relAB.String()).Scan(&n)
	if n != 1 || desc.String == "pwned" {
		t.Errorf("relationship A1->B1 changed by an out-of-scope member: exists=%d description=%q", n, desc.String)
	}
	_ = h.db.QueryRow(`SELECT status, relationship_type FROM relationship_suggestions WHERE id = $1`, r.suggAB.String()).Scan(&suggStatus, &suggType)
	if suggStatus.String != "pending" || suggType.String != "contains" {
		t.Errorf("suggestion A1->B1 changed by an out-of-scope member: %s %s", suggStatus.String, suggType.String)
	}
	_ = h.db.QueryRow(`SELECT status FROM asset_dedup_review WHERE id = $1`, r.reviewAB.String()).Scan(&reviewStatus)
	if reviewStatus.String != "pending" {
		t.Errorf("dedup review A1+B1 changed by an out-of-scope member: %s", reviewStatus.String)
	}
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE id = $1`, h.assetB.String()).Scan(&n)
	if n != 1 {
		t.Error("B1 was merged away by an out-of-scope member")
	}

	// In-scope rows stay usable.
	for _, q := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/services/" + r.svcA.String()},
		{http.MethodGet, "/api/v1/state-history/" + r.histA.String()},
		{http.MethodGet, "/api/v1/relationships/" + r.relAA.String()},
		{http.MethodPost, "/api/v1/relationships/suggestions/" + r.suggAA.String() + "/dismiss"},
		{http.MethodPost, "/api/v1/assets/dedup/reviews/" + r.reviewAA.String() + "/reject"},
	} {
		if status, body := h.do(h.memberA, false, q.method, q.path, nil); status != http.StatusOK {
			t.Errorf("memberA %s in-scope %s = %d, want 200 (body %.200s)", q.method, q.path, status, body)
		}
	}
	// An administrator still reaches group B's rows.
	if status, body := h.do(h.owner, true, http.MethodGet, "/api/v1/relationships/"+r.relAB.String(), nil); status != http.StatusOK {
		t.Errorf("owner GET relationship A1->B1 = %d (body %.200s)", status, body)
	}
}

func TestDataScope_SubresourceWrites_TargetMustBeInScope(t *testing.T) {
	h := newDSHarness(t)
	r := h.seedSubresources()
	count := func() int {
		var n int
		_ = h.db.QueryRow(`SELECT COUNT(*) FROM asset_relationships WHERE source_asset_id = $1 AND target_asset_id = $2 AND relationship_type = 'cname_of'`,
			h.assetA.String(), h.assetB.String()).Scan(&n)
		return n
	}
	base := "/api/v1/assets/" + h.assetA.String() + "/relationships"
	status, body := h.do(h.memberA, false, http.MethodPost, base, map[string]any{"target_asset_id": h.assetB.String(), "type": "cname_of"})
	if status == http.StatusCreated || dsLeaksB(body) {
		t.Errorf("memberA linked A1 to out-of-scope B1: %d %.200s", status, body)
	}
	_, _ = h.do(h.memberA, false, http.MethodPost, base+"/batch", map[string]any{
		"items": []map[string]any{{"target_asset_id": h.assetB.String(), "type": "cname_of"}},
	})
	if count() != 0 {
		t.Error("an out-of-scope relationship target was linked")
	}
	// The registry's relationship check runs only after the scope check, so a
	// disallowed pair to an out-of-scope target answers like a missing
	// target and never names that target's type.
	stOut, bodyOut := h.do(h.memberA, false, http.MethodPost, base, map[string]any{"target_asset_id": h.assetB.String(), "type": "runs_on"})
	stMissing, _ := h.do(h.memberA, false, http.MethodPost, base, map[string]any{"target_asset_id": shared.NewID().String(), "type": "runs_on"})
	if stOut != stMissing || strings.Contains(bodyOut, "cannot") {
		t.Errorf("out-of-scope target with a disallowed type = %d %.200s, missing target = %d", stOut, bodyOut, stMissing)
	}
	// The same link to an in-scope target works.
	if status, body := h.do(h.memberA, false, http.MethodPost, base, map[string]any{"target_asset_id": r.assetA2.String(), "type": "cname_of"}); status != http.StatusCreated {
		t.Errorf("memberA link A1->A2 = %d (body %.200s)", status, body)
	}

	// Generating reads and replaces every pending suggestion of the
	// organization: a scoped member may not trigger it.
	if status, body := h.do(h.memberA, false, http.MethodPost, "/api/v1/relationships/suggestions/generate", nil); status != http.StatusForbidden {
		t.Errorf("memberA generate = %d, want 403 (body %.200s)", status, body)
	}

	// Approve-all only approves the suggestions the member can see.
	if status, body := h.do(h.memberA, false, http.MethodPost, "/api/v1/relationships/suggestions/approve-all", nil); status != http.StatusOK {
		t.Fatalf("approve-all = %d (body %.200s)", status, body)
	}
	var sa, sb string
	_ = h.db.QueryRow(`SELECT status FROM relationship_suggestions WHERE id = $1`, r.suggAA.String()).Scan(&sa)
	_ = h.db.QueryRow(`SELECT status FROM relationship_suggestions WHERE id = $1`, r.suggAB.String()).Scan(&sb)
	if sa != "approved" || sb != "pending" {
		t.Errorf("approve-all by memberA: A1->A2 %s (want approved), A1->B1 %s (want pending)", sa, sb)
	}
}

// The duplicate-review queue is readable with assets:read (the web route and
// the asset overview show it to every reader); acting on it needs
// assets:delete.
func TestDataScope_DedupReviewPermissions(t *testing.T) {
	h := newDSHarness(t)
	r := h.seedSubresources()
	call := func(perms, method, path string) int {
		req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Test-User", h.memberFull.String())
		req.Header.Set("X-Test-Perms", perms)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	read := permission.AssetsRead.String()
	if got := call(read, http.MethodGet, "/api/v1/assets/dedup/reviews"); got != http.StatusOK {
		t.Errorf("assets:read GET reviews = %d, want 200", got)
	}
	reject := "/api/v1/assets/dedup/reviews/" + r.reviewAA.String() + "/reject"
	if got := call(read+","+permission.AssetsWrite.String(), http.MethodPost, reject); got != http.StatusForbidden {
		t.Errorf("assets:read+write POST reject = %d, want 403", got)
	}
	if got := call(read+","+permission.AssetsDelete.String(), http.MethodPost, reject); got != http.StatusOK {
		t.Errorf("assets:delete POST reject = %d, want 200", got)
	}
}
