package routes

// Layer 2 data scope (access groups → user_accessible_assets) over the real
// route registration, handlers, services and a migrated database.
//
// Each test reproduces one bypass from the 2026-10 data-scope audit (finding
// F4): a member whose scope is group A (asset A1) could read and change
// group B's asset B1 and finding FB through by-id routes, sub-resources,
// bulk-by-id actions and indirect lists. The same requests are also made as
// an administrator and as a member with no scope assignment, whose behavior
// must not change (fail-open stays the default).

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

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/attack"
	"github.com/openctemio/api/internal/app/datascope"
	infrahttp "github.com/openctemio/api/internal/infra/http"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/internal/testdb"
	"github.com/openctemio/api/pkg/domain/notification"
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/api/pkg/validator"
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

	tenant, owner, memberA, memberFree, memberStrict shared.ID
	assetA, assetB, findingA, findingB               shared.ID
	exposureA, exposureB, group                      shared.ID
}

// dsStrictPolicy reads the organization's policy (members without an access
// group see everything | nothing) straight from the database, uncached.
type dsStrictPolicy struct{ h *dsHarness }

func (p dsStrictPolicy) RestrictedDataScope(ctx context.Context, tenantID string) bool {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return false
	}
	v, err := postgres.NewTenantRepository(&postgres.DB{DB: p.h.db}).GetMembersWithoutGroupSee(ctx, id)
	return err == nil && tenant.RestrictsMembersWithoutGroup(v)
}

// setPolicy sets what members without an access group see in the harness tenant.
func (h *dsHarness) setPolicy(v string) {
	h.t.Helper()
	h.exec(`UPDATE tenants SET members_without_group_see = $2 WHERE id = $1`, h.tenant.String(), v)
}

// dsMemberPerms is what a generous custom "member" role holds: every
// permission the probed routes need, so a 404 can only come from data scope.
var dsMemberPerms = []string{ //nolint:gochecknoglobals // test fixture
	permission.AssetsRead.String(), permission.AssetsWrite.String(), permission.AssetsDelete.String(),
	permission.FindingsRead.String(), permission.FindingsWrite.String(), permission.FindingsDelete.String(),
	permission.FindingsStatus.String(), permission.FindingsTriage.String(), permission.FindingsAssign.String(),
	permission.FindingsBulkUpdate.String(), permission.FindingsVerify.String(),
	permission.AssetGroupsRead.String(), permission.DashboardRead.String(),
}

// dsAuth is a stand-in for UnifiedAuth: the test names the caller in headers.
func (h *dsHarness) dsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
		ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenant.String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
		ctx = context.WithValue(ctx, middleware.PermissionsKey, dsMemberPerms)
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

	enforcer := datascope.New(postgres.NewDataScopeRepository(db), dsStrictPolicy{h},
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

	assetSvc := app.NewAssetService(assetRepo, log)
	assetSvc.SetAccessControlRepository(accessRepo)
	assetSvc.SetDataScopePolicy(dsStrictPolicy{h})
	assetSvc.SetDataScope(enforcer)

	vulnSvc := app.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), findingRepo, log)
	vulnSvc.SetCommentRepository(postgres.NewFindingCommentRepository(db))
	vulnSvc.SetAccessControlRepository(accessRepo)
	vulnSvc.SetDataScopePolicy(dsStrictPolicy{h})
	vulnSvc.SetDataScope(enforcer)
	vulnSvc.SetAssetRepository(assetRepo)

	groupSvc := app.NewAssetGroupService(postgres.NewAssetGroupRepository(db), log)
	groupSvc.SetDataScope(enforcer)

	surfaceSvc := attack.NewSurfaceService(assetRepo, postgres.NewAssetRelationshipRepository(db), log)
	surfaceSvc.SetFindingRiskCounter(findingRepo)
	surfaceSvc.SetDataScope(enforcer)

	expSvc := app.NewExposureService(postgres.NewExposureRepository(db), postgres.NewExposureStateHistoryRepository(db), log)
	expSvc.SetDataScope(enforcer)

	dashSvc := app.NewDashboardService(postgres.NewDashboardRepository(sqldb), log)
	dashSvc.SetDataScope(enforcer)

	notifSvc := app.NewNotificationService(postgres.NewNotificationRepository(db), nil, log)
	notifSvc.SetDataScope(enforcer)

	// The guard is installed on the token-tenant chain exactly as Register does.
	prevGuard := dataScopeGuardMiddleware
	dataScopeGuardMiddleware = middleware.DataScopeGuard(enforcer)
	t.Cleanup(func() { dataScopeGuardMiddleware = prevGuard })

	router := infrahttp.NewChiRouter()
	auth := Middleware(h.dsAuth)
	registerAssetRoutes(router, handler.NewAssetHandler(assetSvc, v, log), auth, nil)
	registerVulnerabilityRoutes(router, handler.NewVulnerabilityHandler(vulnSvc, v, log), nil, nil, nil, auth, nil)
	registerAssetGroupRoutes(router, handler.NewAssetGroupHandler(groupSvc, v, log), auth, nil)
	registerAttackSurfaceRoutes(router, handler.NewAttackSurfaceHandler(surfaceSvc, log), auth, nil, passthrough)
	registerExposureRoutes(router, handler.NewExposureHandler(expSvc, nil, v, log), auth, nil, passthrough)
	registerDashboardRoutes(router, handler.NewDashboardHandler(dashSvc, log), auth, nil)
	registerNotificationRoutes(router, handler.NewNotificationHandler(notifSvc, log), auth, nil)
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
	h.owner, h.memberA, h.memberFree, h.memberStrict = shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	h.assetA, h.assetB = shared.NewID(), shared.NewID()
	h.findingA, h.findingB = shared.NewID(), shared.NewID()
	h.exposureA, h.exposureB, h.group = shared.NewID(), shared.NewID(), shared.NewID()
	t := h.tenant.String()

	// An organization that existed before the "nothing" default: its members
	// without an access group see everything.
	h.exec(`INSERT INTO tenants (id, name, slug, members_without_group_see) VALUES ($1, $2, $2, 'everything')`, t, "ds-"+t)
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, t)
		for _, u := range []shared.ID{h.owner, h.memberA, h.memberFree, h.memberStrict} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})
	for u, role := range map[shared.ID]string{h.owner: "owner", h.memberA: "member", h.memberFree: "member", h.memberStrict: "member"} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, u.String(), u.String()+"@ds.test", role)
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, u.String(), t, role)
		// The team role comes from the system role held (v_user_effective_role).
		roleID := map[string]string{"owner": "00000000-0000-0000-0000-000000000001", "member": "00000000-0000-0000-0000-000000000003"}[role]
		h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, u.String(), t, roleID)
	}
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
	}{{"owner", h.owner, true}, {"member without group", h.memberFree, false}} {
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
		// Admins and unrestricted members keep the full, tenant-wide view.
		for _, who := range []struct {
			name  string
			user  shared.ID
			admin bool
		}{{"owner", h.owner, true}, {"member without group", h.memberFree, false}} {
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

// --- Fail-closed tenants -----------------------------------------------------

func TestDataScope_StrictTenant_MemberWithoutGroupSeesNothing(t *testing.T) {
	h := newDSHarness(t)
	h.setPolicy(tenant.MembersWithoutGroupSeeNothing)
	if status, _ := h.do(h.memberStrict, false, http.MethodGet, "/api/v1/findings/"+h.findingA.String()+"/comments", nil); status != http.StatusNotFound {
		t.Errorf("strict tenant, member without group: finding comments = %d, want 404", status)
	}
	if _, body := h.do(h.memberStrict, false, http.MethodGet, "/api/v1/exposures", nil); strings.Contains(body, "exposure on") {
		t.Errorf("strict tenant, member without group listed exposures: %.200s", body)
	}
	if status, _ := h.do(h.owner, true, http.MethodGet, "/api/v1/findings/"+h.findingB.String()+"/comments", nil); status != http.StatusOK {
		t.Errorf("strict tenant: owner lost access (%d)", status)
	}
}

// --- Real-time push and WebSocket channels -----------------------------------

func TestDataScope_PushRecipientsAndFindingChannels(t *testing.T) {
	h := newDSHarness(t)
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewNotificationRepository(db)
	tenantRepo := postgres.NewTenantRepository(db)

	recipients := func(findingID shared.ID, strict bool) map[shared.ID]bool {
		n := notification.NewNotification(notification.NotificationParams{
			TenantID: h.tenant, Audience: notification.AudienceAll, NotificationType: notification.TypeFindingNew,
			Severity: "high", Title: "t", ResourceType: "finding", ResourceID: &findingID,
		})
		ids, err := repo.ListRecipients(context.Background(), n, strict)
		if err != nil {
			t.Fatal(err)
		}
		out := map[shared.ID]bool{}
		for _, id := range ids {
			out[id] = true
		}
		return out
	}
	rb := recipients(h.findingB, false)
	if rb[h.memberA] || !rb[h.owner] || !rb[h.memberFree] {
		t.Errorf("push for FB: memberA=%v (want false) owner=%v memberFree=%v (want true)", rb[h.memberA], rb[h.owner], rb[h.memberFree])
	}
	if ra := recipients(h.findingA, false); !ra[h.memberA] {
		t.Error("push for in-scope FA must reach memberA")
	}
	if rs := recipients(h.findingA, true); rs[h.memberFree] || !rs[h.owner] || !rs[h.memberA] {
		t.Errorf("strict push for FA: memberFree=%v (want false) owner=%v memberA=%v (want true)", rs[h.memberFree], rs[h.owner], rs[h.memberA])
	}

	// WebSocket finding:{id}/triage:{id} subscriptions resolve the user's
	// scope from their membership (no request context).
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), nil, nil, logger.NewNop())
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
	if err := enforcer.AssertFindingForUser(ctx, h.tenant, h.memberFree, h.findingB); err != nil {
		t.Errorf("member without group refused finding:FB: %v", err)
	}
}

// --- Repository paths not reached over HTTP above ----------------------------

func TestDataScope_AffectedAssetsAndCrossTenantActivity(t *testing.T) {
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

	// Cross-tenant dashboard activity: a tenant where the user is restricted
	// contributes only in-scope findings.
	dash := postgres.NewDashboardRepository(h.db)
	items, err := dash.GetFilteredRecentActivity(ctx, nil, []string{h.tenant.String()}, h.memberA.String(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var sawA, sawB bool
	for _, it := range items {
		sawA = sawA || it.Description == dsMarkerFindingA
		sawB = sawB || it.Description == dsMarkerFindingB
	}
	if !sawA || sawB {
		t.Errorf("restricted cross-tenant activity: sawA=%v (want true) sawB=%v (want false)", sawA, sawB)
	}
	items, err = dash.GetFilteredRecentActivity(ctx, []string{h.tenant.String()}, nil, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	sawB = false
	for _, it := range items {
		sawB = sawB || it.Description == dsMarkerFindingB
	}
	if !sawB {
		t.Error("unrestricted cross-tenant activity must include FB")
	}
}
