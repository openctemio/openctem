package routes

// Organization and personal dashboards (docs/architecture/dashboards.md):
// permission and audience on every read, dashboards:org:manage on every
// change, audit rows for manager actions, personal dashboards owner-only,
// layout-only copies, tenant isolation and the refresh floor.

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

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fixedFloor map[shared.ID]int

func (f fixedFloor) Limit(_ context.Context, tenantID shared.ID, key limits.Key) (int, error) {
	if key != limits.DashboardRefreshFloorMinutes {
		return limits.Unlimited, nil
	}
	if v, ok := f[tenantID]; ok {
		return v, nil
	}
	return limits.Unlimited, nil
}

type dashHarness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server

	tenant, other                          shared.ID
	owner, manager, viewer, viewerR, plain shared.ID
	otherManager                           shared.ID
	roleR, group, otherGroup               shared.ID
}

var (
	dashView   = permission.DashboardsOrgView.String()
	dashManage = permission.DashboardsOrgManage.String()
)

// auth names the caller in headers: X-Test-Tenant, X-Test-User,
// X-Test-Admin, X-Test-Perms.
func (h *dashHarness) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
		ctx = context.WithValue(ctx, middleware.TenantIDKey, r.Header.Get("X-Test-Tenant"))
		ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
		perms := []string{permission.DashboardRead.String()}
		if p := r.Header.Get("X-Test-Perms"); p != "" {
			perms = append(perms, strings.Split(p, ",")...)
		}
		ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newDashHarness(t *testing.T) *dashHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping dashboard DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	h := &dashHarness{t: t, db: sqldb}
	h.seed()

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	svc := dashboardapp.NewService(postgres.NewUserDashboardRepository(db), log)
	svc.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
	svc.SetMembershipReader(postgres.NewTenantRepository(db))
	svc.SetLimitReader(fixedFloor{h.other: 60})

	router := infrahttp.NewChiRouter()
	registerUserDashboardRoutes(router, handler.NewUserDashboardHandler(svc, log), Middleware(h.auth), nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *dashHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func (h *dashHarness) seed() {
	h.tenant, h.other = shared.NewID(), shared.NewID()
	h.owner, h.manager, h.viewer, h.viewerR, h.plain, h.otherManager = shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	h.roleR, h.group, h.otherGroup = shared.NewID(), shared.NewID(), shared.NewID()
	users := []shared.ID{h.owner, h.manager, h.viewer, h.viewerR, h.plain, h.otherManager}
	for _, tid := range []shared.ID{h.tenant, h.other} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tid.String(), "dash-"+tid.String())
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tid := range []shared.ID{h.tenant, h.other} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id = $1`, tid.String())
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String())
		}
		for _, u := range users {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})
	for _, u := range users {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'dash user')`, u.String(), u.String()+"@dash.test")
	}
	members := map[shared.ID]string{h.owner: "owner", h.manager: "member", h.viewer: "member", h.viewerR: "member", h.plain: "member"}
	for u, role := range members {
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, u.String(), h.tenant.String(), role)
	}
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`, h.otherManager.String(), h.other.String())
	// Role R (custom, tenant) held by viewerR; a team in each tenant.
	h.exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level) VALUES ($1, $2, $3, 'Role R', 20)`,
		h.roleR.String(), h.tenant.String(), "dash-r-"+h.roleR.String()[:8])
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, h.viewerR.String(), h.tenant.String(), h.roleR.String())
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'Dash team', $3)`, h.group.String(), h.tenant.String(), "dash-"+h.group.String()[:8])
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'Other team', $3)`, h.otherGroup.String(), h.other.String(), "dash-"+h.otherGroup.String()[:8])
}

type caller struct {
	tenant, user shared.ID
	admin        bool
	perms        []string
}

func (h *dashHarness) do(c caller, method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Tenant", c.tenant.String())
	req.Header.Set("X-Test-User", c.user.String())
	if c.admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	if len(c.perms) > 0 {
		req.Header.Set("X-Test-Perms", strings.Join(c.perms, ","))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (h *dashHarness) auditCount(action, resourceID string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2 AND resource_id = $3`,
		h.tenant.String(), action, resourceID).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func names(body map[string]any) []string {
	data, _ := body["data"].([]any)
	out := make([]string, 0, len(data))
	for _, d := range data {
		m, _ := d.(map[string]any)
		out = append(out, m["name"].(string))
	}
	return out
}

var layout = map[string]any{"name": "CISO", "columns": 2, "layout": []map[string]any{{"widget_type": "kpi", "x": 0, "y": 0, "w": 1, "h": 1}}}

func TestOrgDashboards_PermissionsAndAudit_DB(t *testing.T) {
	h := newDashHarness(t)
	manager := caller{h.tenant, h.manager, false, []string{dashManage}}
	viewer := caller{h.tenant, h.viewer, false, []string{dashView}}
	plain := caller{h.tenant, h.plain, false, nil}
	owner := caller{h.tenant, h.owner, true, nil}

	// Nobody without a dashboards permission reads or creates.
	if code, _ := h.do(plain, http.MethodGet, "/api/v1/organization/dashboards", nil); code != http.StatusForbidden {
		t.Fatalf("member without dashboards:org:view lists = %d, want 403", code)
	}
	if code, _ := h.do(viewer, http.MethodPost, "/api/v1/organization/dashboards", layout); code != http.StatusForbidden {
		t.Fatalf("viewer creates = %d, want 403", code)
	}

	code, created := h.do(manager, http.MethodPost, "/api/v1/organization/dashboards", layout)
	if code != http.StatusCreated || created["kind"] != "organization" {
		t.Fatalf("manager creates = %d %v", code, created)
	}
	id := created["id"].(string)
	code, second := h.do(owner, http.MethodPost, "/api/v1/organization/dashboards", map[string]any{"name": "VM", "layout": []any{}})
	if code != http.StatusCreated {
		t.Fatalf("owner (admin) creates = %d", code)
	}
	id2 := second["id"].(string)
	if h.auditCount("dashboard.org_created", id) != 1 {
		t.Fatal("create not audited")
	}

	// The viewer reads; every change is refused.
	if code, body := h.do(viewer, http.MethodGet, "/api/v1/organization/dashboards", nil); code != http.StatusOK || len(names(body)) != 2 {
		t.Fatalf("viewer lists = %d %v", code, body)
	}
	if code, body := h.do(viewer, http.MethodGet, "/api/v1/organization/dashboards/"+id, nil); code != http.StatusOK || body["audience"] != nil {
		t.Fatalf("viewer reads = %d %v (no audience for viewers)", code, body)
	}
	denied := []struct{ method, path string }{
		{http.MethodPut, "/" + id},
		{http.MethodDelete, "/" + id},
		{http.MethodPost, "/" + id + "/default"},
		{http.MethodPut, "/" + id + "/audience"},
		{http.MethodPut, "/" + id + "/schedule"},
		{http.MethodPut, "/order"},
	}
	for _, d := range denied {
		if code, _ := h.do(viewer, d.method, "/api/v1/organization/dashboards"+d.path, map[string]any{}); code != http.StatusForbidden {
			t.Errorf("viewer %s %s = %d, want 403", d.method, d.path, code)
		}
	}

	// Every manager action succeeds and is audited.
	upd := map[string]any{"name": "CISO overview", "layout": []any{}}
	if code, _ := h.do(manager, http.MethodPut, "/api/v1/organization/dashboards/"+id, upd); code != http.StatusOK {
		t.Fatalf("update = %d", code)
	}
	if code, _ := h.do(manager, http.MethodPost, "/api/v1/organization/dashboards/"+id+"/default", nil); code != http.StatusOK {
		t.Fatalf("default = %d", code)
	}
	if code, _ := h.do(manager, http.MethodPut, "/api/v1/organization/dashboards/"+id+"/schedule", map[string]any{"refresh_schedule": "15m"}); code != http.StatusOK {
		t.Fatalf("schedule = %d", code)
	}
	if code, _ := h.do(manager, http.MethodPut, "/api/v1/organization/dashboards/order", map[string]any{"ids": []string{id2, id}}); code != http.StatusOK {
		t.Fatalf("order = %d", code)
	}
	// A stale order (one dashboard missing) is refused.
	if code, _ := h.do(manager, http.MethodPut, "/api/v1/organization/dashboards/order", map[string]any{"ids": []string{id}}); code != http.StatusConflict {
		t.Fatalf("stale order = %d, want 409", code)
	}
	aud := map[string]any{"audience": []map[string]string{{"type": "role", "id": h.roleR.String()}}}
	if code, body := h.do(manager, http.MethodPut, "/api/v1/organization/dashboards/"+id+"/audience", aud); code != http.StatusOK || body["audience"] == nil {
		t.Fatalf("audience = %d %v", code, body)
	}
	for _, a := range []string{"dashboard.org_updated", "dashboard.org_default_set", "dashboard.schedule_changed", "dashboard.audience_changed"} {
		if h.auditCount(a, id) != 1 {
			t.Errorf("%s not audited", a)
		}
	}
	if h.auditCount("dashboard.org_reordered", h.tenant.String()) != 1 {
		t.Error("reorder not audited")
	}
	_, list := h.do(manager, http.MethodGet, "/api/v1/organization/dashboards", nil)
	if n := names(list); len(n) != 2 || n[0] != "VM" || n[1] != "CISO overview" {
		t.Fatalf("order after reorder = %v", n)
	}

	// Audience: the viewer without role R no longer sees the dashboard
	// (not found, never forbidden); viewerR does; managers see every one.
	if _, body := h.do(viewer, http.MethodGet, "/api/v1/organization/dashboards", nil); len(names(body)) != 1 {
		t.Fatalf("viewer outside the audience lists %v", names(body))
	}
	if code, _ := h.do(viewer, http.MethodGet, "/api/v1/organization/dashboards/"+id, nil); code != http.StatusNotFound {
		t.Fatalf("viewer outside the audience reads = %d, want 404", code)
	}
	if code, _ := h.do(viewer, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"from_organization_dashboard_id": id}); code != http.StatusNotFound {
		t.Fatalf("viewer outside the audience duplicates = %d, want 404", code)
	}
	viewerR := caller{h.tenant, h.viewerR, false, []string{dashView}}
	if code, _ := h.do(viewerR, http.MethodGet, "/api/v1/organization/dashboards/"+id, nil); code != http.StatusOK {
		t.Fatalf("viewer holding role R reads = %d", code)
	}
	// An audience never widens: role R without dashboards:org:view is refused.
	if code, _ := h.do(caller{h.tenant, h.viewerR, false, nil}, http.MethodGet, "/api/v1/organization/dashboards/"+id, nil); code != http.StatusForbidden {
		t.Fatalf("role R without the permission = %d, want 403", code)
	}
	// A team audience admits the team's members.
	h.exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, h.group.String(), h.viewer.String())
	aud = map[string]any{"audience": []map[string]string{{"type": "group", "id": h.group.String()}}}
	if code, _ := h.do(manager, http.MethodPut, "/api/v1/organization/dashboards/"+id+"/audience", aud); code != http.StatusOK {
		t.Fatalf("team audience = %d", code)
	}
	if code, _ := h.do(viewer, http.MethodGet, "/api/v1/organization/dashboards/"+id, nil); code != http.StatusOK {
		t.Fatalf("team member reads = %d", code)
	}
	// Another tenant's team or an unknown role is refused.
	aud = map[string]any{"audience": []map[string]string{{"type": "group", "id": h.otherGroup.String()}}}
	if code, _ := h.do(manager, http.MethodPut, "/api/v1/organization/dashboards/"+id+"/audience", aud); code != http.StatusBadRequest {
		t.Fatalf("other tenant's team = %d, want 400", code)
	}

	// Duplicate to mine: a personal copy of the layout, nothing else.
	code, dup := h.do(viewer, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"from_organization_dashboard_id": id})
	if code != http.StatusCreated || dup["kind"] != "personal" || dup["origin"] != "duplicated" || dup["refresh_schedule"] != "" || dup["is_org_default"] != nil {
		t.Fatalf("duplicate = %d %v", code, dup)
	}
	if _, mine := h.do(viewer, http.MethodGet, "/api/v1/me/dashboards", nil); len(names(mine)) != 1 {
		t.Fatalf("viewer's personal dashboards = %v", names(mine))
	}
	// The organization list never shows personal dashboards and the other way round.
	if _, body := h.do(manager, http.MethodGet, "/api/v1/organization/dashboards", nil); len(names(body)) != 2 {
		t.Fatalf("org list after duplicate = %v", names(body))
	}
	if code, _ := h.do(viewer, http.MethodGet, "/api/v1/me/dashboards/"+id, nil); code != http.StatusNotFound {
		t.Fatalf("organization dashboard via /me = %d, want 404", code)
	}
	if code, _ := h.do(manager, http.MethodGet, "/api/v1/organization/dashboards/"+dup["id"].(string), nil); code != http.StatusNotFound {
		t.Fatalf("personal dashboard via the organization path = %d, want 404", code)
	}

	// Cross-tenant: another organization's manager neither reads nor changes it.
	otherMgr := caller{h.other, h.otherManager, true, nil}
	if code, _ := h.do(otherMgr, http.MethodGet, "/api/v1/organization/dashboards/"+id, nil); code != http.StatusNotFound {
		t.Fatalf("other tenant reads = %d, want 404", code)
	}
	if code, _ := h.do(otherMgr, http.MethodPut, "/api/v1/organization/dashboards/"+id, upd); code != http.StatusNotFound {
		t.Fatalf("other tenant updates = %d, want 404", code)
	}
	if code, _ := h.do(otherMgr, http.MethodDelete, "/api/v1/organization/dashboards/"+id, nil); code != http.StatusNotFound {
		t.Fatalf("other tenant deletes = %d, want 404", code)
	}
	if _, body := h.do(otherMgr, http.MethodGet, "/api/v1/organization/dashboards", nil); len(names(body)) != 0 {
		t.Fatalf("other tenant lists %v", names(body))
	}
	// The other tenant's floor is 60 minutes: 15m is refused there.
	_, oc := h.do(otherMgr, http.MethodPost, "/api/v1/organization/dashboards", layout)
	if code, _ := h.do(otherMgr, http.MethodPut, "/api/v1/organization/dashboards/"+oc["id"].(string)+"/schedule", map[string]any{"refresh_schedule": "15m"}); code != http.StatusBadRequest {
		t.Fatalf("schedule below the floor = %d, want 400", code)
	}
	if code, _ := h.do(otherMgr, http.MethodPut, "/api/v1/organization/dashboards/"+oc["id"].(string)+"/schedule", map[string]any{"refresh_schedule": "1h"}); code != http.StatusOK {
		t.Fatalf("schedule at the floor = %d", code)
	}

	// Delete.
	if code, _ := h.do(manager, http.MethodDelete, "/api/v1/organization/dashboards/"+id, nil); code != http.StatusNoContent {
		t.Fatalf("delete = %d", code)
	}
	if h.auditCount("dashboard.org_deleted", id) != 1 {
		t.Fatal("delete not audited")
	}
	var audience int
	_ = h.db.QueryRow(`SELECT count(*) FROM dashboard_audience WHERE dashboard_id = $1`, id).Scan(&audience)
	if audience != 0 {
		t.Fatalf("audience rows left after delete: %d", audience)
	}
}

func TestPersonalDashboards_OwnerOnlyAndShareCopies_DB(t *testing.T) {
	h := newDashHarness(t)
	me := caller{h.tenant, h.viewer, false, nil}
	colleague := caller{h.tenant, h.plain, false, nil}

	code, d := h.do(me, http.MethodPost, "/api/v1/me/dashboards", layout)
	if code != http.StatusCreated || d["kind"] != "personal" {
		t.Fatalf("create = %d %v", code, d)
	}
	id := d["id"].(string)
	// Someone else (same tenant, an administrator, or another tenant) never
	// reaches it through /me.
	for name, c := range map[string]caller{
		"colleague":     colleague,
		"owner (admin)": {h.tenant, h.owner, true, nil},
		"other tenant":  {h.other, h.otherManager, true, nil},
	} {
		if code, _ := h.do(c, http.MethodGet, "/api/v1/me/dashboards/"+id, nil); code != http.StatusNotFound {
			t.Errorf("%s reads = %d, want 404", name, code)
		}
		if code, _ := h.do(c, http.MethodPut, "/api/v1/me/dashboards/"+id+"/schedule", map[string]any{"refresh_schedule": "1h"}); code != http.StatusNotFound {
			t.Errorf("%s sets the schedule = %d, want 404", name, code)
		}
		if code, _ := h.do(c, http.MethodPost, "/api/v1/me/dashboards/"+id+"/share", map[string]any{"user_ids": []string{c.user.String()}}); code != http.StatusNotFound {
			t.Errorf("%s shares = %d, want 404", name, code)
		}
	}
	// Owner sets a daily schedule.
	daily := map[string]any{"refresh_schedule": "daily", "refresh_daily_minute": 420}
	if code, body := h.do(me, http.MethodPut, "/api/v1/me/dashboards/"+id+"/schedule", daily); code != http.StatusOK || body["refresh_schedule"] != "daily" || body["next_refresh_at"] == nil {
		t.Fatalf("schedule = %d %v", code, body)
	}

	// Share: the colleague gets a copy; another tenant's user and the sharer
	// themself get nothing.
	share := map[string]any{"user_ids": []string{h.plain.String(), h.otherManager.String(), h.viewer.String()}}
	code, res := h.do(me, http.MethodPost, "/api/v1/me/dashboards/"+id+"/share", share)
	if code != http.StatusOK {
		t.Fatalf("share = %d %v", code, res)
	}
	if s, _ := res["shared"].([]any); len(s) != 1 || s[0] != h.plain.String() {
		t.Fatalf("shared = %v", res)
	}
	if sk, _ := res["skipped"].([]any); len(sk) != 2 {
		t.Fatalf("skipped = %v", res)
	}
	_, theirs := h.do(colleague, http.MethodGet, "/api/v1/me/dashboards", nil)
	data, _ := theirs["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("colleague's dashboards = %v", theirs)
	}
	cp := data[0].(map[string]any)
	if cp["origin"] != "shared" || cp["refresh_schedule"] != "" || cp["id"] == id || cp["name"] != "CISO" {
		t.Fatalf("copy = %v (layout only, its own id, no schedule)", cp)
	}
	// Sharing again names the copy "CISO (2)".
	if code, _ := h.do(me, http.MethodPost, "/api/v1/me/dashboards/"+id+"/share", map[string]any{"user_ids": []string{h.plain.String()}}); code != http.StatusOK {
		t.Fatal("second share")
	}
	_, theirs = h.do(colleague, http.MethodGet, "/api/v1/me/dashboards", nil)
	if n := names(theirs); len(n) != 2 || (n[0] != "CISO (2)" && n[1] != "CISO (2)") {
		t.Fatalf("names after second share = %v", n)
	}
	// The other tenant's user has nothing.
	if _, body := h.do(caller{h.other, h.otherManager, true, nil}, http.MethodGet, "/api/v1/me/dashboards", nil); len(names(body)) != 0 {
		t.Fatalf("other tenant user got %v", names(body))
	}
	if h.auditCount("dashboard.layout_shared", id) != 2 {
		t.Fatal("share not audited")
	}

	// At most 30 personal dashboards.
	for i := 0; i < 29; i++ {
		body := map[string]any{"name": "D" + string(rune('A'+i)), "layout": []any{}}
		if code, _ := h.do(me, http.MethodPost, "/api/v1/me/dashboards", body); code != http.StatusCreated {
			t.Fatalf("create #%d = %d", i+2, code)
		}
	}
	if code, _ := h.do(me, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"name": "one too many", "layout": []any{}}); code != http.StatusBadRequest {
		t.Fatalf("31st dashboard = %d, want 400", code)
	}
}
