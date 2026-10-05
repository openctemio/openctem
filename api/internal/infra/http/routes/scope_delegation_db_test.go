package routes

// The scope-widening cap (owner decision D13, research doc 15 L-09) over the
// real group and scope-rule routes and a migrated database. A custom role
// with groups:write / groups:members (a "team lead") restricted to one asset
// could assign any asset to a group, add themselves to any group, add others
// to a group holding assets the lead cannot see, or write a scope rule that
// pulls in any matching asset. Now a caller can only hand out scope they
// hold.

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
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type sdHarness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server

	tenant, other                 string
	admin, lead, peer, outsider   string
	reader                        string // holds a has_full_data_access role
	assetIn, assetOut             string
	groupIn, groupOut, groupEmpty string
}

func (h *sdHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func newSDHarness(t *testing.T) *sdHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping scope delegation DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &sdHarness{t: t, db: sqldb}
	h.seed()

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	acRepo := postgres.NewAccessControlRepository(db)
	groupRepo := postgres.NewGroupRepository(db)
	groupSvc := app.NewGroupService(groupRepo, log,
		app.WithAccessControlRepository(acRepo), app.WithScopeDelegationCap(enforcer))
	ruleSvc := scopeapp.NewRuleService(acRepo, groupRepo, log)
	ruleSvc.SetScopeDelegationCap(enforcer)

	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			uid := r.Header.Get("X-Test-User")
			ctx = context.WithValue(ctx, middleware.UserIDKey, uid)
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenant)
			ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
			if id, err := shared.IDFromString(uid); err == nil {
				if u, err := userdom.NewLocalUserWithID(id, uid+"@sd.test", "sd"); err == nil {
					ctx = context.WithValue(ctx, middleware.LocalUserKey, u)
				}
			}
			ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{
				permission.GroupsRead.String(), permission.GroupsWrite.String(), permission.GroupsMembers.String(), permission.GroupsAssets.String(),
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	registerGroupRoutes(router, handler.NewGroupHandler(groupSvc, validator.New(), log), auth, nil)
	registerScopeRuleRoutes(router, handler.NewScopeRuleHandler(ruleSvc, validator.New(), log), auth, nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *sdHarness) seed() {
	id := func() string { return shared.NewID().String() }
	h.tenant, h.other = id(), id()
	h.admin, h.lead, h.peer, h.outsider, h.reader = id(), id(), id(), id(), id()
	h.assetIn, h.assetOut = id(), id()
	h.groupIn, h.groupOut, h.groupEmpty = id(), id(), id()

	for _, tn := range []string{h.tenant, h.other} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn, "sd-"+tn)
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tn := range []string{h.tenant, h.other} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM roles WHERE tenant_id = $1`, tn)
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range []string{h.admin, h.lead, h.peer, h.outsider, h.reader} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{h.admin, h.lead, h.peer, h.outsider, h.reader} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'sd')`, u, u+"@sd.test")
	}
	for _, u := range []string{h.admin, h.lead, h.peer, h.reader} {
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u, h.tenant)
	}
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, h.outsider, h.other)
	for _, a := range []string{h.assetIn, h.assetOut} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			a, h.tenant, "sd-"+a+".example.com")
	}
	for g, name := range map[string]string{h.groupIn: "in", h.groupOut: "out", h.groupEmpty: "empty"} {
		h.exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, $3, $4)`, g, h.tenant, "sd "+name, "sd-"+g)
	}
	h.exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`, h.assetIn, h.groupIn)
	h.exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`, h.assetOut, h.groupOut)
	// The lead may see assetIn only.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.lead, h.tenant, h.assetIn)
	// The reader holds a full-data role (and one scope row of its own).
	role := id()
	h.exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level, has_full_data_access) VALUES ($1, $2, $3, 'Global Reader', 30, TRUE)`,
		role, h.tenant, "sd-reader-"+role[:8])
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, h.reader, h.tenant, role)
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.reader, h.tenant, h.assetIn)
}

func (h *sdHarness) do(user string, admin bool, method, path string, body any) (int, string) {
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

func (h *sdHarness) expect(user string, admin bool, method, path string, body any, want int) string {
	h.t.Helper()
	status, out := h.do(user, admin, method, path, body)
	if status != want {
		h.t.Errorf("%s %s = %d, want %d (%.200s)", method, path, status, want, out)
	}
	return out
}

func (h *sdHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(q, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestScopeDelegation_GroupAssets_DB(t *testing.T) {
	h := newSDHarness(t)
	assets := "/api/v1/groups/" + h.groupEmpty + "/assets"

	h.expect(h.lead, false, http.MethodPost, assets, map[string]any{"asset_id": h.assetOut, "ownership_type": "secondary"}, http.StatusNotFound)
	h.expect(h.lead, false, http.MethodPost, assets, map[string]any{"asset_id": h.assetIn, "ownership_type": "secondary"}, http.StatusNoContent)
	body := h.expect(h.lead, false, http.MethodPost, assets+"/bulk", map[string]any{
		"asset_ids": []string{h.assetOut}, "ownership_type": "secondary"}, http.StatusOK)
	if !strings.Contains(body, `"success_count":0`) {
		t.Errorf("bulk assign of an out-of-scope asset by the lead: %s, want 0 successes", body)
	}
	if n := h.count(`SELECT COUNT(*) FROM asset_owners WHERE group_id = $1 AND asset_id = $2`, h.groupEmpty, h.assetOut); n != 0 {
		t.Error("the lead assigned an asset outside their scope")
	}
	h.expect(h.admin, true, http.MethodPost, assets, map[string]any{"asset_id": h.assetOut, "ownership_type": "secondary"}, http.StatusNoContent)
}

func TestScopeDelegation_GroupMembers_DB(t *testing.T) {
	h := newSDHarness(t)
	members := func(g string) string { return "/api/v1/groups/" + g + "/members" }
	add := func(u string) map[string]any { return map[string]any{"user_id": u, "role": "member"} }

	// Self-membership needs full data access.
	h.expect(h.lead, false, http.MethodPost, members(h.groupIn), add(h.lead), http.StatusForbidden)
	// Others only into a group whose assets the lead holds.
	h.expect(h.lead, false, http.MethodPost, members(h.groupOut), add(h.peer), http.StatusForbidden)
	h.expect(h.lead, false, http.MethodPost, members(h.groupIn), add(h.peer), http.StatusCreated)
	// Not a member of the organization (L-14): not found.
	h.expect(h.admin, true, http.MethodPost, members(h.groupIn), add(h.outsider), http.StatusNotFound)
	if n := h.count(`SELECT COUNT(*) FROM user_accessible_assets WHERE user_id = $1 AND asset_id = $2`, h.peer, h.assetOut); n != 0 {
		t.Error("the peer got an asset the lead does not hold")
	}
	// An admin and a full-data role holder may do both.
	h.expect(h.admin, true, http.MethodPost, members(h.groupOut), add(h.admin), http.StatusCreated)
	h.expect(h.reader, false, http.MethodPost, members(h.groupOut), add(h.reader), http.StatusCreated)
}

func TestScopeDelegation_ScopeRules_DB(t *testing.T) {
	h := newSDHarness(t)
	rules := "/api/v1/groups/" + h.groupIn + "/scope-rules"
	rule := map[string]any{"name": "sd tags", "rule_type": "tag_match", "match_tags": []string{"prod"}, "match_logic": "any"}

	h.expect(h.lead, false, http.MethodPost, rules+"/", rule, http.StatusForbidden)
	if n := h.count(`SELECT COUNT(*) FROM group_asset_scope_rules WHERE group_id = $1`, h.groupIn); n != 0 {
		t.Error("the lead created a scope rule")
	}
	body := h.expect(h.admin, true, http.MethodPost, rules+"/", rule, http.StatusCreated)
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &created)
	h.expect(h.lead, false, http.MethodPut, rules+"/"+created.ID, map[string]any{"match_tags": []string{"prod", "dev"}}, http.StatusForbidden)
}

// The group-modification cap (RFC-050 W7, research 21b M-4): a restricted
// manager may unassign an asset, change an ownership type or remove someone
// else only in a group whose whole asset set is inside their own scope.
func TestScopeDelegation_GroupModificationCap_DB(t *testing.T) {
	h := newSDHarness(t)
	out := "/api/v1/groups/" + h.groupOut
	in := "/api/v1/groups/" + h.groupIn
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, h.groupOut, h.peer)
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, h.groupOut, h.lead)

	h.expect(h.lead, false, http.MethodDelete, out+"/assets/"+h.assetOut, nil, http.StatusForbidden)
	h.expect(h.lead, false, http.MethodPut, out+"/assets/"+h.assetOut, map[string]any{"ownership_type": "primary"}, http.StatusForbidden)
	h.expect(h.lead, false, http.MethodDelete, out+"/members/"+h.peer, nil, http.StatusForbidden)
	if n := h.count(`SELECT COUNT(*) FROM asset_owners WHERE group_id = $1 AND asset_id = $2 AND ownership_type = 'secondary'`, h.groupOut, h.assetOut); n != 1 {
		t.Error("the lead changed another BU's group asset")
	}
	if n := h.count(`SELECT COUNT(*) FROM group_members WHERE group_id = $1 AND user_id = $2`, h.groupOut, h.peer); n != 1 {
		t.Error("the lead removed a member of a group they do not fully cover")
	}

	// Leaving a group oneself only narrows one's own scope: allowed.
	h.expect(h.lead, false, http.MethodDelete, out+"/members/"+h.lead, nil, http.StatusNoContent)
	// Inside their own scope the lead manages the group.
	h.expect(h.lead, false, http.MethodPut, in+"/assets/"+h.assetIn, map[string]any{"ownership_type": "primary"}, http.StatusNoContent)
	h.expect(h.lead, false, http.MethodDelete, in+"/assets/"+h.assetIn, nil, http.StatusNoContent)
	// An administrator is not capped.
	h.expect(h.admin, true, http.MethodDelete, out+"/members/"+h.peer, nil, http.StatusNoContent)
}
