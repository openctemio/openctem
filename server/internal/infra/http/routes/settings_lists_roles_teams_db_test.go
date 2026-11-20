package routes

// Roles list usage (members, pending approvals) and Teams list access
// summaries against a migrated database: counts are tenant-scoped and come
// from grouped queries.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/internal/app/accesscontrol"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	roledom "github.com/openctemio/openctem/server/pkg/domain/role"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

func asRole(id shared.ID) roledom.ID {
	r, _ := roledom.ParseID(id.String())
	return r
}

func (h *grbHarness) pendingApproval(tenant string, status string, expired bool) {
	h.t.Helper()
	f := uuid.NewString()
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, 'sast', 'x', 'm', 'low', $1::text, 'new')`, f, tenant)
	exp := "now() + interval '1 day'"
	if expired {
		exp = "now() - interval '1 day'"
	}
	h.exec(`INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status, status, expires_at)
		VALUES ($1, $2::uuid, 'accepted', $3, `+exp+`)`, tenant, f, status)
}

func TestRolesList_UsageCountsAreTenantScoped_DB(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	tid := h.tenant.String()

	approver := h.customRole(h.tenant, "approver", false, string(permission.FindingsApprove), "findings:read")
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, h.member.String(), tid, approver.String())
	// The same person through a team too counts once; a second person through
	// the team counts.
	if err := h.groups.BindRole(ctx, h.team.String(), approver.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	if err := h.addMember(h.owner, h.member); err != nil {
		t.Fatal(err)
	}
	if err := h.addMember(h.owner, h.lead); err != nil {
		t.Fatal(err)
	}
	h.pendingApproval(tid, "pending", false)
	h.pendingApproval(tid, "pending", false)
	h.pendingApproval(tid, "pending", true)               // expired: not waiting
	h.pendingApproval(tid, "approved", false)             // decided
	h.pendingApproval(h.other.String(), "pending", false) // another tenant

	roles, err := h.roleSvc.ListRolesForTenant(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := h.roleSvc.RoleUsageForTenant(ctx, tid, roles)
	if err != nil {
		t.Fatal(err)
	}
	if u := usage[asRole(approver)]; u.Members != 2 || u.PendingApprovals != 2 {
		t.Errorf("approver usage = %+v, want 2 members and 2 pending approvals", u)
	}
	if u := usage[asRole(h.analyst)]; u.Members != 0 || u.PendingApprovals != 0 {
		t.Errorf("analyst (no findings:approve) usage = %+v", u)
	}
	if u := usage[roledom.ViewerRoleID]; u.Members < 1 {
		t.Errorf("viewer usage = %+v, want the viewer holders of this tenant only", u)
	}

	// Another tenant reading the same roles sees none of this tenant's people
	// or approvals.
	foreign, err := h.roleSvc.RoleUsageForTenant(ctx, h.other.String(), roles)
	if err != nil {
		t.Fatal(err)
	}
	if u := foreign[asRole(approver)]; u.Members != 0 {
		t.Errorf("another tenant sees %d members of this tenant's role", u.Members)
	}
	fr, _ := h.roleSvc.ListRolesForTenant(ctx, h.other.String())
	fu, _ := h.roleSvc.RoleUsageForTenant(ctx, h.other.String(), fr)
	if u := fu[asRole(h.foreign)]; u.Members != 0 || u.PendingApprovals != 0 {
		t.Errorf("foreign role usage = %+v", u)
	}
	for _, r := range fr {
		if r.ID() == asRole(approver) {
			t.Error("another tenant lists this tenant's role")
		}
	}
}

func TestTeamsList_AccessSummaryBatch_DB(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	tid := h.tenant.String()

	if _, err := h.setAccess(h.owner, h.team, "all_assets", "security-analyst"); err != nil {
		t.Fatal(err)
	}
	second := h.newTeam(h.tenant)
	if err := h.groups.BindRole(ctx, second.String(), h.analyst.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	empty := h.newTeam(h.tenant)
	// The other tenant's team carries a preset of its own.
	h.exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, h.other.String(), h.otherTeam.String(), h.foreign.String())

	out, err := h.groups.ListGroups(ctx, accesscontrol.ListGroupsInput{TenantID: tid, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.groups.ListTeamAccess(ctx, tid, out.Groups)
	if err != nil {
		t.Fatal(err)
	}
	if v := got[h.team]; v.ScopeMode != "all_assets" || !v.Privileged || len(v.Presets) != 1 || v.Presets[0].TemplateID != "security-analyst" {
		t.Errorf("preset team view = %+v", v)
	}
	if v := got[second]; v.ScopeMode != "specific" || v.OtherRoles != 1 || len(v.Presets) != 0 {
		t.Errorf("hand-bound team view = %+v", v)
	}
	if v, ok := got[empty]; !ok || v.ScopeMode != "specific" || v.OtherRoles != 0 || v.Privileged {
		t.Errorf("empty team view = %+v ok=%v", v, ok)
	}

	// Another tenant asking about this tenant's teams gets empty views.
	cross, err := h.groups.ListTeamAccess(ctx, h.other.String(), out.Groups)
	if err != nil {
		t.Fatal(err)
	}
	for id, v := range cross {
		if v.OtherRoles != 0 || len(v.Presets) != 0 || v.Privileged || v.ScopeMode != "specific" {
			t.Errorf("team %s leaked to another tenant: %+v", id, v)
		}
	}
}

// The lists answer with the new fields, and keep their permission gates: a
// caller without roles:read or team:groups:read is refused before the handler
// runs, a reader of another tenant sees none of this tenant's rows.
func TestSettingsLists_ShapeAndGates_DB(t *testing.T) {
	h := newGRBHarness(t)
	log := logger.NewNop()
	roleH := handler.NewRoleHandler(h.roleSvc, validator.New(), log)
	groupH := handler.NewGroupHandler(h.groups, validator.New(), log)
	if _, err := h.setAccess(h.owner, h.team, "specific", "security-analyst"); err != nil {
		t.Fatal(err)
	}

	call := func(tenant string, perms []string, gate permission.Permission, hf http.HandlerFunc, path string) *httptest.ResponseRecorder {
		called := false
		wrapped := middleware.Require(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			hf(w, r)
		}))
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
		ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, perms)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code == http.StatusForbidden && called {
			t.Errorf("%s: handler ran for a refused caller", path)
		}
		return rec
	}

	// Without the permission: 403, no data.
	if rec := call(h.tenant.String(), []string{"findings:read"}, permission.RolesRead, roleH.ListRoles, "/api/v1/roles"); rec.Code != http.StatusForbidden {
		t.Errorf("roles without roles:read = %d", rec.Code)
	}
	if rec := call(h.tenant.String(), []string{"findings:read"}, permission.GroupsRead, groupH.ListGroups, "/api/v1/groups"); rec.Code != http.StatusForbidden {
		t.Errorf("groups without the group permission = %d", rec.Code)
	}

	// With it: the new fields are present.
	rec := call(h.tenant.String(), []string{string(permission.RolesRead)}, permission.RolesRead, roleH.ListRoles, "/api/v1/roles")
	if rec.Code != http.StatusOK {
		t.Fatalf("roles = %d %s", rec.Code, rec.Body.String())
	}
	var roles struct {
		Roles []map[string]any `json:"roles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &roles); err != nil {
		t.Fatal(err)
	}
	for _, r := range roles.Roles {
		if _, ok := r["members_count"]; !ok {
			t.Fatalf("role %v has no members_count", r["slug"])
		}
		if _, ok := r["pending_approvals"]; !ok {
			t.Fatalf("role %v has no pending_approvals", r["slug"])
		}
	}
	rec = call(h.tenant.String(), []string{string(permission.GroupsRead)}, permission.GroupsRead, groupH.ListGroups, "/api/v1/groups")
	if rec.Code != http.StatusOK {
		t.Fatalf("groups = %d %s", rec.Code, rec.Body.String())
	}
	var groups struct {
		Groups []struct {
			ID     string `json:"id"`
			Access *struct {
				ScopeMode string `json:"scope_mode"`
				Presets   []struct {
					TemplateID string `json:"template_id"`
				} `json:"presets"`
			} `json:"access"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &groups); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range groups.Groups {
		if g.Access == nil {
			t.Fatalf("team %s has no access summary", g.ID)
		}
		if g.ID == h.team.String() {
			found = true
			if g.Access.ScopeMode != "specific" || len(g.Access.Presets) != 1 || g.Access.Presets[0].TemplateID != "security-analyst" {
				t.Errorf("team access = %+v", g.Access)
			}
		}
	}
	if !found {
		t.Fatal("team missing from the list")
	}

	// Another tenant lists its own teams only.
	rec = call(h.other.String(), []string{string(permission.GroupsRead)}, permission.GroupsRead, groupH.ListGroups, "/api/v1/groups")
	if rec.Code != http.StatusOK || bytesContains(rec.Body.String(), h.team.String()) {
		t.Errorf("another tenant's team list = %d, leaks this tenant's team: %v", rec.Code, bytesContains(rec.Body.String(), h.team.String()))
	}
}

func bytesContains(s, sub string) bool { return strings.Contains(s, sub) }
