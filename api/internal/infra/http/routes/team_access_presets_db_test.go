package routes

// Team access presets (research/298) against a migrated database: a preset
// becomes a managed role of the team, members inherit it, and the guards of
// privileged teams hold.

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

var errStepUpNeeded = errors.New("step-up needed")

type denyGate struct{}

func (denyGate) RequireRecentAuth(context.Context, string) error { return errStepUpNeeded }

func (h *grbHarness) setAccess(actor shared.ID, team shared.ID, scope string, presets ...string) (*accesscontrol.TeamAccessView, error) {
	return h.groups.SetTeamAccess(context.Background(), accesscontrol.SetTeamAccessInput{
		GroupID: team.String(), Presets: presets, ScopeMode: scope,
	}, h.actx(actor))
}

func (h *grbHarness) managedRoleOf(team shared.ID, templateID string) shared.ID {
	h.t.Helper()
	var id string
	if err := h.db.QueryRow(`SELECT id FROM roles WHERE managed_group_id = $1 AND template_id = $2`, team.String(), templateID).Scan(&id); err != nil {
		h.t.Fatalf("managed role %s: %v", templateID, err)
	}
	out, _ := shared.IDFromString(id)
	return out
}

// analystPerm is a permission the security-analyst preset carries and the
// built-in viewer and member roles do not.
func analystPerm(t *testing.T) string {
	t.Helper()
	tpl, ok := permission.RoleTemplateByID("security-analyst")
	if !ok {
		t.Fatal("security-analyst template missing")
	}
	builtin := map[permission.Permission]bool{}
	for _, r := range []tenant.Role{tenant.RoleViewer, tenant.RoleMember} {
		for _, p := range permission.RolePermissions[r] {
			builtin[p] = true
		}
	}
	for _, p := range tpl.Permissions {
		if !builtin[p] {
			return string(p)
		}
	}
	t.Fatal("every preset permission is in the built-in roles")
	return ""
}

// An owner picks a preset: members inherit it on add, lose it on removal and
// when the membership ends, and clearing the preset deletes the managed role.
func TestTeamAccess_PresetInheritance(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	perm := analystPerm(t)
	if err := h.addMember(h.owner, h.member); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(h.perms(h.member), perm) {
		t.Fatal("permission before the preset")
	}
	v, err := h.setAccess(h.owner, h.team, "specific", "security-analyst")
	if err != nil {
		t.Fatalf("owner sets a preset: %v", err)
	}
	if len(v.Presets) != 1 || v.ScopeMode != "specific" || v.Privileged {
		t.Fatalf("view = %+v", v)
	}
	if !slices.Contains(h.perms(h.member), perm) {
		t.Fatal("the member did not inherit the preset")
	}
	// A person added later inherits too; a non-member never does.
	if err := h.addMember(h.owner, h.admin); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(h.perms(h.outsider), perm) {
		t.Fatal("a non-member holds the preset")
	}
	// Removal takes it away.
	if err := h.groups.RemoveMember(ctx, h.team.String(), h.admin, h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	// Expiry takes it away at once.
	h.exec(`UPDATE group_members SET expires_at = now() - interval '1 second' WHERE group_id = $1 AND user_id = $2`, h.team.String(), h.member.String())
	if slices.Contains(h.perms(h.member), perm) {
		t.Fatal("an expired member keeps the preset")
	}
	h.exec(`UPDATE group_members SET expires_at = NULL WHERE group_id = $1 AND user_id = $2`, h.team.String(), h.member.String())

	// Setting the same access again changes nothing.
	if _, err := h.setAccess(h.owner, h.team, "specific", "security-analyst"); err != nil {
		t.Fatal(err)
	}
	var n int
	h.exec(`SELECT 1`)
	_ = h.db.QueryRow(`SELECT count(*) FROM roles WHERE managed_group_id = $1`, h.team.String()).Scan(&n)
	if n != 1 {
		t.Fatalf("managed roles after a repeat = %d", n)
	}
	// Clearing the presets removes the access and the role.
	if _, err := h.setAccess(h.owner, h.team, "specific"); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(h.perms(h.member), perm) {
		t.Fatal("the preset survived clearing")
	}
	_ = h.db.QueryRow(`SELECT count(*) FROM roles WHERE managed_group_id = $1`, h.team.String()).Scan(&n)
	if n != 0 {
		t.Fatalf("managed roles after clearing = %d", n)
	}
}

// "All assets" feeds the data-scope engine like has_full_data_access.
func TestTeamAccess_AllAssetsIsFullDataAccess(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	ds := postgres.NewDataScopeRepository(&postgres.DB{DB: h.db})
	if err := h.addMember(h.owner, h.member); err != nil {
		t.Fatal(err)
	}
	if full, _ := ds.HasFullDataRole(ctx, h.tenant, h.member); full {
		t.Fatal("full data before the scope mode")
	}
	v, err := h.setAccess(h.owner, h.team, "all_assets")
	if err != nil {
		t.Fatal(err)
	}
	if v.ScopeMode != "all_assets" || !v.Privileged {
		t.Fatalf("view = %+v", v)
	}
	if full, err := ds.HasFullDataRole(ctx, h.tenant, h.member); err != nil || !full {
		t.Fatalf("member of an all-assets team: full=%v err=%v", full, err)
	}
	if full, _ := ds.HasFullDataRole(ctx, h.tenant, h.outsider); full {
		t.Fatal("a non-member sees all assets")
	}
	// Back to specific assets.
	if _, err := h.setAccess(h.owner, h.team, "specific"); err != nil {
		t.Fatal(err)
	}
	if full, _ := ds.HasFullDataRole(ctx, h.tenant, h.member); full {
		t.Fatal("full data survived switching to specific assets")
	}
}

func TestTeamAccess_PrivilegedTeamGuards(t *testing.T) {
	h := newGRBHarness(t)
	// Only the owner makes a team privileged; an administrator or a team
	// lead cannot, and nothing changed.
	for _, actor := range []shared.ID{h.admin, h.lead} {
		if _, err := h.setAccess(actor, h.team, "all_assets"); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("non-owner sets all assets: %v", err)
		}
		if _, err := h.setAccess(actor, h.team, "specific", "program-lead"); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("non-owner sets a full-data preset: %v", err)
		}
	}
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM roles WHERE managed_group_id = $1`, h.team.String()).Scan(&n)
	if n != 0 {
		t.Fatalf("a refused change created %d roles", n)
	}

	// Owner without a recent sign-in: step-up required.
	h.roleSvc.SetStepUpGate(denyGate{})
	if _, err := h.setAccess(h.owner, h.team, "all_assets"); !errors.Is(err, errStepUpNeeded) {
		t.Fatalf("owner without step-up: %v", err)
	}
	h.roleSvc.SetStepUpGate(nil)
	if _, err := h.setAccess(h.owner, h.team, "all_assets"); err != nil {
		t.Fatal(err)
	}

	// Changing a privileged team, even removing its access, is the owner's.
	if _, err := h.setAccess(h.admin, h.team, "specific"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("admin removes elevated access: %v", err)
	}
	// So is changing the team itself.
	name := "renamed"
	if _, err := h.groups.UpdateGroup(context.Background(), h.team.String(), accesscontrol.UpdateGroupInput{Name: &name}, h.actx(h.admin)); !errors.Is(err, accesscontrol.ErrPrivilegedTeamOwnerOnly) {
		t.Fatalf("admin renames a privileged team: %v", err)
	}
	if _, err := h.groups.UpdateGroup(context.Background(), h.team.String(), accesscontrol.UpdateGroupInput{Name: &name}, h.actx(h.owner)); err != nil {
		t.Fatalf("owner renames a privileged team: %v", err)
	}
}

// Adding people to a privileged managed team needs members:write, which a
// team lead holding the team permissions does not have.
func TestTeamAccess_MembersNeedMembersWriteInPrivilegedTeam(t *testing.T) {
	h := newGRBHarness(t)
	if _, err := h.setAccess(h.owner, h.team, "all_assets"); err != nil {
		t.Fatal(err)
	}
	// The lead is refused (ceiling and members permission).
	if err := h.addMember(h.lead, h.member); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("lead adds to a privileged team: %v", err)
	}
	// A manager who holds full data access and the team member permission,
	// but not members:write, is refused for that reason.
	mgrRole := h.customRole(h.tenant, "team-mgr", true, "team:groups:read", "team:groups:members")
	mgr := h.user(h.tenant, "internal", "")
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, mgr.String(), h.tenant.String(), mgrRole.String())
	if err := h.addMember(mgr, h.member); !errors.Is(err, accesscontrol.ErrPrivilegedTeamNeedsMembersManage) {
		t.Fatalf("manager without members:write: %v", err)
	}
	writer := h.customRole(h.tenant, "member-writer", false, "team:members:write")
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, mgr.String(), h.tenant.String(), writer.String())
	// The cached permissions of mgr were never loaded, so the new role counts.
	if err := h.addMember(mgr, h.member); err != nil {
		t.Fatalf("manager with members:write: %v", err)
	}
	// Nobody outside the organization joins an all-assets team.
	if err := h.addMember(h.owner, h.outsider); !errors.Is(err, accesscontrol.ErrExternalTeamFullData) {
		t.Fatalf("outside member joins an all-assets team: %v", err)
	}
	// Nor is all assets set on a team that already has one.
	other := h.newTeam(h.tenant)
	if _, err := h.groups.AddMember(context.Background(), accesscontrol.AddGroupMemberInput{GroupID: other.String(), UserID: h.outsider, Role: "member"}, h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.setAccess(h.owner, other, "all_assets"); !errors.Is(err, accesscontrol.ErrExternalTeamFullData) {
		t.Fatalf("all assets on a team with an outside member: %v", err)
	}
}

// A managed role is changed only through the team's access settings.
func TestTeamAccess_ManagedRoleIsNotEditable(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	if _, err := h.setAccess(h.owner, h.team, "specific", "security-analyst"); err != nil {
		t.Fatal(err)
	}
	role := h.managedRoleOf(h.team, "security-analyst")
	tid := h.tenant.String()
	name := "renamed"
	if _, err := h.roleSvc.UpdateRole(ctx, tid, role.String(), accesscontrol.UpdateRoleInput{Name: &name}, h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrManagedRole) {
		t.Fatalf("update: %v", err)
	}
	if err := h.roleSvc.DeleteRole(ctx, tid, role.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrManagedRole) {
		t.Fatalf("delete: %v", err)
	}
	if err := h.roleSvc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: tid, UserID: h.member.String(), RoleID: role.String()}, h.owner.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrManagedRole) {
		t.Fatalf("assign: %v", err)
	}
	if err := h.roleSvc.ValidateRolesForTenant(ctx, tid, []string{role.String()}); !errors.Is(err, accesscontrol.ErrManagedRole) {
		t.Fatalf("invitation roles: %v", err)
	}
	// Not bound by hand to another team, nor unbound by hand.
	other := h.newTeam(h.tenant)
	if err := h.groups.BindRole(ctx, other.String(), role.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrManagedRole) {
		t.Fatalf("bind elsewhere: %v", err)
	}
	if err := h.groups.UnbindRole(ctx, h.team.String(), role.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrManagedRole) {
		t.Fatalf("unbind: %v", err)
	}
	// The schema refuses the same moves if the service were bypassed.
	if _, err := h.db.Exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, h.member.String(), tid, role.String()); err == nil {
		t.Error("the schema assigned a managed role to a person")
	}
	if _, err := h.db.Exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, tid, other.String(), role.String()); err == nil {
		t.Error("the schema bound a managed role to another team")
	}
	// Hidden from the Roles list, but shown on the team.
	list, err := h.roleSvc.ListRolesForTenant(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list {
		if r.IsManaged() {
			t.Errorf("managed role %s listed", r.Name())
		}
	}
	views, err := h.groups.ListGroupRoles(ctx, tid, h.team.String())
	if err != nil || len(views) != 1 || !views[0].Managed {
		t.Fatalf("team roles = %+v %v", views, err)
	}
	// Another organization's team and role are not found.
	if _, err := h.groups.SetTeamAccess(ctx, accesscontrol.SetTeamAccessInput{GroupID: h.otherTeam.String(), ScopeMode: "specific", Presets: []string{"security-analyst"}}, h.actx(h.owner)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign team: %v", err)
	}
	if _, err := h.groups.GetTeamAccess(ctx, tid, h.otherTeam.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign team read: %v", err)
	}
	if _, err := h.roleSvc.GetRole(ctx, h.other.String(), role.String()); err == nil {
		t.Fatal("another organization read the managed role")
	}
	// Unknown presets and the internal scope role are refused.
	for _, bad := range []string{"nope", "team-all-assets"} {
		if _, err := h.setAccess(h.owner, h.team, "specific", bad); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("preset %q: %v", bad, err)
		}
	}
	// Deleting the team deletes its managed roles with it.
	if err := h.groups.DeleteGroup(ctx, h.team.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM roles WHERE managed_group_id = $1`, h.team.String()).Scan(&n)
	if n != 0 {
		t.Fatalf("managed roles after deleting the team = %d", n)
	}
}

// A preset an actor does not hold themselves cannot be handed out; owner and
// admin never come through a team.
func TestTeamAccess_CeilingAndSystemRoles(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	if _, err := h.setAccess(h.lead, h.team, "specific", "security-analyst"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("lead hands out a preset above their grants: %v", err)
	}
	for _, sys := range []string{"owner", "admin", "member", "viewer"} {
		if _, err := h.setAccess(h.owner, h.team, "specific", sys); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("system role %q as a preset: %v", sys, err)
		}
	}
	for _, sys := range []roledom.ID{roledom.OwnerRoleID, roledom.AdminRoleID} {
		if err := h.groups.BindRole(ctx, h.team.String(), sys.String(), h.actx(h.owner)); err == nil {
			t.Errorf("system role %s bound to a team", sys)
		}
	}
}

// The outside-member two-factor rule counts a team's presets: a team with
// elevated access is above member for an outside invitee.
func TestTeamAccess_OutsideInviteeSeesTheTeamAsElevated(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	if _, err := h.setAccess(h.owner, h.team, "specific", "program-lead"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.groups.CheckInvitationTeams(ctx, accesscontrol.InvitationTeamCheck{
		TenantID: h.tenant.String(), InviterID: h.owner.String(), GroupIDs: []string{h.team.String()}, External: true,
	}); !errors.Is(err, accesscontrol.ErrExternalTeamFullData) {
		t.Fatalf("outside invitee to a full-data preset team: %v", err)
	}
	plain := h.newTeam(h.tenant)
	if _, err := h.setAccess(h.owner, plain, "specific", "security-analyst"); err != nil {
		t.Fatal(err)
	}
	teams, err := h.groups.CheckInvitationTeams(ctx, accesscontrol.InvitationTeamCheck{
		TenantID: h.tenant.String(), InviterID: h.owner.String(), GroupIDs: []string{plain.String()}, External: true,
	})
	if err != nil || len(teams) != 1 || teams[0].AboveMember {
		t.Fatalf("plain preset team = %+v %v", teams, err)
	}
}

// A team's presets show on the member's profile as access from that team.
func TestTeamAccess_MemberProfileShowsTheTeam(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	if _, err := h.setAccess(h.owner, h.team, "specific", "security-analyst"); err != nil {
		t.Fatal(err)
	}
	if err := h.addMember(h.owner, h.member); err != nil {
		t.Fatal(err)
	}
	got, err := h.groups.ListUserTeamAccess(ctx, h.tenant.String(), h.member)
	if err != nil || len(got) != 1 || got[0].Grant.GroupID != h.team || !got[0].Grant.Managed || got[0].Grant.TemplateID != "security-analyst" {
		t.Fatalf("member access = %+v %v", got, err)
	}
	// The other organization sees nothing of this person.
	none, err := h.groups.ListUserTeamAccess(ctx, h.other.String(), h.member)
	if err != nil || len(none) != 0 {
		t.Fatalf("foreign view = %+v %v", none, err)
	}
	h.exec(`UPDATE group_members SET expires_at = now() - interval '1 second' WHERE group_id = $1 AND user_id = $2`, h.team.String(), h.member.String())
	got, _ = h.groups.ListUserTeamAccess(ctx, h.tenant.String(), h.member)
	if len(got) != 0 {
		t.Fatalf("an ended membership still shows access: %+v", got)
	}
}

// A template update is offered and applied to the team's managed role.
func TestTeamAccess_PresetUpgrade(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	tpl, _ := permission.RoleTemplateByID("security-analyst")
	if tpl.Version < 2 {
		t.Skip("the template has no earlier version to upgrade from")
	}
	if _, err := h.setAccess(h.owner, h.team, "specific", "security-analyst"); err != nil {
		t.Fatal(err)
	}
	role := h.managedRoleOf(h.team, "security-analyst")
	h.exec(`UPDATE roles SET template_version = 1 WHERE id = $1`, role.String())
	h.exec(`DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`, role.String(), analystPerm(t))
	v, err := h.groups.GetTeamAccess(ctx, h.tenant.String(), h.team.String())
	if err != nil || len(v.Presets) != 1 || !v.Presets[0].UpdateAvailable {
		t.Fatalf("view = %+v %v", v, err)
	}
	if _, err := h.groups.UpgradeTeamPreset(ctx, h.team.String(), "security-analyst", tpl.Version+1, h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrTemplateUpdateStale) {
		t.Fatalf("stale version: %v", err)
	}
	if _, err := h.groups.UpgradeTeamPreset(ctx, h.team.String(), "security-analyst", tpl.Version, h.actx(h.lead)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("lead upgrades: %v", err)
	}
	v, err = h.groups.UpgradeTeamPreset(ctx, h.team.String(), "security-analyst", tpl.Version, h.actx(h.owner))
	if err != nil || v.Presets[0].UpdateAvailable {
		t.Fatalf("upgrade = %+v %v", v, err)
	}
	if err := h.addMember(h.owner, h.member); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.perms(h.member), analystPerm(t)) {
		t.Fatal("the upgrade did not restore the permission")
	}
	if _, err := h.groups.UpgradeTeamPreset(ctx, h.team.String(), "security-analyst", tpl.Version, h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrNoPresetUpdate) {
		t.Fatalf("second upgrade: %v", err)
	}
}
