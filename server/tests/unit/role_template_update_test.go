package unit

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// templateRepo adds the role-holder listing UpdateRole needs.
type templateRepo struct{ *ceilingRepo }

func (templateRepo) ListRoleHolderIDs(context.Context, role.ID, role.ID) ([]role.ID, error) {
	return nil, nil
}

func templateService(t *testing.T) (*accesscontrol.RoleService, *templateRepo, role.ID, role.ID, role.ID) {
	t.Helper()
	tid, owner, manager := role.NewID(), role.NewID(), role.NewID()
	var ownerPerms []string
	for _, r := range permission.SystemRoles() {
		if r.Slug == "owner" {
			ownerPerms = permission.ToStrings(r.Permissions)
		}
	}
	ownerR := sysRole(role.OwnerRoleID, "owner", true, ownerPerms...)
	// A delegated role manager: role editing plus the executive template's
	// reads, nothing more.
	exec, _ := permission.RoleTemplateByID("executive")
	managerPerms := append(permission.ToStrings(exec.Permissions), string(permission.RolesWrite), string(permission.RolesRead))
	managerR := role.New(tid, "role-manager", "Role manager", "", 10, false, managerPerms, owner)
	repo := &templateRepo{newCeilingRepo(ownerR, managerR)}
	repo.sets[owner.String()] = []role.ID{role.OwnerRoleID}
	repo.sets[manager.String()] = []role.ID{managerR.ID()}
	svc := accesscontrol.NewRoleService(repo, newMockPermissionRepo(), logger.NewNop(),
		accesscontrol.WithRoleMembershipReader(ceilingMembers{owners: map[string]bool{owner.String(): true}}))
	return svc, repo, tid, owner, manager
}

// Creating a role from a template records the template, its version and the
// permissions it had, even when the creator trimmed the role.
func TestRoleTemplate_CreateRecordsOrigin(t *testing.T) {
	svc, _, tid, owner, _ := templateService(t)
	tpl, _ := permission.RoleTemplateByID("security-analyst")
	trimmed := permission.ToStrings(tpl.Permissions)[:5]
	r, err := svc.CreateRole(context.Background(), accesscontrol.CreateRoleInput{
		TenantID: tid.String(), Slug: "analyst", Name: "Analyst", Permissions: trimmed, TemplateID: tpl.ID,
	}, owner.String(), audit.AuditContext{ActorID: owner.String()})
	if err != nil {
		t.Fatal(err)
	}
	o := r.Template()
	if o == nil || o.ID != tpl.ID || o.Version != tpl.Version || !slices.Equal(o.Permissions, permission.ToStrings(tpl.Permissions)) {
		t.Fatalf("origin = %+v", o)
	}
	if !slices.Equal(r.Permissions(), trimmed) {
		t.Errorf("role permissions = %v, want the creator's %v", r.Permissions(), trimmed)
	}
	if st := accesscontrol.TemplateStatusOf(r); st == nil || st.UpdateAvailable {
		t.Errorf("a role on the current version shows an update: %+v", st)
	}

	_, err = svc.CreateRole(context.Background(), accesscontrol.CreateRoleInput{
		TenantID: tid.String(), Slug: "nope", Name: "Nope", TemplateID: "no-such-template",
	}, owner.String(), audit.AuditContext{ActorID: owner.String()})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown template: %v, want a validation error", err)
	}
}

// A template update never changes a role by itself; applying it adds what the
// template added, removes what it removed, keeps the role's own edits, and is
// bounded by the editor's own grants.
func TestRoleTemplate_UpdateIsOfferedAndApplied(t *testing.T) {
	ctx := context.Background()
	svc, repo, tid, owner, manager := templateService(t)
	tpl, _ := permission.RoleTemplateByID("executive")
	cur := permission.ToStrings(tpl.Permissions)

	// The role took an older version: that version had ReportsRead missing
	// and an extra permission the template later dropped.
	older := append(slices.DeleteFunc(slices.Clone(cur), func(p string) bool { return p == string(permission.ReportsRead) }),
		string(permission.ComponentsRead))
	// The organization's own edit on top: it added AssetGroupsRead.
	rolePerms := append(slices.Clone(older), string(permission.AssetGroupsRead))
	r := role.New(tid, "exec", "Exec", "", 10, false, rolePerms, owner)
	r.SetTemplate(&role.TemplateOrigin{ID: tpl.ID, Version: tpl.Version - 1, Permissions: older})
	repo.roles[r.ID().String()] = r

	_, st, err := svc.RoleTemplateStatus(ctx, tid.String(), r.ID().String())
	if err != nil {
		t.Fatal(err)
	}
	if st == nil || !st.UpdateAvailable ||
		!slices.Equal(st.Diff.Added, []string{string(permission.ReportsRead)}) ||
		!slices.Equal(st.Diff.Removed, []string{string(permission.ComponentsRead)}) {
		t.Fatalf("status = %+v", st)
	}
	// Nothing changed yet.
	if got, _ := svc.GetRole(ctx, tid.String(), r.ID().String()); !slices.Equal(got.Permissions(), rolePerms) {
		t.Fatalf("the role changed before anyone applied the update")
	}

	// A stale review is refused.
	if _, err := svc.ApplyTemplateUpdate(ctx, tid.String(), r.ID().String(), tpl.Version+1,
		audit.AuditContext{ActorID: owner.String()}); !errors.Is(err, shared.ErrConflict) {
		t.Errorf("stale version: %v, want conflict", err)
	}
	// Another organization cannot see or apply it.
	other := role.NewID()
	if _, _, err := svc.RoleTemplateStatus(ctx, other.String(), r.ID().String()); !errors.Is(err, role.ErrRoleNotFound) {
		t.Errorf("cross-tenant status: %v, want not found", err)
	}
	if _, err := svc.ApplyTemplateUpdate(ctx, other.String(), r.ID().String(), tpl.Version,
		audit.AuditContext{ActorID: owner.String()}); !errors.Is(err, role.ErrRoleNotFound) {
		t.Errorf("cross-tenant apply: %v, want not found", err)
	}
	// The delegated manager lacks AssetGroupsRead (kept by the update), so
	// the update is beyond their grants.
	wantForbidden(t, "manager applies", func() error {
		_, err := svc.ApplyTemplateUpdate(ctx, tid.String(), r.ID().String(), tpl.Version,
			audit.AuditContext{ActorID: manager.String()})
		return err
	}())

	got, err := svc.ApplyTemplateUpdate(ctx, tid.String(), r.ID().String(), tpl.Version,
		audit.AuditContext{ActorID: owner.String()})
	if err != nil {
		t.Fatal(err)
	}
	want := append(slices.Clone(cur), string(permission.AssetGroupsRead))
	gp := slices.Clone(got.Permissions())
	slices.Sort(gp)
	slices.Sort(want)
	if !slices.Equal(gp, want) {
		t.Errorf("after update = %v, want %v", gp, want)
	}
	if o := got.Template(); o == nil || o.Version != tpl.Version || !slices.Equal(o.Permissions, cur) {
		t.Errorf("origin after update = %+v", o)
	}
	if st := accesscontrol.TemplateStatusOf(got); st.UpdateAvailable {
		t.Errorf("update still offered after applying it")
	}
	if _, err := svc.ApplyTemplateUpdate(ctx, tid.String(), r.ID().String(), tpl.Version,
		audit.AuditContext{ActorID: owner.String()}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("second apply: %v, want nothing to apply", err)
	}
}
