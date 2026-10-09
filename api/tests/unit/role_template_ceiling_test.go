package unit

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A role template is only a starting point: creating a role from it goes
// through CreateRole, so nobody can use a template to build a role above their
// own grants. The owner can create every template; a delegated role manager
// can create only the templates their own permissions cover.
func TestRoleTemplates_CreationIsBoundedByTheCreator(t *testing.T) {
	ctx := context.Background()
	tid, owner, manager := role.NewID(), role.NewID(), role.NewID()

	var ownerPerms []string
	for _, r := range permission.SystemRoles() {
		if r.Slug == "owner" {
			ownerPerms = permission.ToStrings(r.Permissions)
		}
	}
	ownerR := sysRole(role.OwnerRoleID, "owner", true, ownerPerms...)

	analyst, _ := permission.RoleTemplateByID("security-analyst")
	managerPerms := append(permission.ToStrings(analyst.Permissions), string(permission.RolesWrite), string(permission.RolesRead))
	managerR := role.New(tid, "role-manager", "Role manager", "", 10, false, managerPerms, owner)

	repo := newCeilingRepo(ownerR, managerR)
	repo.sets[owner.String()] = []role.ID{role.OwnerRoleID}
	repo.sets[manager.String()] = []role.ID{managerR.ID()}
	svc := accesscontrol.NewRoleService(repo, newMockPermissionRepo(), logger.NewNop(),
		accesscontrol.WithRoleMembershipReader(ceilingMembers{owners: map[string]bool{owner.String(): true}}))

	create := func(actor role.ID, tpl permission.RoleTemplate, slug string) error {
		_, err := svc.CreateRole(ctx, accesscontrol.CreateRoleInput{
			TenantID: tid.String(), Slug: slug, Name: tpl.Name, Description: tpl.Description,
			HasFullDataAccess: tpl.HasFullDataAccess, Permissions: permission.ToStrings(tpl.Permissions),
		}, actor.String(), audit.AuditContext{ActorID: actor.String()})
		return err
	}

	for _, tpl := range permission.RoleTemplates() {
		if err := create(owner, tpl, tpl.ID); err != nil {
			t.Errorf("owner creates %s: %v", tpl.ID, err)
		}
	}

	// Full data access, risk approval and fix_apply are beyond an analyst.
	for _, id := range []string{"program-lead", "auditor", "risk-approver", "remediation-owner", "validation-engineer"} {
		tpl, _ := permission.RoleTemplateByID(id)
		wantForbidden(t, "role manager creates "+id, create(manager, tpl, "m-"+id))
	}
	// A template inside the manager's own grants is allowed.
	exec, _ := permission.RoleTemplateByID("executive")
	if err := create(manager, exec, "m-executive"); err != nil {
		t.Errorf("role manager creates executive: %v", err)
	}
}
