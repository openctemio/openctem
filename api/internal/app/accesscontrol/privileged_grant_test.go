package accesscontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
)

// fakeHolderRepo answers only the two reads the privileged-grant guards use.
type fakeHolderRepo struct {
	roledom.Repository
	userRoles []*roledom.Role
	holders   []*roledom.UserRole
}

func (f fakeHolderRepo) GetUserRoles(context.Context, roledom.ID, roledom.ID) ([]*roledom.Role, error) {
	return f.userRoles, nil
}

func (f fakeHolderRepo) ListRoleMembers(context.Context, roledom.ID, roledom.ID) ([]*roledom.UserRole, error) {
	return f.holders, nil
}

func customRole(tid roledom.ID, perms []string, fullData bool) *roledom.Role {
	now := time.Now()
	return roledom.Reconstruct(roledom.NewID(), &tid, "c", "C", "", false, 1, fullData, perms, now, now, nil)
}

// A non-system actor granting a privileged custom role to a user who does not
// hold it needs a recent sign-in; a plain role, a role already held and a
// system path do not.
func TestAuthorizePrivilegedGrant(t *testing.T) {
	tid, uid := roledom.NewID(), roledom.NewID()
	actor := grantActor{id: "actor"}
	priv := customRole(tid, []string{"team:members:invite"}, false)
	plain := customRole(tid, []string{"assets:read"}, false)
	gate := stepUpGate{requester: "actor"}
	ctx := context.Background()

	svc := &RoleService{roleRepo: fakeHolderRepo{}, stepUp: gate}
	if err := svc.authorizePrivilegedGrant(ctx, actor, tid, uid, []*roledom.Role{plain}); err != nil {
		t.Errorf("plain role: want nil, got %v", err)
	}
	if err := svc.authorizePrivilegedGrant(ctx, actor, tid, uid, []*roledom.Role{plain, priv}); !errors.Is(err, errStepUp) {
		t.Errorf("privileged role: want step-up, got %v", err)
	}
	if err := (&RoleService{roleRepo: fakeHolderRepo{}, stepUp: stepUpGate{requester: "actor", fresh: true}}).
		authorizePrivilegedGrant(ctx, actor, tid, uid, []*roledom.Role{priv}); err != nil {
		t.Errorf("privileged role after step-up: %v", err)
	}
	held := &RoleService{roleRepo: fakeHolderRepo{userRoles: []*roledom.Role{priv}}, stepUp: gate}
	if err := held.authorizePrivilegedGrant(ctx, actor, tid, uid, []*roledom.Role{priv}); err != nil {
		t.Errorf("already held: want nil, got %v", err)
	}
	if err := svc.authorizePrivilegedGrant(ctx, grantActor{system: true}, tid, uid, []*roledom.Role{priv}); err != nil {
		t.Errorf("system actor: want nil, got %v", err)
	}
	if err := (&RoleService{roleRepo: fakeHolderRepo{}}).authorizePrivilegedGrant(ctx, actor, tid, uid, []*roledom.Role{priv}); err != nil {
		t.Errorf("no step-up gate wired: want nil, got %v", err)
	}
}

// An edit that makes a directly-held role privileged needs a recent sign-in;
// the same edit on a role nobody holds, or one that stays plain, does not.
func TestGuardDirectRolePrivilege(t *testing.T) {
	tid := roledom.NewID()
	editor := grantActor{id: "actor"}
	plain := customRole(tid, []string{"assets:read"}, false)
	already := customRole(tid, []string{"team:members:invite"}, false)
	priv := []string{"team:members:invite"}
	ctx := context.Background()
	held := []*roledom.UserRole{{UserID: roledom.NewID()}}

	withHolders := &RoleService{roleRepo: fakeHolderRepo{holders: held}, stepUp: stepUpGate{requester: "actor"}}
	noHolders := &RoleService{roleRepo: fakeHolderRepo{}, stepUp: stepUpGate{requester: "actor"}}

	if err := withHolders.guardDirectRolePrivilege(ctx, plain, priv, false, editor); !errors.Is(err, errStepUp) {
		t.Errorf("held role made privileged: want step-up, got %v", err)
	}
	if err := withHolders.guardDirectRolePrivilege(ctx, plain, []string{"assets:write"}, false, editor); err != nil {
		t.Errorf("still plain: want nil, got %v", err)
	}
	if err := withHolders.guardDirectRolePrivilege(ctx, already, priv, false, editor); err != nil {
		t.Errorf("already privileged: want nil, got %v", err)
	}
	if err := noHolders.guardDirectRolePrivilege(ctx, plain, priv, false, editor); err != nil {
		t.Errorf("no holders: want nil, got %v", err)
	}
	if err := withHolders.guardDirectRolePrivilege(ctx, plain, priv, false, grantActor{system: true}); err != nil {
		t.Errorf("system editor: want nil, got %v", err)
	}
}

// A delegated role manager may not change a role that carries a permission
// they do not hold: not strip it, not rename around it.
func TestMayEditChecksOldAndNewPermissions(t *testing.T) {
	tid := roledom.NewID()
	approver := customRole(tid, []string{"findings:approve", "assets:read"}, false)
	manager := grantActor{id: "m", perms: map[string]bool{"assets:read": true, "team:roles:write": true}}
	owner := grantActor{id: "o", owner: true}

	// Strip the approve permission the manager does not hold.
	if err := manager.mayEdit(approver, []string{"assets:read"}, false); !errors.Is(err, ErrGrantForbidden) {
		t.Errorf("stripping a permission the editor lacks: want ErrGrantForbidden, got %v", err)
	}
	// Add a permission the manager does not hold.
	plain := customRole(tid, []string{"assets:read"}, false)
	if err := manager.mayEdit(plain, []string{"assets:read", "findings:approve"}, false); !errors.Is(err, ErrGrantForbidden) {
		t.Errorf("adding a permission the editor lacks: want ErrGrantForbidden, got %v", err)
	}
	// Dropping full data access the editor lacks.
	full := customRole(tid, []string{"assets:read"}, true)
	if err := manager.mayEdit(full, []string{"assets:read"}, false); !errors.Is(err, ErrGrantForbidden) {
		t.Errorf("dropping full data the editor lacks: want ErrGrantForbidden, got %v", err)
	}
	// Within the ceiling, and the owner.
	if err := manager.mayEdit(plain, []string{"assets:read"}, false); err != nil {
		t.Errorf("within ceiling: %v", err)
	}
	if err := owner.mayEdit(approver, []string{"assets:read"}, false); err != nil {
		t.Errorf("owner: %v", err)
	}
}

// An edit that gives a directly held role an approval permission needs a
// recent sign-in, even when the role was already privileged.
func TestGuardDirectRoleApprovalGain(t *testing.T) {
	tid := roledom.NewID()
	editor := grantActor{id: "actor"}
	ctx := context.Background()
	held := []*roledom.UserRole{{UserID: roledom.NewID()}}
	svc := &RoleService{roleRepo: fakeHolderRepo{holders: held}, stepUp: stepUpGate{requester: "actor"}}

	plain := customRole(tid, []string{"assets:read"}, false)
	if err := svc.guardDirectRolePrivilege(ctx, plain, []string{"assets:read", "findings:approve"}, false, editor); !errors.Is(err, errStepUp) {
		t.Errorf("gaining approve: want step-up, got %v", err)
	}
	priv := customRole(tid, []string{"team:members:invite"}, false)
	if err := svc.guardDirectRolePrivilege(ctx, priv, []string{"team:members:invite", "scans:approve"}, false, editor); !errors.Is(err, errStepUp) {
		t.Errorf("privileged role gaining approve: want step-up, got %v", err)
	}
	if err := svc.guardDirectRolePrivilege(ctx, priv, []string{"team:members:invite", "team:roles:write"}, false, editor); !errors.Is(err, errStepUp) {
		t.Errorf("privileged role gaining another privileged permission: want step-up, got %v", err)
	}
	if err := svc.guardDirectRolePrivilege(ctx, priv, []string{"team:members:invite"}, false, editor); err != nil {
		t.Errorf("no gain: want nil, got %v", err)
	}
}

// Granting a role that carries an approval permission needs a recent sign-in.
func TestAuthorizePrivilegedGrantApprove(t *testing.T) {
	tid, uid := roledom.NewID(), roledom.NewID()
	approver := customRole(tid, []string{"findings:approve"}, false)
	svc := &RoleService{roleRepo: fakeHolderRepo{}, stepUp: stepUpGate{requester: "actor"}}
	if err := svc.authorizePrivilegedGrant(context.Background(), grantActor{id: "actor"}, tid, uid, []*roledom.Role{approver}); !errors.Is(err, errStepUp) {
		t.Errorf("approve role: want step-up, got %v", err)
	}
}
