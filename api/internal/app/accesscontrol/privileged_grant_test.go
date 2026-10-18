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
