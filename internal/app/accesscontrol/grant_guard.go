package accesscontrol

import (
	"context"
	"fmt"

	roledom "github.com/openctemio/api/pkg/domain/role"
	"github.com/openctemio/api/pkg/domain/shared"
)

// Role-grant ceiling.
//
// Every path that changes a user's role set (AssignRole, SetUserRoles and
// therefore GrantExactRoles, BulkAssignRoleToUsers, RemoveRole) and every path
// that changes what a custom role carries (CreateRole, UpdateRole) is checked
// against the acting user's own grants, read from the database:
//
//   - only an owner may grant the owner role;
//   - anyone else may grant only roles whose permissions they hold themselves
//     (and full data access only if they have it), so an administrator can
//     neither grant a role above their own nor raise their own privileges;
//   - removing a role (RemoveRole, or a role that SetUserRoles drops) needs the
//     same: nobody may take away a role they could not have given;
//   - only an owner may change the role set of a user who holds the owner
//     role, and the tenant's owner (membership role 'owner') always keeps it.
//
// The handler-level check (assertCanGrantPermissions) lets administrators
// through, so this is where the rule is enforced. An empty actor is a system
// path (invitation acceptance without an inviter, SCIM, SSO); it may not grant
// the owner role and is otherwise not limited.

// ErrGrantForbidden is returned when the actor may not make a role change.
var ErrGrantForbidden = fmt.Errorf("%w: role change not allowed", shared.ErrForbidden)

type grantActor struct {
	system   bool
	owner    bool
	fullData bool
	perms    map[string]bool
}

func (s *RoleService) loadGrantActor(ctx context.Context, tid roledom.ID, actorID string) (grantActor, error) {
	if actorID == "" {
		return grantActor{system: true}, nil
	}
	uid, err := roledom.ParseID(actorID)
	if err != nil {
		return grantActor{}, fmt.Errorf("%w: invalid actor id format", shared.ErrValidation)
	}
	roles, err := s.roleRepo.GetUserRoles(ctx, tid, uid)
	if err != nil {
		return grantActor{}, fmt.Errorf("load actor roles: %w", err)
	}
	a := grantActor{perms: map[string]bool{}}
	for _, r := range roles {
		if r.ID() == roledom.OwnerRoleID {
			a.owner = true
		}
		if r.HasFullDataAccess() {
			a.fullData = true
		}
	}
	perms, err := s.roleRepo.GetUserPermissions(ctx, tid, uid)
	if err != nil {
		return grantActor{}, fmt.Errorf("load actor permissions: %w", err)
	}
	for _, p := range perms {
		a.perms[p] = true
	}
	return a, nil
}

// mayGrant reports whether the actor may give someone role r.
func (a grantActor) mayGrant(r *roledom.Role) error {
	if r.ID() == roledom.OwnerRoleID && !a.owner {
		return fmt.Errorf("%w: only an owner can grant the owner role", ErrGrantForbidden)
	}
	if err := a.mayCarry(r.Permissions(), r.HasFullDataAccess()); err != nil {
		return fmt.Errorf("%w (role %q)", err, r.Name())
	}
	return nil
}

// mayRevoke reports whether the actor may take role r away from someone. The
// ceiling is the same as for granting: a delegated role manager cannot strip a
// role (system admin, member, or a custom role) whose permissions they do not
// hold, and only an owner can remove the owner role.
func (a grantActor) mayRevoke(r *roledom.Role) error {
	if err := a.mayGrant(r); err != nil {
		return fmt.Errorf("cannot remove it: %w", err)
	}
	return nil
}

// mayCarry reports whether the actor may hand out this permission set.
func (a grantActor) mayCarry(perms []string, fullData bool) error {
	if a.system || a.owner {
		return nil
	}
	for _, p := range perms {
		if !a.perms[p] {
			return fmt.Errorf("%w: it carries %s, which you do not hold", ErrGrantForbidden, p)
		}
	}
	if fullData && !a.fullData {
		return fmt.Errorf("%w: it carries full data access, which you do not have", ErrGrantForbidden)
	}
	return nil
}

// holdsOwnerRole reports whether the user currently holds the owner role.
func (s *RoleService) holdsOwnerRole(ctx context.Context, tid, uid roledom.ID) (bool, error) {
	roles, err := s.roleRepo.GetUserRoles(ctx, tid, uid)
	if err != nil {
		return false, fmt.Errorf("load user roles: %w", err)
	}
	for _, r := range roles {
		if r.ID() == roledom.OwnerRoleID {
			return true, nil
		}
	}
	return false, nil
}

// isMembershipOwner reports whether the user is the tenant's owner by
// membership. False when no membership reader is wired.
func (s *RoleService) isMembershipOwner(ctx context.Context, tid, uid roledom.ID) bool {
	if s.membershipReader == nil {
		return false
	}
	t, err := shared.IDFromString(tid.String())
	if err != nil {
		return false
	}
	u, err := shared.IDFromString(uid.String())
	if err != nil {
		return false
	}
	m, err := s.membershipReader.GetMembership(ctx, u, t)
	return err == nil && m != nil && m.IsOwner()
}

// authorizeRoleSetChange checks a change of user uid's role set to keepsOwner
// (whether the new set still contains the owner role) by actor a.
func (s *RoleService) authorizeRoleSetChange(ctx context.Context, a grantActor, tid, uid roledom.ID, keepsOwner bool) error {
	targetOwner, err := s.holdsOwnerRole(ctx, tid, uid)
	if err != nil {
		return err
	}
	if targetOwner && !a.owner && !a.system {
		return fmt.Errorf("%w: only an owner can change an owner's roles", ErrGrantForbidden)
	}
	if !keepsOwner && s.isMembershipOwner(ctx, tid, uid) {
		return fmt.Errorf("%w: the organization's owner keeps the owner role; transfer ownership instead", shared.ErrValidation)
	}
	return nil
}

// AuthorizeAccountAction checks that actorID may act on targetUserID's account
// in ways that amount to taking it over, such as issuing a set-password link
// for an account that has never signed in. The actor must be able to grant
// every role the target holds, and a target holding the owner or admin system
// role needs an owner. An empty actorID is a system path (the platform
// console) and is allowed.
func (s *RoleService) AuthorizeAccountAction(ctx context.Context, tenantID, actorID, targetUserID string) error {
	if actorID == "" {
		return nil
	}
	tid, err := roledom.ParseID(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	uid, err := roledom.ParseID(targetUserID)
	if err != nil {
		return fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
	}
	actor, err := s.loadGrantActor(ctx, tid, actorID)
	if err != nil {
		return err
	}
	roles, err := s.roleRepo.GetUserRoles(ctx, tid, uid)
	if err != nil {
		return fmt.Errorf("load target roles: %w", err)
	}
	for _, r := range roles {
		if (r.ID() == roledom.OwnerRoleID || r.ID() == roledom.AdminRoleID) && !actor.owner {
			return fmt.Errorf("%w: only an owner can act on an owner's or administrator's account", ErrGrantForbidden)
		}
		if err := actor.mayGrant(r); err != nil {
			return err
		}
	}
	return nil
}
