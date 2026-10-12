package accesscontrol

// Team (access group) to role binding (owner decisions G1-G12).
//
// A custom role bound to a team is held by every active member of the team
// (v_user_role_grants). Roles stay the only source of permissions. Because
// whoever manages a team's membership then hands out its roles:
//
//   - binding or unbinding a role is a grant: team:roles:assign and
//     team:groups:write (route), and the actor must be able to grant the
//     role themselves (grant ceiling) and, without full data access, hold
//     every asset of the team in their own scope (D13);
//   - adding or removing a member of a team that carries roles is a grant of
//     each of them under the same ceiling; nobody but the owner adds
//     themselves to such a team;
//   - a privileged role (full data access, or a permission in
//     permission.PrivilegedPermissions) is bound, unbound, and its team's
//     membership changed, by the owner only, with a recent sign-in;
//   - only custom roles bind (the schema refuses built-in roles), so team
//     roles, the administrator bypass and the owner invariants are untouched;
//   - an external member never holds a full-data role through a team (RFC-058);
//   - every change invalidates the affected members' cached permissions.

import (
	"context"
	"errors"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	groupdom "github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrPrivilegedTeamOwnerOnly refuses a non-owner change to a team that
// carries a privileged role.
var ErrPrivilegedTeamOwnerOnly = fmt.Errorf("%w: only the owner changes a team that carries a privileged role", ErrGrantForbidden)

// ErrSelfJoinRoleTeam refuses adding oneself to a team that carries roles.
var ErrSelfJoinRoleTeam = fmt.Errorf("%w: you cannot add yourself to a team that carries roles", ErrGrantForbidden)

// WithRoleBindings enables team role bindings: the binding store and the role
// service whose grant ceiling, step-up gate and cache invalidation they use.
func WithRoleBindings(bindings groupdom.RoleBindingRepository, roles *RoleService) GroupServiceOption {
	return func(s *GroupService) {
		s.bindings = bindings
		s.roles = roles
		if roles != nil {
			roles.bindings = bindings
		}
	}
}

// SetRoleBindings enables team role bindings after construction (the role
// service is built after the group service at the composition root).
func (s *GroupService) SetRoleBindings(bindings groupdom.RoleBindingRepository, roles *RoleService) {
	WithRoleBindings(bindings, roles)(s)
}

// GroupRoleView is a role bound to a team, as the API shows it.
type GroupRoleView struct {
	Binding    groupdom.RoleBinding
	Privileged bool
}

func (s *GroupService) requireBindings() error {
	if s.bindings == nil || s.roles == nil {
		return fmt.Errorf("%w: team role bindings are not available", shared.ErrValidation)
	}
	return nil
}

// boundRoles loads the roles bound to team g.
func (s *GroupService) boundRoles(ctx context.Context, g *groupdom.Group) ([]*roledom.Role, error) {
	if s.bindings == nil || s.roles == nil {
		return nil, nil
	}
	bs, err := s.bindings.ListGroupRoles(ctx, g.TenantID(), g.ID())
	if err != nil {
		return nil, err
	}
	out := make([]*roledom.Role, 0, len(bs))
	for _, b := range bs {
		r, err := s.roles.roleRepo.GetByID(ctx, asRoleID(g.TenantID()), asRoleID(b.RoleID))
		if err != nil {
			return nil, fmt.Errorf("load bound role: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

func isPrivileged(r *roledom.Role) bool {
	return permission.IsPrivilegedRole(r.Permissions(), r.HasFullDataAccess())
}

// requireOwnerStepUp is the owner-only + recent sign-in rule for privileged
// team changes.
func (s *GroupService) requireOwnerStepUp(ctx context.Context, a grantActor) error {
	if a.system {
		return nil
	}
	if !a.owner {
		return ErrPrivilegedTeamOwnerOnly
	}
	if s.roles != nil && s.roles.stepUp != nil {
		return s.roles.stepUp.RequireRecentAuth(ctx, a.id)
	}
	return nil
}

// checkMembershipGrant applies the binding rules to a change of userID's
// membership of team g by actorID (adding true: add or extend; false:
// remove). It returns whether the team carries roles, so the caller knows to
// invalidate the member's permissions afterwards.
func (s *GroupService) checkMembershipGrant(ctx context.Context, g *groupdom.Group, userID shared.ID, actorID string, adding bool) (bool, error) {
	roles, err := s.boundRoles(ctx, g)
	if err != nil || len(roles) == 0 {
		return false, err
	}
	a, err := s.roles.loadGrantActor(ctx, asRoleID(g.TenantID()), actorID)
	if err != nil {
		return true, err
	}
	if adding && !a.system && !a.owner && a.id == userID.String() {
		return true, ErrSelfJoinRoleTeam
	}
	privileged, fullData := false, false
	for _, r := range roles {
		check := a.mayGrant
		if !adding {
			check = a.mayRevoke
		}
		if err := check(r); err != nil {
			return true, err
		}
		privileged = privileged || isPrivileged(r)
		fullData = fullData || r.HasFullDataAccess()
	}
	if privileged {
		if err := s.requireOwnerStepUp(ctx, a); err != nil {
			return true, err
		}
	}
	if adding && fullData {
		external, err := s.bindings.IsExternalMember(ctx, g.TenantID(), userID)
		if err != nil {
			return true, err
		}
		if external {
			return true, ErrExternalRoleCeiling
		}
	}
	return true, nil
}

// invalidateMembers drops the cached permissions of the given users.
func (s *GroupService) invalidateMembers(ctx context.Context, tenantID shared.ID, users []shared.ID) {
	if s.roles == nil || len(users) == 0 {
		return
	}
	ids := make([]string, len(users))
	for i, u := range users {
		ids[i] = u.String()
	}
	s.roles.invalidateUsersPermissions(ctx, tenantID.String(), ids)
}

// ListGroupRoles returns the roles bound to a team.
func (s *GroupService) ListGroupRoles(ctx context.Context, tenantID, groupID string) ([]GroupRoleView, error) {
	if err := s.requireBindings(); err != nil {
		return nil, err
	}
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}
	g, err := s.groupForTenant(ctx, gid, tenantID)
	if err != nil {
		return nil, err
	}
	bs, err := s.bindings.ListGroupRoles(ctx, g.TenantID(), g.ID())
	if err != nil {
		return nil, err
	}
	out := make([]GroupRoleView, 0, len(bs))
	for _, b := range bs {
		r, err := s.roles.roleRepo.GetByID(ctx, asRoleID(g.TenantID()), asRoleID(b.RoleID))
		if err != nil {
			return nil, fmt.Errorf("load bound role: %w", err)
		}
		out = append(out, GroupRoleView{Binding: b, Privileged: isPrivileged(r)})
	}
	return out, nil
}

// ListRoleGroups returns the teams a role of the tenant is bound to.
func (s *GroupService) ListRoleGroups(ctx context.Context, tenantID, roleID string) ([]groupdom.RoleBinding, error) {
	if err := s.requireBindings(); err != nil {
		return nil, err
	}
	rid, err := roledom.ParseID(roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
	}
	r, err := s.roles.roleForTenant(ctx, tenantID, rid)
	if err != nil {
		return nil, roleNotFound(err)
	}
	if r.TenantID() == nil {
		return []groupdom.RoleBinding{}, nil // built-in roles are never bound
	}
	return s.bindings.ListRoleGroups(ctx, asSharedID(*r.TenantID()), asSharedID(rid))
}

// loadBindingTarget loads the team and the custom role of a binding change
// and the acting user, with the checks shared by bind and unbind.
func (s *GroupService) loadBindingTarget(ctx context.Context, groupID, roleID string, actx auditapp.AuditContext) (*groupdom.Group, *roledom.Role, grantActor, error) {
	if err := s.requireBindings(); err != nil {
		return nil, nil, grantActor{}, err
	}
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, nil, grantActor{}, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}
	rid, err := roledom.ParseID(roleID)
	if err != nil {
		return nil, nil, grantActor{}, fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
	}
	g, err := s.groupForTenant(ctx, gid, actx.TenantID)
	if err != nil {
		return nil, nil, grantActor{}, err
	}
	r, err := s.roles.roleForTenant(ctx, g.TenantID().String(), rid)
	if err != nil {
		return nil, nil, grantActor{}, roleNotFound(err)
	}
	if r.IsSystem() || r.TenantID() == nil {
		return nil, nil, grantActor{}, groupdom.ErrSystemRoleBinding
	}
	a, err := s.roles.loadGrantActor(ctx, asRoleID(g.TenantID()), actx.ActorID)
	if err != nil {
		return nil, nil, grantActor{}, err
	}
	// D13: without full data access the actor needs every asset of the team
	// in their own scope.
	if err := s.requireWholeGroupInScope(ctx, g); err != nil {
		return nil, nil, grantActor{}, err
	}
	if isPrivileged(r) {
		if err := s.requireOwnerStepUp(ctx, a); err != nil {
			return nil, nil, grantActor{}, err
		}
	}
	return g, r, a, nil
}

// BindRole binds a custom role to a team: every active member holds it.
func (s *GroupService) BindRole(ctx context.Context, groupID, roleID string, actx auditapp.AuditContext) error {
	g, r, a, err := s.loadBindingTarget(ctx, groupID, roleID, actx)
	if err != nil {
		return err
	}
	if err := a.mayGrant(r); err != nil {
		return err
	}
	existing, err := s.bindings.ListGroupRoles(ctx, g.TenantID(), g.ID())
	if err != nil {
		return err
	}
	if len(existing) >= groupdom.MaxRoleBindingsPerGroup {
		return groupdom.ErrTooManyBindings
	}
	if r.HasFullDataAccess() {
		external, err := s.bindings.HasExternalMembers(ctx, g.TenantID(), g.ID())
		if err != nil {
			return err
		}
		if external {
			return ErrExternalRoleCeiling
		}
	}
	var by *shared.ID
	if id, err := shared.IDFromString(actx.ActorID); err == nil {
		by = &id
	}
	if err := s.bindings.BindRole(ctx, g.TenantID(), g.ID(), asSharedID(r.ID()), by); err != nil {
		return err
	}
	members, err := s.bindings.ListActiveMemberIDs(ctx, g.TenantID(), g.ID())
	if err != nil {
		s.logger.Error("failed to list team members for invalidation", "error", err)
	}
	s.invalidateMembers(ctx, g.TenantID(), members)
	s.auditBinding(ctx, actx, g, r, true, len(members))
	return nil
}

// UnbindRole removes a role from a team.
func (s *GroupService) UnbindRole(ctx context.Context, groupID, roleID string, actx auditapp.AuditContext) error {
	g, r, a, err := s.loadBindingTarget(ctx, groupID, roleID, actx)
	if err != nil {
		return err
	}
	if err := a.mayRevoke(r); err != nil {
		return err
	}
	// Members to invalidate are read before the binding goes.
	members, err := s.bindings.ListActiveMemberIDs(ctx, g.TenantID(), g.ID())
	if err != nil {
		return err
	}
	if err := s.bindings.UnbindRole(ctx, g.TenantID(), g.ID(), asSharedID(r.ID())); err != nil {
		return err
	}
	s.invalidateMembers(ctx, g.TenantID(), members)
	s.auditBinding(ctx, actx, g, r, false, len(members))
	return nil
}

func (s *GroupService) auditBinding(ctx context.Context, actx auditapp.AuditContext, g *groupdom.Group, r *roledom.Role, bound bool, members int) {
	action, msg := audit.ActionRoleAssigned, fmt.Sprintf("Role %q bound to team %q", r.Name(), g.Name())
	if !bound {
		action, msg = audit.ActionRoleUnassigned, fmt.Sprintf("Role %q removed from team %q", r.Name(), g.Name())
	}
	severity := audit.SeverityHigh
	if isPrivileged(r) {
		severity = audit.SeverityCritical
	}
	actx.TenantID = g.TenantID().String()
	event := auditapp.NewSuccessEvent(action, audit.ResourceTypeGroup, g.ID().String()).
		WithResourceName(g.Name()).
		WithMessage(msg).
		WithMetadata("binding", "team").
		WithMetadata("role_id", r.ID().String()).
		WithMetadata("role_name", r.Name()).
		WithMetadata("privileged", isPrivileged(r)).
		WithMetadata("member_count", members).
		WithSeverity(severity)
	s.logAudit(ctx, actx, event)
}

// asRoleID and asSharedID convert between the two id types (both UUIDs).
func asRoleID(id shared.ID) roledom.ID {
	r, _ := roledom.ParseID(id.String())
	return r
}

func asSharedID(id roledom.ID) shared.ID {
	r, _ := shared.IDFromString(id.String())
	return r
}

// roleNotFound maps the role store's not-found to a 404-class error.
func roleNotFound(err error) error {
	if errors.Is(err, roledom.ErrRoleNotFound) {
		return fmt.Errorf("%w: role not found", shared.ErrNotFound)
	}
	return err
}
