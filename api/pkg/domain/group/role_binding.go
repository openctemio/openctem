package group

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A team (access group) may be bound to custom roles; every active member of
// the team holds them (decisions G1-G12, migration group_role_bindings). Roles stay
// the only source of permissions.

// MaxRoleBindingsPerGroup is a sanity limit on roles bound to one team.
const MaxRoleBindingsPerGroup = 10

// Errors for role bindings.
var (
	ErrRoleAlreadyBound   = fmt.Errorf("%w: the role is already bound to this team", shared.ErrConflict)
	ErrRoleBindingMissing = fmt.Errorf("%w: the role is not bound to this team", shared.ErrNotFound)
	ErrSystemRoleBinding  = fmt.Errorf("%w: only custom roles can be bound to a team", shared.ErrValidation)
	ErrTooManyBindings    = fmt.Errorf("%w: a team carries at most %d roles", shared.ErrValidation, MaxRoleBindingsPerGroup)
)

// RoleBinding is one role bound to one team.
type RoleBinding struct {
	TenantID  shared.ID
	GroupID   shared.ID
	GroupName string
	RoleID    shared.ID
	RoleName  string
	CreatedBy *shared.ID
	CreatedAt time.Time
}

// RoleBindingRepository persists team role bindings. Every method is scoped
// to the tenant.
type RoleBindingRepository interface {
	ListGroupRoles(ctx context.Context, tenantID, groupID shared.ID) ([]RoleBinding, error)
	ListRoleGroups(ctx context.Context, tenantID, roleID shared.ID) ([]RoleBinding, error)
	BindRole(ctx context.Context, tenantID, groupID, roleID shared.ID, createdBy *shared.ID) error
	UnbindRole(ctx context.Context, tenantID, groupID, roleID shared.ID) error
	// ListActiveMemberIDs returns the members whose membership has not
	// ended: the users holding the team's roles.
	ListActiveMemberIDs(ctx context.Context, tenantID, groupID shared.ID) ([]shared.ID, error)
	// HasExternalMembers reports whether any member of the team is an
	// external member of the organization (RFC-058).
	HasExternalMembers(ctx context.Context, tenantID, groupID shared.ID) (bool, error)
	// IsExternalMember reports whether the user is an external member of the
	// organization.
	IsExternalMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}
