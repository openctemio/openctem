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

// UserTeamGrant is one role a person holds through one active team they are a
// member of ("access from team X"). MemberUntil is the end date of their
// membership, nil when it has none.
type UserTeamGrant struct {
	GroupID     shared.ID
	GroupName   string
	RoleID      shared.ID
	RoleName    string
	Managed     bool
	TemplateID  string
	MemberUntil *time.Time
}

// OutsideMember is a team member who may not hold full data access through
// the team: an external member of the organization or a service account.
type OutsideMember struct {
	UserID  shared.ID
	Name    string
	Service bool
}

// MaxOutsideMembersListed caps the outside members a team view or a refusal
// names.
const MaxOutsideMembersListed = 20

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
	// ListOutsideMembers returns up to limit members of the team who are
	// outside the organization (external members, RFC-058) or service
	// accounts: neither may hold full data access through a team.
	ListOutsideMembers(ctx context.Context, tenantID, groupID shared.ID, limit int) ([]OutsideMember, error)
	// IsExternalMember reports whether the user is an external member of the
	// organization.
	IsExternalMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	// ListUserTeamGrants returns the roles the user holds through the active
	// teams they belong to, with the team each comes from.
	ListUserTeamGrants(ctx context.Context, tenantID, userID shared.ID) ([]UserTeamGrant, error)
}
