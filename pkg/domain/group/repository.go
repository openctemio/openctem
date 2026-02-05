package group

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Repository defines the interface for group persistence.
type Repository interface {
	// Group CRUD operations
	Create(ctx context.Context, g *Group) error
	GetByID(ctx context.Context, id shared.ID) (*Group, error)
	GetBySlug(ctx context.Context, tenantID shared.ID, slug string) (*Group, error)
	Update(ctx context.Context, g *Group) error
	Delete(ctx context.Context, id shared.ID) error

	// Group queries
	List(ctx context.Context, tenantID shared.ID, filter ListFilter) ([]*Group, error)
	Count(ctx context.Context, tenantID shared.ID, filter ListFilter) (int64, error)
	ExistsBySlug(ctx context.Context, tenantID shared.ID, slug string) (bool, error)
	ListByIDs(ctx context.Context, ids []shared.ID) ([]*Group, error)

	// External sync queries
	GetByExternalID(ctx context.Context, tenantID shared.ID, source ExternalSource, externalID string) (*Group, error)

	// Member operations
	AddMember(ctx context.Context, member *Member) error
	GetMember(ctx context.Context, groupID, userID shared.ID) (*Member, error)
	UpdateMember(ctx context.Context, member *Member) error
	RemoveMember(ctx context.Context, groupID, userID shared.ID) error
	ListMembers(ctx context.Context, groupID shared.ID) ([]*Member, error)
	ListMembersWithUserInfo(ctx context.Context, groupID shared.ID) ([]*MemberWithUser, error)
	CountMembers(ctx context.Context, groupID shared.ID) (int64, error)
	GetMemberStats(ctx context.Context, groupID shared.ID) (*MemberStats, error)
	IsMember(ctx context.Context, groupID, userID shared.ID) (bool, error)

	// User-centric queries
	ListGroupsByUser(ctx context.Context, tenantID, userID shared.ID) ([]*GroupWithRole, error)
	ListGroupIDsByUser(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error)

	// Permission set assignment
	AssignPermissionSet(ctx context.Context, groupID, permissionSetID shared.ID, assignedBy *shared.ID) error
	RemovePermissionSet(ctx context.Context, groupID, permissionSetID shared.ID) error
	ListPermissionSetIDs(ctx context.Context, groupID shared.ID) ([]shared.ID, error)
	ListGroupsWithPermissionSet(ctx context.Context, permissionSetID shared.ID) ([]*Group, error)
}

// ListFilter contains filter options for listing groups.
type ListFilter struct {
	// Type filters
	GroupTypes []GroupType

	// Search
	Search string // Search in name, slug, description

	// External sync filter
	ExternalSource *ExternalSource
	HasExternalID  *bool

	// Status filter
	IsActive *bool

	// Pagination
	Limit  int
	Offset int

	// Sorting
	OrderBy   string // "name", "created_at", "updated_at"
	OrderDesc bool
}

// DefaultListFilter returns a default filter.
func DefaultListFilter() ListFilter {
	return ListFilter{
		Limit:   50,
		Offset:  0,
		OrderBy: "name",
	}
}

// GroupWithRole represents a group with the user's role in it.
type GroupWithRole struct {
	Group *Group
	Role  MemberRole
}

// GroupWithMembers represents a group with its members.
type GroupWithMembers struct {
	Group   *Group
	Members []*MemberWithUser
}

// GroupWithPermissionSets represents a group with its assigned permission sets.
type GroupWithPermissionSets struct {
	Group            *Group
	PermissionSetIDs []shared.ID
}
