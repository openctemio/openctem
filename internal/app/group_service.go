package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/permissionset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// GroupService handles group-related business operations.
type GroupService struct {
	repo              group.Repository
	permissionSetRepo permissionset.Repository
	accessControlRepo accesscontrol.Repository
	auditService      *AuditService
	logger            *logger.Logger
}

// NewGroupService creates a new GroupService.
func NewGroupService(
	repo group.Repository,
	log *logger.Logger,
	opts ...GroupServiceOption,
) *GroupService {
	s := &GroupService{
		repo:   repo,
		logger: log.With("service", "group"),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// GroupServiceOption is a functional option for GroupService.
type GroupServiceOption func(*GroupService)

// WithGroupAuditService sets the audit service for GroupService.
func WithGroupAuditService(auditService *AuditService) GroupServiceOption {
	return func(s *GroupService) {
		s.auditService = auditService
	}
}

// WithPermissionSetRepository sets the permission set repository.
func WithPermissionSetRepository(repo permissionset.Repository) GroupServiceOption {
	return func(s *GroupService) {
		s.permissionSetRepo = repo
	}
}

// WithAccessControlRepository sets the access control repository.
func WithAccessControlRepository(repo accesscontrol.Repository) GroupServiceOption {
	return func(s *GroupService) {
		s.accessControlRepo = repo
	}
}

// logAudit logs an audit event if audit service is configured.
func (s *GroupService) logAudit(ctx context.Context, actx AuditContext, event AuditEvent) {
	if s.auditService == nil {
		return
	}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log audit event", "error", err, "action", event.Action)
	}
}

// =============================================================================
// GROUP CRUD OPERATIONS
// =============================================================================

// CreateGroupInput represents the input for creating a group.
type CreateGroupInput struct {
	TenantID    string               `json:"-"`
	Name        string               `json:"name" validate:"required,min=2,max=100"`
	Slug        string               `json:"slug" validate:"required,min=2,max=100,slug"`
	Description string               `json:"description" validate:"max=500"`
	GroupType   string               `json:"group_type" validate:"required,oneof=security_team team department project external"`
	Settings    *group.GroupSettings `json:"settings,omitempty"`
}

// CreateGroup creates a new group.
func (s *GroupService) CreateGroup(ctx context.Context, input CreateGroupInput, creatorUserID shared.ID, actx AuditContext) (*group.Group, error) {
	s.logger.Info("creating group", "name", input.Name, "slug", input.Slug, "type", input.GroupType)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	// Validate group type
	groupType := group.GroupType(input.GroupType)
	if !groupType.IsValid() {
		return nil, fmt.Errorf("%w: invalid group type", shared.ErrValidation)
	}

	// Check if slug already exists in tenant
	exists, err := s.repo.ExistsBySlug(ctx, tenantID, input.Slug)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: slug '%s' is already taken in this tenant", shared.ErrValidation, input.Slug)
	}

	// Create group
	g, err := group.NewGroup(tenantID, input.Name, input.Slug, groupType)
	if err != nil {
		return nil, err
	}

	if input.Description != "" {
		g.UpdateDescription(input.Description)
	}

	if input.Settings != nil {
		g.UpdateSettings(*input.Settings)
	}

	// Create in database
	if err := s.repo.Create(ctx, g); err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	// Add creator as owner of the group
	_, err = s.AddMember(ctx, AddGroupMemberInput{
		GroupID: g.ID().String(),
		UserID:  creatorUserID,
		Role:    string(group.MemberRoleOwner),
	}, actx)
	if err != nil {
		// Rollback group creation
		_ = s.repo.Delete(ctx, g.ID())
		return nil, fmt.Errorf("failed to add creator as group owner: %w", err)
	}

	s.logger.Info("group created", "id", g.ID().String(), "name", g.Name())

	// Log audit event
	actx.TenantID = input.TenantID
	event := NewSuccessEvent(audit.ActionGroupCreated, audit.ResourceTypeGroup, g.ID().String()).
		WithResourceName(g.Name()).
		WithMessage(fmt.Sprintf("Group '%s' created", g.Name())).
		WithMetadata("group_type", input.GroupType)
	s.logAudit(ctx, actx, event)

	return g, nil
}

// GetGroup retrieves a group by ID.
func (s *GroupService) GetGroup(ctx context.Context, groupID string) (*group.Group, error) {
	id, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, id)
}

// GetGroupBySlug retrieves a group by tenant and slug.
func (s *GroupService) GetGroupBySlug(ctx context.Context, tenantID, slug string) (*group.Group, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.repo.GetBySlug(ctx, tid, slug)
}

// UpdateGroupInput represents the input for updating a group.
type UpdateGroupInput struct {
	Name        *string              `json:"name" validate:"omitempty,min=2,max=100"`
	Slug        *string              `json:"slug" validate:"omitempty,min=2,max=100,slug"`
	Description *string              `json:"description" validate:"omitempty,max=500"`
	Settings    *group.GroupSettings `json:"settings,omitempty"`
	IsActive    *bool                `json:"is_active,omitempty"`
}

// UpdateGroup updates a group.
func (s *GroupService) UpdateGroup(ctx context.Context, groupID string, input UpdateGroupInput, actx AuditContext) (*group.Group, error) {
	id, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	g, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		if err := g.UpdateName(*input.Name); err != nil {
			return nil, err
		}
	}

	if input.Slug != nil && *input.Slug != g.Slug() {
		// Check if new slug already exists
		exists, err := s.repo.ExistsBySlug(ctx, g.TenantID(), *input.Slug)
		if err != nil {
			return nil, fmt.Errorf("failed to check slug existence: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: slug '%s' is already taken", shared.ErrValidation, *input.Slug)
		}
		if err := g.UpdateSlug(*input.Slug); err != nil {
			return nil, err
		}
	}

	if input.Description != nil {
		g.UpdateDescription(*input.Description)
	}

	if input.Settings != nil {
		g.UpdateSettings(*input.Settings)
	}

	if input.IsActive != nil {
		if *input.IsActive {
			g.Activate()
		} else {
			g.Deactivate()
		}
	}

	if err := s.repo.Update(ctx, g); err != nil {
		return nil, fmt.Errorf("failed to update group: %w", err)
	}

	s.logger.Info("group updated", "id", groupID)

	// Log audit event
	actx.TenantID = g.TenantID().String()
	event := NewSuccessEvent(audit.ActionGroupUpdated, audit.ResourceTypeGroup, groupID).
		WithResourceName(g.Name()).
		WithMessage(fmt.Sprintf("Group '%s' updated", g.Name()))
	s.logAudit(ctx, actx, event)

	return g, nil
}

// DeleteGroup deletes a group.
func (s *GroupService) DeleteGroup(ctx context.Context, groupID string, actx AuditContext) error {
	id, err := shared.IDFromString(groupID)
	if err != nil {
		return fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	g, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	tenantID := g.TenantID().String()
	groupName := g.Name()

	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}

	s.logger.Info("group deleted", "id", groupID)

	// Log audit event
	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionGroupDeleted, audit.ResourceTypeGroup, groupID).
		WithResourceName(groupName).
		WithMessage(fmt.Sprintf("Group '%s' deleted", groupName)).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)

	return nil
}

// ListGroupsInput represents the input for listing groups.
type ListGroupsInput struct {
	TenantID  string
	GroupType *string
	IsActive  *bool
	Search    string
	Limit     int
	Offset    int
}

// ListGroupsOutput represents the output for listing groups.
type ListGroupsOutput struct {
	Groups     []*group.Group
	TotalCount int64
}

// ListGroups lists groups with filtering.
func (s *GroupService) ListGroups(ctx context.Context, input ListGroupsInput) (*ListGroupsOutput, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	filter := group.ListFilter{
		Search: input.Search,
		Limit:  input.Limit,
		Offset: input.Offset,
	}

	if input.GroupType != nil {
		gt := group.GroupType(*input.GroupType)
		filter.GroupTypes = []group.GroupType{gt}
	}

	if input.IsActive != nil {
		filter.IsActive = input.IsActive
	}

	groups, err := s.repo.List(ctx, tenantID, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	count, err := s.repo.Count(ctx, tenantID, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count groups: %w", err)
	}

	return &ListGroupsOutput{
		Groups:     groups,
		TotalCount: count,
	}, nil
}

// =============================================================================
// MEMBER OPERATIONS
// =============================================================================

// AddGroupMemberInput represents the input for adding a member to a group.
type AddGroupMemberInput struct {
	GroupID string    `json:"-"`
	UserID  shared.ID `json:"user_id" validate:"required"`
	Role    string    `json:"role" validate:"required,oneof=owner lead member"`
}

// AddMember adds a user to a group.
func (s *GroupService) AddMember(ctx context.Context, input AddGroupMemberInput, actx AuditContext) (*group.Member, error) {
	groupID, err := shared.IDFromString(input.GroupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	role := group.MemberRole(input.Role)
	if !role.IsValid() {
		return nil, fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}

	// Check if user is already a member
	_, err = s.repo.GetMember(ctx, groupID, input.UserID)
	if err == nil {
		return nil, fmt.Errorf("%w: user is already a member of this group", shared.ErrValidation)
	}
	if !group.IsMemberNotFound(err) {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}

	member, err := group.NewMember(groupID, input.UserID, role, nil)
	if err != nil {
		return nil, err
	}

	if err := s.repo.AddMember(ctx, member); err != nil {
		return nil, fmt.Errorf("failed to add member: %w", err)
	}

	s.logger.Info("member added to group", "group_id", input.GroupID, "user_id", input.UserID.String(), "role", role)

	// Log audit event
	g, _ := s.repo.GetByID(ctx, groupID)
	if g != nil {
		actx.TenantID = g.TenantID().String()
	}
	event := NewSuccessEvent(audit.ActionMemberAdded, audit.ResourceTypeGroup, input.GroupID).
		WithMessage(fmt.Sprintf("Member added to group with role %s", role)).
		WithMetadata("user_id", input.UserID.String()).
		WithMetadata("role", input.Role)
	s.logAudit(ctx, actx, event)

	return member, nil
}

// UpdateMemberRoleInput represents the input for updating a member's role.
type UpdateGroupMemberRoleInput struct {
	GroupID string    `json:"-"`
	UserID  shared.ID `json:"-"`
	Role    string    `json:"role" validate:"required,oneof=owner lead member"`
}

// UpdateMemberRole updates a member's role in a group.
func (s *GroupService) UpdateMemberRole(ctx context.Context, input UpdateGroupMemberRoleInput, actx AuditContext) (*group.Member, error) {
	groupID, err := shared.IDFromString(input.GroupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	role := group.MemberRole(input.Role)
	if !role.IsValid() {
		return nil, fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}

	member, err := s.repo.GetMember(ctx, groupID, input.UserID)
	if err != nil {
		return nil, err
	}

	oldRole := member.Role()
	if err := member.UpdateRole(role); err != nil {
		return nil, err
	}

	if err := s.repo.UpdateMember(ctx, member); err != nil {
		return nil, fmt.Errorf("failed to update member role: %w", err)
	}

	s.logger.Info("member role updated", "group_id", input.GroupID, "user_id", input.UserID.String(), "new_role", role)

	// Log audit event
	g, _ := s.repo.GetByID(ctx, groupID)
	if g != nil {
		actx.TenantID = g.TenantID().String()
	}
	changes := audit.NewChanges().Set("role", oldRole.String(), input.Role)
	event := NewSuccessEvent(audit.ActionMemberRoleChanged, audit.ResourceTypeGroup, input.GroupID).
		WithChanges(changes).
		WithMessage(fmt.Sprintf("Member role changed from %s to %s", oldRole, role)).
		WithMetadata("user_id", input.UserID.String())
	s.logAudit(ctx, actx, event)

	return member, nil
}

// RemoveMember removes a member from a group.
func (s *GroupService) RemoveMember(ctx context.Context, groupID string, userID shared.ID, actx AuditContext) error {
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	// Get group for audit context
	g, err := s.repo.GetByID(ctx, gid)
	if err != nil {
		return err
	}

	// Check if this would remove the last owner
	member, err := s.repo.GetMember(ctx, gid, userID)
	if err != nil {
		return err
	}

	if member.Role() == group.MemberRoleOwner {
		// Count owners
		members, err := s.repo.ListMembers(ctx, gid)
		if err != nil {
			return fmt.Errorf("failed to list members: %w", err)
		}
		ownerCount := 0
		for _, m := range members {
			if m.Role() == group.MemberRoleOwner {
				ownerCount++
			}
		}
		if ownerCount <= 1 {
			return fmt.Errorf("%w: cannot remove the last owner", shared.ErrValidation)
		}
	}

	if err := s.repo.RemoveMember(ctx, gid, userID); err != nil {
		return err
	}

	s.logger.Info("member removed from group", "group_id", groupID, "user_id", userID.String())

	// Log audit event
	actx.TenantID = g.TenantID().String()
	event := NewSuccessEvent(audit.ActionMemberRemoved, audit.ResourceTypeGroup, groupID).
		WithMessage("Member removed from group").
		WithMetadata("user_id", userID.String()).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)

	return nil
}

// ListGroupMembers lists all members of a group.
func (s *GroupService) ListGroupMembers(ctx context.Context, groupID string) ([]*group.Member, error) {
	id, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	return s.repo.ListMembers(ctx, id)
}

// ListGroupMembersWithUserInfo lists members with user details.
func (s *GroupService) ListGroupMembersWithUserInfo(ctx context.Context, groupID string) ([]*group.MemberWithUser, error) {
	id, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	return s.repo.ListMembersWithUserInfo(ctx, id)
}

// ListUserGroups lists all groups a user belongs to.
func (s *GroupService) ListUserGroups(ctx context.Context, tenantID string, userID shared.ID) ([]*group.GroupWithRole, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.repo.ListGroupsByUser(ctx, tid, userID)
}

// =============================================================================
// PERMISSION SET ASSIGNMENT OPERATIONS
// =============================================================================

// AssignPermissionSetInput represents the input for assigning a permission set to a group.
type AssignPermissionSetInput struct {
	GroupID         string `json:"-"`
	PermissionSetID string `json:"permission_set_id" validate:"required"`
}

// AssignPermissionSet assigns a permission set to a group.
func (s *GroupService) AssignPermissionSet(ctx context.Context, input AssignPermissionSetInput, assignedBy shared.ID, actx AuditContext) error {
	groupID, err := shared.IDFromString(input.GroupID)
	if err != nil {
		return fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	permissionSetID, err := shared.IDFromString(input.PermissionSetID)
	if err != nil {
		return fmt.Errorf("%w: invalid permission set id format", shared.ErrValidation)
	}

	// Verify group exists
	g, err := s.repo.GetByID(ctx, groupID)
	if err != nil {
		return err
	}

	// Verify permission set exists (if repo is configured)
	if s.permissionSetRepo != nil {
		_, err = s.permissionSetRepo.GetByID(ctx, permissionSetID)
		if err != nil {
			return err
		}
	}

	if err := s.repo.AssignPermissionSet(ctx, groupID, permissionSetID, &assignedBy); err != nil {
		return fmt.Errorf("failed to assign permission set: %w", err)
	}

	s.logger.Info("permission set assigned", "group_id", input.GroupID, "permission_set_id", input.PermissionSetID)

	// Refresh materialized view if access control repo is configured
	if s.accessControlRepo != nil {
		if err := s.accessControlRepo.RefreshUserAccessibleAssets(ctx); err != nil {
			s.logger.Error("failed to refresh user accessible assets", "error", err)
		}
	}

	// Log audit event
	actx.TenantID = g.TenantID().String()
	event := NewSuccessEvent(audit.ActionPermissionSetAssigned, audit.ResourceTypeGroup, input.GroupID).
		WithMessage("Permission set assigned to group").
		WithMetadata("permission_set_id", input.PermissionSetID)
	s.logAudit(ctx, actx, event)

	return nil
}

// UnassignPermissionSet removes a permission set from a group.
func (s *GroupService) UnassignPermissionSet(ctx context.Context, groupID, permissionSetID string, actx AuditContext) error {
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	psid, err := shared.IDFromString(permissionSetID)
	if err != nil {
		return fmt.Errorf("%w: invalid permission set id format", shared.ErrValidation)
	}

	// Get group for audit context
	g, err := s.repo.GetByID(ctx, gid)
	if err != nil {
		return err
	}

	if err := s.repo.RemovePermissionSet(ctx, gid, psid); err != nil {
		return fmt.Errorf("failed to unassign permission set: %w", err)
	}

	s.logger.Info("permission set unassigned", "group_id", groupID, "permission_set_id", permissionSetID)

	// Refresh materialized view if access control repo is configured
	if s.accessControlRepo != nil {
		if err := s.accessControlRepo.RefreshUserAccessibleAssets(ctx); err != nil {
			s.logger.Error("failed to refresh user accessible assets", "error", err)
		}
	}

	// Log audit event
	actx.TenantID = g.TenantID().String()
	event := NewSuccessEvent(audit.ActionPermissionSetUnassigned, audit.ResourceTypeGroup, groupID).
		WithMessage("Permission set removed from group").
		WithMetadata("permission_set_id", permissionSetID)
	s.logAudit(ctx, actx, event)

	return nil
}

// ListGroupPermissionSets lists permission sets assigned to a group.
func (s *GroupService) ListGroupPermissionSets(ctx context.Context, groupID string) ([]shared.ID, error) {
	id, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	return s.repo.ListPermissionSetIDs(ctx, id)
}

// ListGroupPermissionSetsWithDetails lists permission sets assigned to a group with full details.
func (s *GroupService) ListGroupPermissionSetsWithDetails(ctx context.Context, groupID string) ([]*permissionset.PermissionSetWithItems, error) {
	ids, err := s.ListGroupPermissionSets(ctx, groupID)
	if err != nil {
		return nil, err
	}

	result := make([]*permissionset.PermissionSetWithItems, 0, len(ids))
	for _, id := range ids {
		ps, err := s.permissionSetRepo.GetWithItems(ctx, id)
		if err != nil {
			// If a permission set is not found or other error, we log but continue
			// or we could fail. For now, let's skip/continue to avoid breaking the whole list
			// if one reference is bad.
			continue
		}
		result = append(result, ps)
	}

	return result, nil
}

// =============================================================================
// ASSET OWNERSHIP OPERATIONS
// =============================================================================

// AssignAssetInput represents the input for assigning an asset to a group.
type AssignAssetInput struct {
	GroupID       string `json:"-"`
	AssetID       string `json:"asset_id" validate:"required,uuid"`
	OwnershipType string `json:"ownership_type" validate:"required,oneof=primary secondary stakeholder informed"`
}

// AssignAsset assigns an asset to a group with the specified ownership type.
func (s *GroupService) AssignAsset(ctx context.Context, input AssignAssetInput, assignedBy shared.ID, actx AuditContext) error {
	if s.accessControlRepo == nil {
		return fmt.Errorf("access control repository not configured")
	}

	groupID, err := shared.IDFromString(input.GroupID)
	if err != nil {
		return fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	assetID, err := shared.IDFromString(input.AssetID)
	if err != nil {
		return fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
	}

	ownershipType := accesscontrol.OwnershipType(input.OwnershipType)
	if !ownershipType.IsValid() {
		return fmt.Errorf("%w: invalid ownership type", shared.ErrValidation)
	}

	// Verify group exists
	g, err := s.repo.GetByID(ctx, groupID)
	if err != nil {
		return err
	}

	// Create the asset owner relationship
	ao, err := accesscontrol.NewAssetOwner(assetID, groupID, ownershipType, &assignedBy)
	if err != nil {
		return err
	}

	if err := s.accessControlRepo.CreateAssetOwner(ctx, ao); err != nil {
		return fmt.Errorf("failed to assign asset: %w", err)
	}

	s.logger.Info("asset assigned to group", "group_id", input.GroupID, "asset_id", input.AssetID, "ownership_type", input.OwnershipType)

	// Refresh materialized view
	if err := s.accessControlRepo.RefreshUserAccessibleAssets(ctx); err != nil {
		s.logger.Error("failed to refresh user accessible assets", "error", err)
	}

	// Log audit event
	actx.TenantID = g.TenantID().String()
	event := NewSuccessEvent(audit.ActionAssetAssigned, audit.ResourceTypeGroup, input.GroupID).
		WithMessage("Asset assigned to group").
		WithMetadata("asset_id", input.AssetID).
		WithMetadata("ownership_type", input.OwnershipType)
	s.logAudit(ctx, actx, event)

	return nil
}

// UnassignAssetInput represents the input for removing an asset from a group.
type UnassignAssetInput struct {
	GroupID string `json:"-"`
	AssetID string `json:"-"`
}

// UnassignAsset removes an asset from a group.
func (s *GroupService) UnassignAsset(ctx context.Context, input UnassignAssetInput, actx AuditContext) error {
	if s.accessControlRepo == nil {
		return fmt.Errorf("access control repository not configured")
	}

	groupID, err := shared.IDFromString(input.GroupID)
	if err != nil {
		return fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	assetID, err := shared.IDFromString(input.AssetID)
	if err != nil {
		return fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
	}

	// Verify group exists
	g, err := s.repo.GetByID(ctx, groupID)
	if err != nil {
		return err
	}

	if err := s.accessControlRepo.DeleteAssetOwner(ctx, assetID, groupID); err != nil {
		return fmt.Errorf("failed to unassign asset: %w", err)
	}

	s.logger.Info("asset unassigned from group", "group_id", input.GroupID, "asset_id", input.AssetID)

	// Refresh materialized view
	if err := s.accessControlRepo.RefreshUserAccessibleAssets(ctx); err != nil {
		s.logger.Error("failed to refresh user accessible assets", "error", err)
	}

	// Log audit event
	actx.TenantID = g.TenantID().String()
	event := NewSuccessEvent(audit.ActionAssetUnassigned, audit.ResourceTypeGroup, input.GroupID).
		WithMessage("Asset removed from group").
		WithMetadata("asset_id", input.AssetID)
	s.logAudit(ctx, actx, event)

	return nil
}

// UpdateAssetOwnershipInput represents the input for updating asset ownership type.
type UpdateAssetOwnershipInput struct {
	GroupID       string `json:"-"`
	AssetID       string `json:"-"`
	OwnershipType string `json:"ownership_type" validate:"required,oneof=primary secondary stakeholder informed"`
}

// UpdateAssetOwnership updates the ownership type of an asset for a group.
func (s *GroupService) UpdateAssetOwnership(ctx context.Context, input UpdateAssetOwnershipInput, actx AuditContext) error {
	if s.accessControlRepo == nil {
		return fmt.Errorf("access control repository not configured")
	}

	groupID, err := shared.IDFromString(input.GroupID)
	if err != nil {
		return fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	assetID, err := shared.IDFromString(input.AssetID)
	if err != nil {
		return fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
	}

	ownershipType := accesscontrol.OwnershipType(input.OwnershipType)
	if !ownershipType.IsValid() {
		return fmt.Errorf("%w: invalid ownership type", shared.ErrValidation)
	}

	// Verify group exists
	g, err := s.repo.GetByID(ctx, groupID)
	if err != nil {
		return err
	}

	// Get existing asset owner
	ao, err := s.accessControlRepo.GetAssetOwner(ctx, assetID, groupID)
	if err != nil {
		return err
	}

	// Update ownership type
	if err := ao.UpdateOwnershipType(ownershipType); err != nil {
		return err
	}

	if err := s.accessControlRepo.UpdateAssetOwner(ctx, ao); err != nil {
		return fmt.Errorf("failed to update asset ownership: %w", err)
	}

	s.logger.Info("asset ownership updated", "group_id", input.GroupID, "asset_id", input.AssetID, "ownership_type", input.OwnershipType)

	// Log audit event
	actx.TenantID = g.TenantID().String()
	event := NewSuccessEvent(audit.ActionAssetOwnershipUpdated, audit.ResourceTypeGroup, input.GroupID).
		WithMessage("Asset ownership type updated").
		WithMetadata("asset_id", input.AssetID).
		WithMetadata("ownership_type", input.OwnershipType)
	s.logAudit(ctx, actx, event)

	return nil
}

// ListGroupAssets lists all assets assigned to a group.
func (s *GroupService) ListGroupAssets(ctx context.Context, groupID string) ([]*accesscontrol.AssetOwner, error) {
	if s.accessControlRepo == nil {
		return nil, fmt.Errorf("access control repository not configured")
	}

	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	// First get asset IDs
	assetIDs, err := s.accessControlRepo.ListAssetsByGroup(ctx, gid)
	if err != nil {
		return nil, fmt.Errorf("failed to list group assets: %w", err)
	}

	// Get full asset owner info for each
	owners := make([]*accesscontrol.AssetOwner, 0, len(assetIDs))
	for _, assetID := range assetIDs {
		ao, err := s.accessControlRepo.GetAssetOwner(ctx, assetID, gid)
		if err != nil {
			s.logger.Error("failed to get asset owner", "asset_id", assetID.String(), "error", err)
			continue
		}
		owners = append(owners, ao)
	}

	return owners, nil
}

// ListAssetOwners lists all groups that own an asset.
func (s *GroupService) ListAssetOwners(ctx context.Context, assetID string) ([]*accesscontrol.AssetOwner, error) {
	if s.accessControlRepo == nil {
		return nil, fmt.Errorf("access control repository not configured")
	}

	aid, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
	}

	return s.accessControlRepo.ListAssetOwners(ctx, aid)
}

// ListMyAssets lists all assets the user can access through their group memberships.
func (s *GroupService) ListMyAssets(ctx context.Context, tenantID string, userID shared.ID) ([]shared.ID, error) {
	if s.accessControlRepo == nil {
		return nil, fmt.Errorf("access control repository not configured")
	}

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.accessControlRepo.ListAccessibleAssets(ctx, tid, userID)
}

// CanAccessAsset checks if a user can access an asset through their group memberships.
func (s *GroupService) CanAccessAsset(ctx context.Context, userID shared.ID, assetID string) (bool, error) {
	if s.accessControlRepo == nil {
		return false, fmt.Errorf("access control repository not configured")
	}

	aid, err := shared.IDFromString(assetID)
	if err != nil {
		return false, fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
	}

	return s.accessControlRepo.CanAccessAsset(ctx, userID, aid)
}
