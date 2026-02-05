package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/permissionset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// PermissionService handles permission-related business operations.
type PermissionService struct {
	permissionSetRepo permissionset.Repository
	accessControlRepo accesscontrol.Repository
	groupRepo         group.Repository
	resolver          *accesscontrol.PermissionResolver
	auditService      *AuditService
	logger            *logger.Logger
}

// NewPermissionService creates a new PermissionService.
func NewPermissionService(
	permissionSetRepo permissionset.Repository,
	log *logger.Logger,
	opts ...PermissionServiceOption,
) *PermissionService {
	s := &PermissionService{
		permissionSetRepo: permissionSetRepo,
		resolver:          accesscontrol.NewPermissionResolver(),
		logger:            log.With("service", "permission"),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// PermissionServiceOption is a functional option for PermissionService.
type PermissionServiceOption func(*PermissionService)

// WithPermissionAuditService sets the audit service for PermissionService.
func WithPermissionAuditService(auditService *AuditService) PermissionServiceOption {
	return func(s *PermissionService) {
		s.auditService = auditService
	}
}

// WithPermissionAccessControlRepository sets the access control repository.
func WithPermissionAccessControlRepository(repo accesscontrol.Repository) PermissionServiceOption {
	return func(s *PermissionService) {
		s.accessControlRepo = repo
	}
}

// WithPermissionGroupRepository sets the group repository.
func WithPermissionGroupRepository(repo group.Repository) PermissionServiceOption {
	return func(s *PermissionService) {
		s.groupRepo = repo
	}
}

// logAudit logs an audit event if audit service is configured.
func (s *PermissionService) logAudit(ctx context.Context, actx AuditContext, event AuditEvent) {
	if s.auditService == nil {
		return
	}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log audit event", "error", err, "action", event.Action)
	}
}

// =============================================================================
// PERMISSION SET CRUD OPERATIONS
// =============================================================================

// CreatePermissionSetInput represents the input for creating a permission set.
type CreatePermissionSetInput struct {
	TenantID    string   `json:"-"`
	Name        string   `json:"name" validate:"required,min=2,max=100"`
	Slug        string   `json:"slug" validate:"required,min=2,max=100,slug"`
	Description string   `json:"description" validate:"max=500"`
	SetType     string   `json:"set_type" validate:"required,oneof=custom extended cloned"`
	ParentSetID *string  `json:"parent_set_id,omitempty"`
	Permissions []string `json:"permissions,omitempty"` // List of permission IDs to add
}

// CreatePermissionSet creates a new permission set.
func (s *PermissionService) CreatePermissionSet(ctx context.Context, input CreatePermissionSetInput, actx AuditContext) (*permissionset.PermissionSet, error) {
	s.logger.Info("creating permission set", "name", input.Name, "type", input.SetType)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	setType := permissionset.SetType(input.SetType)
	if !setType.IsValid() {
		return nil, fmt.Errorf("%w: invalid set type", shared.ErrValidation)
	}

	// Check if slug already exists in tenant
	exists, err := s.permissionSetRepo.ExistsBySlug(ctx, &tenantID, input.Slug)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: slug '%s' is already taken", shared.ErrValidation, input.Slug)
	}

	// Parse parent set ID if provided
	var parentSetID *shared.ID
	if input.ParentSetID != nil && *input.ParentSetID != "" {
		pid, err := shared.IDFromString(*input.ParentSetID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid parent set id format", shared.ErrValidation)
		}
		parentSetID = &pid

		// Verify parent set exists
		_, err = s.permissionSetRepo.GetByID(ctx, pid)
		if err != nil {
			return nil, fmt.Errorf("parent permission set not found: %w", err)
		}
	}

	// Extended and cloned types require a parent
	if (setType == permissionset.SetTypeExtended || setType == permissionset.SetTypeCloned) && parentSetID == nil {
		return nil, fmt.Errorf("%w: parent_set_id is required for %s type", shared.ErrValidation, setType)
	}

	// Create permission set based on type
	var ps *permissionset.PermissionSet
	switch setType {
	case permissionset.SetTypeExtended:
		ps, err = permissionset.NewExtendedPermissionSet(tenantID, input.Name, input.Slug, input.Description, *parentSetID)
	case permissionset.SetTypeCloned:
		// Get parent's latest version
		latestVersion, verr := s.permissionSetRepo.GetLatestVersion(ctx, *parentSetID)
		sourceVersion := 1
		if verr == nil && latestVersion != nil {
			sourceVersion = latestVersion.Version()
		}
		ps, err = permissionset.NewClonedPermissionSet(tenantID, input.Name, input.Slug, input.Description, *parentSetID, sourceVersion)
	default:
		// Custom type
		ps, err = permissionset.NewPermissionSet(tenantID, input.Name, input.Slug, input.Description)
	}

	if err != nil {
		return nil, err
	}

	// Create in database
	if err := s.permissionSetRepo.Create(ctx, ps); err != nil {
		return nil, fmt.Errorf("failed to create permission set: %w", err)
	}

	// Add permissions if provided
	if len(input.Permissions) > 0 {
		for _, permID := range input.Permissions {
			item, err := permissionset.NewItem(ps.ID(), permID, permissionset.ModificationAdd)
			if err != nil {
				s.logger.Error("failed to create permission item", "permission_id", permID, "error", err)
				continue
			}
			if err := s.permissionSetRepo.AddItem(ctx, item); err != nil {
				s.logger.Error("failed to add permission item", "permission_id", permID, "error", err)
			}
		}
	}

	s.logger.Info("permission set created", "id", ps.ID().String(), "name", ps.Name())

	// Log audit event
	actx.TenantID = input.TenantID
	event := NewSuccessEvent(audit.ActionPermissionSetCreated, audit.ResourceTypePermissionSet, ps.ID().String()).
		WithResourceName(ps.Name()).
		WithMessage(fmt.Sprintf("Permission set '%s' created", ps.Name())).
		WithMetadata("set_type", input.SetType)
	s.logAudit(ctx, actx, event)

	return ps, nil
}

// GetPermissionSet retrieves a permission set by ID.
func (s *PermissionService) GetPermissionSet(ctx context.Context, permissionSetID string) (*permissionset.PermissionSet, error) {
	id, err := shared.IDFromString(permissionSetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid permission set id format", shared.ErrValidation)
	}

	return s.permissionSetRepo.GetByID(ctx, id)
}

// GetPermissionSetWithItems retrieves a permission set with its items.
func (s *PermissionService) GetPermissionSetWithItems(ctx context.Context, permissionSetID string) (*permissionset.PermissionSetWithItems, error) {
	id, err := shared.IDFromString(permissionSetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid permission set id format", shared.ErrValidation)
	}

	return s.permissionSetRepo.GetWithItems(ctx, id)
}

// UpdatePermissionSetInput represents the input for updating a permission set.
type UpdatePermissionSetInput struct {
	Name        *string `json:"name" validate:"omitempty,min=2,max=100"`
	Description *string `json:"description" validate:"omitempty,max=500"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

// UpdatePermissionSet updates a permission set.
func (s *PermissionService) UpdatePermissionSet(ctx context.Context, permissionSetID string, input UpdatePermissionSetInput, actx AuditContext) (*permissionset.PermissionSet, error) {
	id, err := shared.IDFromString(permissionSetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid permission set id format", shared.ErrValidation)
	}

	ps, err := s.permissionSetRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Cannot modify system permission sets
	if ps.IsSystem() {
		return nil, fmt.Errorf("%w: cannot modify system permission set", shared.ErrValidation)
	}

	if input.Name != nil {
		if err := ps.UpdateName(*input.Name); err != nil {
			return nil, err
		}
	}

	if input.Description != nil {
		ps.UpdateDescription(*input.Description)
	}

	if input.IsActive != nil {
		if *input.IsActive {
			ps.Activate()
		} else {
			ps.Deactivate()
		}
	}

	if err := s.permissionSetRepo.Update(ctx, ps); err != nil {
		return nil, fmt.Errorf("failed to update permission set: %w", err)
	}

	s.logger.Info("permission set updated", "id", permissionSetID)

	// Log audit event
	if ps.TenantID() != nil {
		actx.TenantID = ps.TenantID().String()
	}
	event := NewSuccessEvent(audit.ActionPermissionSetUpdated, audit.ResourceTypePermissionSet, permissionSetID).
		WithResourceName(ps.Name()).
		WithMessage(fmt.Sprintf("Permission set '%s' updated", ps.Name()))
	s.logAudit(ctx, actx, event)

	return ps, nil
}

// DeletePermissionSet deletes a permission set.
func (s *PermissionService) DeletePermissionSet(ctx context.Context, permissionSetID string, actx AuditContext) error {
	id, err := shared.IDFromString(permissionSetID)
	if err != nil {
		return fmt.Errorf("%w: invalid permission set id format", shared.ErrValidation)
	}

	ps, err := s.permissionSetRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Cannot delete system permission sets
	if ps.IsSystem() {
		return fmt.Errorf("%w: cannot delete system permission set", shared.ErrValidation)
	}

	// Check if permission set is in use
	usageCount, err := s.permissionSetRepo.CountGroupsUsing(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to check permission set usage: %w", err)
	}
	if usageCount > 0 {
		return fmt.Errorf("%w: permission set is assigned to %d groups", shared.ErrValidation, usageCount)
	}

	setName := ps.Name()
	var tenantIDStr string
	if ps.TenantID() != nil {
		tenantIDStr = ps.TenantID().String()
	}

	if err := s.permissionSetRepo.Delete(ctx, id); err != nil {
		return err
	}

	s.logger.Info("permission set deleted", "id", permissionSetID)

	// Log audit event
	actx.TenantID = tenantIDStr
	event := NewSuccessEvent(audit.ActionPermissionSetDeleted, audit.ResourceTypePermissionSet, permissionSetID).
		WithResourceName(setName).
		WithMessage(fmt.Sprintf("Permission set '%s' deleted", setName)).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)

	return nil
}

// ListPermissionSetsInput represents the input for listing permission sets.
type ListPermissionSetsInput struct {
	TenantID      string
	IncludeSystem bool    // Include system permission sets
	SetType       *string // Filter by type
	IsActive      *bool
	Search        string
	Limit         int
	Offset        int
}

// ListPermissionSetsOutput represents the output for listing permission sets.
type ListPermissionSetsOutput struct {
	PermissionSets []*permissionset.PermissionSet
	TotalCount     int64
}

// ListPermissionSets lists permission sets with filtering.
func (s *PermissionService) ListPermissionSets(ctx context.Context, input ListPermissionSetsInput) (*ListPermissionSetsOutput, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	filter := permissionset.ListFilter{
		TenantID:      &tenantID,
		IncludeSystem: input.IncludeSystem,
		Search:        input.Search,
		Limit:         input.Limit,
		Offset:        input.Offset,
	}

	if input.SetType != nil {
		st := permissionset.SetType(*input.SetType)
		filter.SetTypes = []permissionset.SetType{st}
	}

	if input.IsActive != nil {
		filter.IsActive = input.IsActive
	}

	sets, err := s.permissionSetRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list permission sets: %w", err)
	}

	count, err := s.permissionSetRepo.Count(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count permission sets: %w", err)
	}

	return &ListPermissionSetsOutput{
		PermissionSets: sets,
		TotalCount:     count,
	}, nil
}

// =============================================================================
// PERMISSION SET ITEMS OPERATIONS
// =============================================================================

// AddPermissionToSetInput represents the input for adding a permission to a set.
type AddPermissionToSetInput struct {
	PermissionSetID  string `json:"-"`
	PermissionID     string `json:"permission_id" validate:"required"`
	ModificationType string `json:"modification_type" validate:"omitempty,oneof=add remove"`
}

// AddPermissionToSet adds a permission to a permission set.
func (s *PermissionService) AddPermissionToSet(ctx context.Context, input AddPermissionToSetInput, actx AuditContext) error {
	permSetID, err := shared.IDFromString(input.PermissionSetID)
	if err != nil {
		return fmt.Errorf("%w: invalid permission set id format", shared.ErrValidation)
	}

	ps, err := s.permissionSetRepo.GetByID(ctx, permSetID)
	if err != nil {
		return err
	}

	// Cannot modify system permission sets
	if ps.IsSystem() {
		return fmt.Errorf("%w: cannot modify system permission set", shared.ErrValidation)
	}

	modType := permissionset.ModificationAdd
	if input.ModificationType != "" {
		modType = permissionset.ModificationType(input.ModificationType)
	}

	item, err := permissionset.NewItem(permSetID, input.PermissionID, modType)
	if err != nil {
		return err
	}

	if err := s.permissionSetRepo.AddItem(ctx, item); err != nil {
		return fmt.Errorf("failed to add permission: %w", err)
	}

	s.logger.Info("permission added to set", "permission_set_id", input.PermissionSetID, "permission_id", input.PermissionID)

	// Log audit event
	if ps.TenantID() != nil {
		actx.TenantID = ps.TenantID().String()
	}
	event := NewSuccessEvent(audit.ActionPermissionSetUpdated, audit.ResourceTypePermissionSet, input.PermissionSetID).
		WithMessage(fmt.Sprintf("Permission '%s' added to set", input.PermissionID)).
		WithMetadata("permission_id", input.PermissionID).
		WithMetadata("modification_type", string(modType))
	s.logAudit(ctx, actx, event)

	return nil
}

// RemovePermissionFromSet removes a permission from a permission set.
func (s *PermissionService) RemovePermissionFromSet(ctx context.Context, permissionSetID, permissionID string, actx AuditContext) error {
	permSetID, err := shared.IDFromString(permissionSetID)
	if err != nil {
		return fmt.Errorf("%w: invalid permission set id format", shared.ErrValidation)
	}

	ps, err := s.permissionSetRepo.GetByID(ctx, permSetID)
	if err != nil {
		return err
	}

	// Cannot modify system permission sets
	if ps.IsSystem() {
		return fmt.Errorf("%w: cannot modify system permission set", shared.ErrValidation)
	}

	if err := s.permissionSetRepo.RemoveItem(ctx, permSetID, permissionID); err != nil {
		return fmt.Errorf("failed to remove permission: %w", err)
	}

	s.logger.Info("permission removed from set", "permission_set_id", permissionSetID, "permission_id", permissionID)

	// Log audit event
	if ps.TenantID() != nil {
		actx.TenantID = ps.TenantID().String()
	}
	event := NewSuccessEvent(audit.ActionPermissionSetUpdated, audit.ResourceTypePermissionSet, permissionSetID).
		WithMessage(fmt.Sprintf("Permission '%s' removed from set", permissionID)).
		WithMetadata("permission_id", permissionID)
	s.logAudit(ctx, actx, event)

	return nil
}

// =============================================================================
// PERMISSION RESOLUTION
// =============================================================================

// ResolveUserPermissions resolves all effective permissions for a user.
func (s *PermissionService) ResolveUserPermissions(ctx context.Context, tenantID string, userID shared.ID) ([]permission.Permission, error) {
	perms, _, err := s.ResolveUserPermissionsWithCount(ctx, tenantID, userID)
	return perms, err
}

// ResolveUserPermissionsWithCount resolves all effective permissions for a user and returns the group count.
func (s *PermissionService) ResolveUserPermissionsWithCount(ctx context.Context, tenantID string, userID shared.ID) ([]permission.Permission, int, error) {
	if s.groupRepo == nil {
		return nil, 0, fmt.Errorf("group repository not configured")
	}

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	// Get all groups the user belongs to
	userGroups, err := s.groupRepo.ListGroupsByUser(ctx, tid, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get user groups: %w", err)
	}

	// Collect permissions from all groups
	allGroupPermissions := make([][]permission.Permission, 0, len(userGroups))
	for _, ug := range userGroups {
		groupPerms, err := s.ResolveGroupPermissions(ctx, ug.Group.ID().String())
		if err != nil {
			s.logger.Error("failed to resolve group permissions", "group_id", ug.Group.ID().String(), "error", err)
			continue
		}
		allGroupPermissions = append(allGroupPermissions, groupPerms)
	}

	// Merge all group permissions
	return s.resolver.ResolveUserPermissions(allGroupPermissions), len(userGroups), nil
}

// ResolveGroupPermissions resolves all effective permissions for a group.
func (s *PermissionService) ResolveGroupPermissions(ctx context.Context, groupID string) ([]permission.Permission, error) {
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	// Get permission sets assigned to the group
	permSetIDs, err := s.groupRepo.ListPermissionSetIDs(ctx, gid)
	if err != nil {
		return nil, fmt.Errorf("failed to get group permission sets: %w", err)
	}

	// Get permission sets with their items
	permissionSets := make([]*permissionset.PermissionSetWithItems, 0, len(permSetIDs))
	parentChains := make(map[shared.ID][]*permissionset.PermissionSetWithItems)

	for _, psID := range permSetIDs {
		psWithItems, err := s.permissionSetRepo.GetWithItems(ctx, psID)
		if err != nil {
			s.logger.Error("failed to get permission set", "id", psID.String(), "error", err)
			continue
		}
		permissionSets = append(permissionSets, psWithItems)

		// Get parent chain for extended sets
		if psWithItems.PermissionSet.IsExtended() {
			chainSets, err := s.permissionSetRepo.GetInheritanceChain(ctx, psID)
			if err != nil {
				s.logger.Error("failed to get inheritance chain", "id", psID.String(), "error", err)
			} else {
				// Convert []*PermissionSet to []*PermissionSetWithItems
				var chainWithItems []*permissionset.PermissionSetWithItems
				for _, chainPS := range chainSets {
					chainPSWithItems, err := s.permissionSetRepo.GetWithItems(ctx, chainPS.ID())
					if err != nil {
						s.logger.Error("failed to get chain set items", "id", chainPS.ID().String(), "error", err)
						continue
					}
					chainWithItems = append(chainWithItems, chainPSWithItems)
				}
				parentChains[psID] = chainWithItems
			}
		}
	}

	// Get custom group permissions
	var customPermissions []*accesscontrol.GroupPermission
	if s.accessControlRepo != nil {
		customPermissions, err = s.accessControlRepo.ListGroupPermissions(ctx, gid)
		if err != nil {
			s.logger.Error("failed to get custom group permissions", "group_id", groupID, "error", err)
		}
	}

	// Resolve permissions
	return s.resolver.ResolveGroupPermissions(permissionSets, parentChains, customPermissions), nil
}

// HasPermission checks if a user has a specific permission.
func (s *PermissionService) HasPermission(ctx context.Context, tenantID string, userID shared.ID, perm permission.Permission) (bool, error) {
	perms, err := s.ResolveUserPermissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}

	return permission.Contains(perms, perm), nil
}

// HasAnyPermission checks if a user has any of the specified permissions.
func (s *PermissionService) HasAnyPermission(ctx context.Context, tenantID string, userID shared.ID, perms ...permission.Permission) (bool, error) {
	userPerms, err := s.ResolveUserPermissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}

	return permission.ContainsAny(userPerms, perms...), nil
}

// HasAllPermissions checks if a user has all of the specified permissions.
func (s *PermissionService) HasAllPermissions(ctx context.Context, tenantID string, userID shared.ID, perms ...permission.Permission) (bool, error) {
	userPerms, err := s.ResolveUserPermissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}

	return permission.ContainsAll(userPerms, perms...), nil
}

// =============================================================================
// GROUP PERMISSIONS (CUSTOM OVERRIDES)
// =============================================================================

// CreateGroupPermissionInput represents the input for creating a custom group permission.
type CreateGroupPermissionInput struct {
	GroupID      string `json:"-"`
	PermissionID string `json:"permission_id" validate:"required"`
	Effect       string `json:"effect" validate:"required,oneof=allow deny"`
}

// CreateGroupPermission creates a custom permission override for a group.
func (s *PermissionService) CreateGroupPermission(ctx context.Context, input CreateGroupPermissionInput, createdBy shared.ID, actx AuditContext) (*accesscontrol.GroupPermission, error) {
	if s.accessControlRepo == nil {
		return nil, fmt.Errorf("access control repository not configured")
	}

	groupID, err := shared.IDFromString(input.GroupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	effect := accesscontrol.PermissionEffect(input.Effect)
	if !effect.IsValid() {
		return nil, fmt.Errorf("%w: invalid permission effect", shared.ErrValidation)
	}

	// Verify group exists
	g, err := s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return nil, err
	}

	gp, err := accesscontrol.NewGroupPermission(groupID, input.PermissionID, effect, &createdBy)
	if err != nil {
		return nil, err
	}

	if err := s.accessControlRepo.CreateGroupPermission(ctx, gp); err != nil {
		return nil, fmt.Errorf("failed to create group permission: %w", err)
	}

	s.logger.Info("group permission created", "group_id", input.GroupID, "permission_id", input.PermissionID, "effect", effect)

	// Log audit event
	actx.TenantID = g.TenantID().String()
	event := NewSuccessEvent(audit.ActionPermissionGranted, audit.ResourceTypeGroup, input.GroupID).
		WithMessage(fmt.Sprintf("Custom %s permission '%s' added to group", effect, input.PermissionID)).
		WithMetadata("permission_id", input.PermissionID).
		WithMetadata("effect", input.Effect)
	s.logAudit(ctx, actx, event)

	return gp, nil
}

// DeleteGroupPermission removes a custom permission override from a group.
func (s *PermissionService) DeleteGroupPermission(ctx context.Context, groupID, permissionID string, actx AuditContext) error {
	if s.accessControlRepo == nil {
		return fmt.Errorf("access control repository not configured")
	}

	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	// Get group for audit context
	g, err := s.groupRepo.GetByID(ctx, gid)
	if err != nil {
		return err
	}

	if err := s.accessControlRepo.DeleteGroupPermission(ctx, gid, permissionID); err != nil {
		return fmt.Errorf("failed to delete group permission: %w", err)
	}

	s.logger.Info("group permission deleted", "group_id", groupID, "permission_id", permissionID)

	// Log audit event
	actx.TenantID = g.TenantID().String()
	event := NewSuccessEvent(audit.ActionPermissionRevoked, audit.ResourceTypeGroup, groupID).
		WithMessage(fmt.Sprintf("Custom permission '%s' removed from group", permissionID)).
		WithMetadata("permission_id", permissionID)
	s.logAudit(ctx, actx, event)

	return nil
}

// ListGroupCustomPermissions lists custom permissions for a group.
func (s *PermissionService) ListGroupCustomPermissions(ctx context.Context, groupID string) ([]*accesscontrol.GroupPermission, error) {
	if s.accessControlRepo == nil {
		return nil, fmt.Errorf("access control repository not configured")
	}

	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}

	return s.accessControlRepo.ListGroupPermissions(ctx, gid)
}
