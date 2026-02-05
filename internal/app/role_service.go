package app

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/role"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// RoleService handles role-related business operations.
type RoleService struct {
	roleRepo       role.Repository
	permissionRepo role.PermissionRepository
	auditService   *AuditService
	// Permission sync services for real-time permission updates
	permVersionSvc *PermissionVersionService
	permCacheSvc   *PermissionCacheService
	logger         *logger.Logger
}

// NewRoleService creates a new RoleService.
func NewRoleService(
	roleRepo role.Repository,
	permissionRepo role.PermissionRepository,
	log *logger.Logger,
	opts ...RoleServiceOption,
) *RoleService {
	s := &RoleService{
		roleRepo:       roleRepo,
		permissionRepo: permissionRepo,
		logger:         log.With("service", "role"),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// RoleServiceOption is a functional option for RoleService.
type RoleServiceOption func(*RoleService)

// WithRoleAuditService sets the audit service for RoleService.
func WithRoleAuditService(auditService *AuditService) RoleServiceOption {
	return func(s *RoleService) {
		s.auditService = auditService
	}
}

// WithRolePermissionVersionService sets the permission version service.
// This enables real-time permission synchronization when roles change.
func WithRolePermissionVersionService(svc *PermissionVersionService) RoleServiceOption {
	return func(s *RoleService) {
		s.permVersionSvc = svc
	}
}

// WithRolePermissionCacheService sets the permission cache service.
// This enables permission cache invalidation when roles change.
func WithRolePermissionCacheService(svc *PermissionCacheService) RoleServiceOption {
	return func(s *RoleService) {
		s.permCacheSvc = svc
	}
}

// logAudit logs an audit event if audit service is configured.
func (s *RoleService) logAudit(ctx context.Context, actx AuditContext, event AuditEvent) {
	if s.auditService == nil {
		return
	}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log audit event", "error", err, "action", event.Action)
	}
}

// invalidateUserPermissions invalidates permission cache and increments version for a user.
// Called when user's roles are changed (assigned, removed, or updated).
// This triggers real-time permission sync: frontend detects version mismatch and refetches.
func (s *RoleService) invalidateUserPermissions(ctx context.Context, tenantID, userID string) {
	// Invalidate permission cache
	if s.permCacheSvc != nil {
		s.permCacheSvc.Invalidate(ctx, tenantID, userID)
	}

	// Increment version to trigger frontend refresh
	if s.permVersionSvc != nil {
		newVersion := s.permVersionSvc.Increment(ctx, tenantID, userID)
		s.logger.Debug("user permissions invalidated",
			"tenant_id", tenantID,
			"user_id", userID,
			"new_version", newVersion,
		)
	}
}

// invalidateUsersPermissions invalidates permissions for multiple users.
// Called when a role definition is updated (affects all users with that role).
func (s *RoleService) invalidateUsersPermissions(ctx context.Context, tenantID string, userIDs []string) {
	if len(userIDs) == 0 {
		return
	}

	// Invalidate cache for all users
	if s.permCacheSvc != nil {
		s.permCacheSvc.InvalidateForUsers(ctx, tenantID, userIDs)
	}

	// Increment versions for all users
	if s.permVersionSvc != nil {
		s.permVersionSvc.IncrementForUsers(ctx, tenantID, userIDs)
		s.logger.Info("permissions invalidated for multiple users",
			"tenant_id", tenantID,
			"user_count", len(userIDs),
		)
	}
}

// =============================================================================
// ROLE CRUD OPERATIONS
// =============================================================================

// CreateRoleInput represents the input for creating a role.
type CreateRoleInput struct {
	TenantID          string   `json:"-"`
	Slug              string   `json:"slug" validate:"required,min=2,max=50,slug"`
	Name              string   `json:"name" validate:"required,min=2,max=100"`
	Description       string   `json:"description" validate:"max=500"`
	HierarchyLevel    int      `json:"hierarchy_level" validate:"min=0,max=100"`
	HasFullDataAccess bool     `json:"has_full_data_access"`
	Permissions       []string `json:"permissions"`
}

// CreateRole creates a new custom role for a tenant.
func (s *RoleService) CreateRole(ctx context.Context, input CreateRoleInput, createdBy string, actx AuditContext) (*role.Role, error) {
	s.logger.Info("creating role", "name", input.Name, "tenant_id", input.TenantID)

	tenantID, err := role.ParseID(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	createdByID, err := role.ParseID(createdBy)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid created_by id format", shared.ErrValidation)
	}

	// Check if slug already exists in tenant
	_, err = s.roleRepo.GetBySlug(ctx, &tenantID, input.Slug)
	if err == nil {
		return nil, fmt.Errorf("%w: role with slug '%s' already exists", shared.ErrValidation, input.Slug)
	}
	if !errors.Is(err, role.ErrRoleNotFound) {
		return nil, fmt.Errorf("failed to check slug existence: %w", err)
	}

	// Validate permissions if provided
	if len(input.Permissions) > 0 {
		valid, invalidIDs, err := s.permissionRepo.ValidatePermissions(ctx, input.Permissions)
		if err != nil {
			return nil, fmt.Errorf("failed to validate permissions: %w", err)
		}
		if !valid {
			return nil, fmt.Errorf("%w: invalid permissions: %v", shared.ErrValidation, invalidIDs)
		}
	}

	// Create the role
	r := role.New(
		tenantID,
		input.Slug,
		input.Name,
		input.Description,
		input.HierarchyLevel,
		input.HasFullDataAccess,
		input.Permissions,
		createdByID,
	)

	if err := s.roleRepo.Create(ctx, r); err != nil {
		if errors.Is(err, role.ErrRoleSlugExists) {
			return nil, fmt.Errorf("%w: role with slug '%s' already exists", shared.ErrValidation, input.Slug)
		}
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	s.logger.Info("role created", "id", r.ID().String(), "name", r.Name())

	// Log audit event
	actx.TenantID = input.TenantID
	event := NewSuccessEvent(audit.ActionRoleCreated, audit.ResourceTypeRole, r.ID().String()).
		WithResourceName(r.Name()).
		WithMessage(fmt.Sprintf("Role '%s' created", r.Name())).
		WithMetadata("slug", r.Slug()).
		WithMetadata("hierarchy_level", r.HierarchyLevel()).
		WithMetadata("has_full_data_access", r.HasFullDataAccess()).
		WithMetadata("permission_count", r.PermissionCount())
	s.logAudit(ctx, actx, event)

	return r, nil
}

// GetRole retrieves a role by ID.
func (s *RoleService) GetRole(ctx context.Context, roleID string) (*role.Role, error) {
	id, err := role.ParseID(roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
	}

	return s.roleRepo.GetByID(ctx, id)
}

// GetRoleBySlug retrieves a role by slug.
func (s *RoleService) GetRoleBySlug(ctx context.Context, tenantID *string, slug string) (*role.Role, error) {
	var tid *role.ID
	if tenantID != nil {
		parsedTID, err := role.ParseID(*tenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
		}
		tid = &parsedTID
	}

	return s.roleRepo.GetBySlug(ctx, tid, slug)
}

// UpdateRoleInput represents the input for updating a role.
type UpdateRoleInput struct {
	Name              *string  `json:"name" validate:"omitempty,min=2,max=100"`
	Description       *string  `json:"description" validate:"omitempty,max=500"`
	HierarchyLevel    *int     `json:"hierarchy_level" validate:"omitempty,min=0,max=100"`
	HasFullDataAccess *bool    `json:"has_full_data_access"`
	Permissions       []string `json:"permissions,omitempty"`
}

// UpdateRole updates a role.
func (s *RoleService) UpdateRole(ctx context.Context, roleID string, input UpdateRoleInput, actx AuditContext) (*role.Role, error) {
	id, err := role.ParseID(roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
	}

	r, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Cannot modify system roles
	if r.IsSystem() {
		return nil, fmt.Errorf("%w: cannot modify system role", shared.ErrValidation)
	}

	// Track changes for audit
	changes := audit.NewChanges()

	name := r.Name()
	description := r.Description()
	hierarchyLevel := r.HierarchyLevel()
	hasFullDataAccess := r.HasFullDataAccess()

	if input.Name != nil {
		changes.Set("name", name, *input.Name)
		name = *input.Name
	}
	if input.Description != nil {
		changes.Set("description", description, *input.Description)
		description = *input.Description
	}
	if input.HierarchyLevel != nil {
		changes.Set("hierarchy_level", hierarchyLevel, *input.HierarchyLevel)
		hierarchyLevel = *input.HierarchyLevel
	}
	if input.HasFullDataAccess != nil {
		changes.Set("has_full_data_access", hasFullDataAccess, *input.HasFullDataAccess)
		hasFullDataAccess = *input.HasFullDataAccess
	}

	if err := r.Update(name, description, hierarchyLevel, hasFullDataAccess); err != nil {
		return nil, err
	}

	// Update permissions if provided
	if input.Permissions != nil {
		// Validate permissions
		if len(input.Permissions) > 0 {
			valid, invalidIDs, err := s.permissionRepo.ValidatePermissions(ctx, input.Permissions)
			if err != nil {
				return nil, fmt.Errorf("failed to validate permissions: %w", err)
			}
			if !valid {
				return nil, fmt.Errorf("%w: invalid permissions: %v", shared.ErrValidation, invalidIDs)
			}
		}

		changes.Set("permissions", r.Permissions(), input.Permissions)
		if err := r.SetPermissions(input.Permissions); err != nil {
			return nil, err
		}
	}

	if err := s.roleRepo.Update(ctx, r); err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	// If permissions changed, invalidate all users with this role
	if input.Permissions != nil {
		tenantIDStr := ""
		if r.TenantID() != nil {
			tenantIDStr = r.TenantID().String()
		}
		if tenantIDStr != "" {
			// Get all users with this role
			members, err := s.roleRepo.ListRoleMembers(ctx, *r.TenantID(), id)
			if err == nil && len(members) > 0 {
				userIDs := make([]string, len(members))
				for i, m := range members {
					userIDs[i] = m.UserID.String()
				}
				s.invalidateUsersPermissions(ctx, tenantIDStr, userIDs)
			}
		}
	}

	s.logger.Info("role updated", "id", roleID)

	// Log audit event
	if r.TenantID() != nil {
		actx.TenantID = r.TenantID().String()
	}
	event := NewSuccessEvent(audit.ActionRoleUpdated, audit.ResourceTypeRole, roleID).
		WithResourceName(r.Name()).
		WithMessage(fmt.Sprintf("Role '%s' updated", r.Name())).
		WithChanges(changes)
	s.logAudit(ctx, actx, event)

	return r, nil
}

// DeleteRole deletes a role.
func (s *RoleService) DeleteRole(ctx context.Context, roleID string, actx AuditContext) error {
	id, err := role.ParseID(roleID)
	if err != nil {
		return fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
	}

	r, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Cannot delete system roles
	if r.IsSystem() {
		return fmt.Errorf("%w: cannot delete system role", shared.ErrValidation)
	}

	roleName := r.Name()
	var tenantIDStr string
	if r.TenantID() != nil {
		tenantIDStr = r.TenantID().String()
	}

	if err := s.roleRepo.Delete(ctx, id); err != nil {
		if errors.Is(err, role.ErrRoleInUse) {
			return fmt.Errorf("%w: role is assigned to users and cannot be deleted", shared.ErrValidation)
		}
		return fmt.Errorf("failed to delete role: %w", err)
	}

	s.logger.Info("role deleted", "id", roleID)

	// Log audit event
	actx.TenantID = tenantIDStr
	event := NewSuccessEvent(audit.ActionRoleDeleted, audit.ResourceTypeRole, roleID).
		WithResourceName(roleName).
		WithMessage(fmt.Sprintf("Role '%s' deleted", roleName)).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)

	return nil
}

// =============================================================================
// ROLE LISTING
// =============================================================================

// ListRolesForTenant returns all roles available for a tenant.
func (s *RoleService) ListRolesForTenant(ctx context.Context, tenantID string) ([]*role.Role, error) {
	tid, err := role.ParseID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.roleRepo.ListForTenant(ctx, tid)
}

// ListSystemRoles returns only system roles.
func (s *RoleService) ListSystemRoles(ctx context.Context) ([]*role.Role, error) {
	return s.roleRepo.ListSystemRoles(ctx)
}

// =============================================================================
// USER ROLE ASSIGNMENTS
// =============================================================================

// GetUserRoles returns all roles for a user in a tenant.
func (s *RoleService) GetUserRoles(ctx context.Context, tenantID, userID string) ([]*role.Role, error) {
	tid, err := role.ParseID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	uid, err := role.ParseID(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
	}

	return s.roleRepo.GetUserRoles(ctx, tid, uid)
}

// GetUserPermissions returns all permissions for a user (UNION of all roles).
func (s *RoleService) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	tid, err := role.ParseID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	uid, err := role.ParseID(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
	}

	return s.roleRepo.GetUserPermissions(ctx, tid, uid)
}

// HasFullDataAccess checks if user has full data access.
func (s *RoleService) HasFullDataAccess(ctx context.Context, tenantID, userID string) (bool, error) {
	tid, err := role.ParseID(tenantID)
	if err != nil {
		return false, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	uid, err := role.ParseID(userID)
	if err != nil {
		return false, fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
	}

	return s.roleRepo.HasFullDataAccess(ctx, tid, uid)
}

// HasPermission checks if a user has a specific permission.
func (s *RoleService) HasPermission(ctx context.Context, tenantID, userID, permission string) (bool, error) {
	permissions, err := s.GetUserPermissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}

	return slices.Contains(permissions, permission), nil
}

// AssignRoleInput represents the input for assigning a role to a user.
type AssignRoleInput struct {
	TenantID string `json:"-"`
	UserID   string `json:"user_id" validate:"required,uuid"`
	RoleID   string `json:"role_id" validate:"required,uuid"`
}

// AssignRole assigns a role to a user.
func (s *RoleService) AssignRole(ctx context.Context, input AssignRoleInput, assignedBy string, actx AuditContext) error {
	tid, err := role.ParseID(input.TenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	uid, err := role.ParseID(input.UserID)
	if err != nil {
		return fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
	}

	rid, err := role.ParseID(input.RoleID)
	if err != nil {
		return fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
	}

	// Verify role exists and is available for tenant
	r, err := s.roleRepo.GetByID(ctx, rid)
	if err != nil {
		return err
	}

	// Ensure role is either a system role or belongs to the same tenant
	if r.TenantID() != nil && r.TenantID().String() != input.TenantID {
		return fmt.Errorf("%w: role not available for this tenant", shared.ErrValidation)
	}

	var assignedByID *role.ID
	if assignedBy != "" {
		id, err := role.ParseID(assignedBy)
		if err != nil {
			return fmt.Errorf("%w: invalid assigned_by id format", shared.ErrValidation)
		}
		assignedByID = &id
	}

	if err := s.roleRepo.AssignRole(ctx, tid, uid, rid, assignedByID); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	// Invalidate user's permissions to trigger real-time sync
	s.invalidateUserPermissions(ctx, input.TenantID, input.UserID)

	s.logger.Info("role assigned", "tenant_id", input.TenantID, "user_id", input.UserID, "role_id", input.RoleID)

	// Log audit event
	actx.TenantID = input.TenantID
	event := NewSuccessEvent(audit.ActionRoleAssigned, audit.ResourceTypeRole, input.RoleID).
		WithResourceName(r.Name()).
		WithMessage(fmt.Sprintf("Role '%s' assigned to user", r.Name())).
		WithMetadata("user_id", input.UserID).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)

	return nil
}

// RemoveRole removes a role from a user.
func (s *RoleService) RemoveRole(ctx context.Context, tenantID, userID, roleID string, actx AuditContext) error {
	tid, err := role.ParseID(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	uid, err := role.ParseID(userID)
	if err != nil {
		return fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
	}

	rid, err := role.ParseID(roleID)
	if err != nil {
		return fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
	}

	// Get role name for audit
	r, _ := s.roleRepo.GetByID(ctx, rid)
	roleName := "unknown"
	if r != nil {
		roleName = r.Name()
	}

	if err := s.roleRepo.RemoveRole(ctx, tid, uid, rid); err != nil {
		if errors.Is(err, role.ErrUserRoleNotFound) {
			return fmt.Errorf("%w: user does not have this role", shared.ErrValidation)
		}
		return fmt.Errorf("failed to remove role: %w", err)
	}

	// Invalidate user's permissions to trigger real-time sync
	s.invalidateUserPermissions(ctx, tenantID, userID)

	s.logger.Info("role removed", "tenant_id", tenantID, "user_id", userID, "role_id", roleID)

	// Log audit event
	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionRoleUnassigned, audit.ResourceTypeRole, roleID).
		WithResourceName(roleName).
		WithMessage(fmt.Sprintf("Role '%s' removed from user", roleName)).
		WithMetadata("user_id", userID).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)

	return nil
}

// SetUserRolesInput represents the input for setting user roles.
type SetUserRolesInput struct {
	TenantID string   `json:"-"`
	UserID   string   `json:"user_id" validate:"required,uuid"`
	RoleIDs  []string `json:"role_ids" validate:"required,min=1"`
}

// SetUserRoles replaces all roles for a user.
func (s *RoleService) SetUserRoles(ctx context.Context, input SetUserRolesInput, assignedBy string, actx AuditContext) error {
	tid, err := role.ParseID(input.TenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	uid, err := role.ParseID(input.UserID)
	if err != nil {
		return fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
	}

	roleIDs := make([]role.ID, 0, len(input.RoleIDs))
	roleNames := make([]string, 0, len(input.RoleIDs))
	for _, ridStr := range input.RoleIDs {
		rid, err := role.ParseID(ridStr)
		if err != nil {
			return fmt.Errorf("%w: invalid role id format: %s", shared.ErrValidation, ridStr)
		}

		// Verify role exists and is available for tenant
		r, err := s.roleRepo.GetByID(ctx, rid)
		if err != nil {
			return fmt.Errorf("role not found: %s", ridStr)
		}

		// Ensure role is either a system role or belongs to the same tenant
		if r.TenantID() != nil && r.TenantID().String() != input.TenantID {
			return fmt.Errorf("%w: role %s not available for this tenant", shared.ErrValidation, ridStr)
		}

		roleIDs = append(roleIDs, rid)
		roleNames = append(roleNames, r.Name())
	}

	// Get current roles for audit
	currentRoles, _ := s.roleRepo.GetUserRoles(ctx, tid, uid)
	currentRoleNames := make([]string, 0, len(currentRoles))
	for _, r := range currentRoles {
		currentRoleNames = append(currentRoleNames, r.Name())
	}

	var assignedByID *role.ID
	if assignedBy != "" {
		id, err := role.ParseID(assignedBy)
		if err != nil {
			return fmt.Errorf("%w: invalid assigned_by id format", shared.ErrValidation)
		}
		assignedByID = &id
	}

	if err := s.roleRepo.SetUserRoles(ctx, tid, uid, roleIDs, assignedByID); err != nil {
		return fmt.Errorf("failed to set user roles: %w", err)
	}

	// Invalidate user's permissions to trigger real-time sync
	s.invalidateUserPermissions(ctx, input.TenantID, input.UserID)

	s.logger.Info("user roles updated", "tenant_id", input.TenantID, "user_id", input.UserID, "roles", input.RoleIDs)

	// Log audit event
	actx.TenantID = input.TenantID
	changes := audit.NewChanges().Set("roles", currentRoleNames, roleNames)
	event := NewSuccessEvent(audit.ActionUserRolesUpdated, audit.ResourceTypeUser, input.UserID).
		WithMessage(fmt.Sprintf("User roles updated to: %v", roleNames)).
		WithChanges(changes).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)

	return nil
}

// =============================================================================
// BULK OPERATIONS
// =============================================================================

// BulkAssignRoleToUsersInput represents the input for bulk role assignment.
type BulkAssignRoleToUsersInput struct {
	TenantID string   `json:"-"`
	RoleID   string   `json:"role_id" validate:"required,uuid"`
	UserIDs  []string `json:"user_ids" validate:"required,min=1,dive,uuid"`
}

// BulkAssignRoleToUsersResult represents the result of bulk role assignment.
type BulkAssignRoleToUsersResult struct {
	SuccessCount int      `json:"success_count"`
	FailedCount  int      `json:"failed_count"`
	FailedUsers  []string `json:"failed_users,omitempty"`
}

// BulkAssignRoleToUsers assigns a role to multiple users at once.
func (s *RoleService) BulkAssignRoleToUsers(ctx context.Context, input BulkAssignRoleToUsersInput, assignedBy string, actx AuditContext) (*BulkAssignRoleToUsersResult, error) {
	s.logger.Info("bulk assigning role to users", "role_id", input.RoleID, "user_count", len(input.UserIDs))

	tid, err := role.ParseID(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	rid, err := role.ParseID(input.RoleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
	}

	// Verify role exists and is available for tenant
	r, err := s.roleRepo.GetByID(ctx, rid)
	if err != nil {
		return nil, err
	}

	// Ensure role is either a system role or belongs to the same tenant
	if r.TenantID() != nil && r.TenantID().String() != input.TenantID {
		return nil, fmt.Errorf("%w: role not available for this tenant", shared.ErrValidation)
	}

	// Parse user IDs
	userIDs := make([]role.ID, 0, len(input.UserIDs))
	for _, uidStr := range input.UserIDs {
		uid, err := role.ParseID(uidStr)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid user id format: %s", shared.ErrValidation, uidStr)
		}
		userIDs = append(userIDs, uid)
	}

	var assignedByID *role.ID
	if assignedBy != "" {
		id, err := role.ParseID(assignedBy)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid assigned_by id format", shared.ErrValidation)
		}
		assignedByID = &id
	}

	// Perform bulk assignment
	if err := s.roleRepo.BulkAssignRoleToUsers(ctx, tid, rid, userIDs, assignedByID); err != nil {
		return nil, fmt.Errorf("failed to bulk assign role: %w", err)
	}

	// Invalidate permissions for all affected users
	s.invalidateUsersPermissions(ctx, input.TenantID, input.UserIDs)

	s.logger.Info("bulk role assignment completed", "role_id", input.RoleID, "user_count", len(input.UserIDs))

	// Log audit event
	actx.TenantID = input.TenantID
	event := NewSuccessEvent(audit.ActionRoleAssigned, audit.ResourceTypeRole, input.RoleID).
		WithResourceName(r.Name()).
		WithMessage(fmt.Sprintf("Role '%s' assigned to %d users", r.Name(), len(input.UserIDs))).
		WithMetadata("user_count", len(input.UserIDs)).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)

	return &BulkAssignRoleToUsersResult{
		SuccessCount: len(input.UserIDs),
		FailedCount:  0,
	}, nil
}

// =============================================================================
// ROLE MEMBERS
// =============================================================================

// ListRoleMembers returns all users who have a specific role.
func (s *RoleService) ListRoleMembers(ctx context.Context, tenantID, roleID string) ([]*role.UserRole, error) {
	tid, err := role.ParseID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	rid, err := role.ParseID(roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
	}

	return s.roleRepo.ListRoleMembers(ctx, tid, rid)
}

// CountUsersWithRole returns the count of users with a specific role.
func (s *RoleService) CountUsersWithRole(ctx context.Context, roleID string) (int, error) {
	rid, err := role.ParseID(roleID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
	}

	return s.roleRepo.CountUsersWithRole(ctx, rid)
}

// =============================================================================
// PERMISSIONS OPERATIONS
// =============================================================================

// ListModulesWithPermissions returns all modules with their permissions.
func (s *RoleService) ListModulesWithPermissions(ctx context.Context) ([]*role.Module, error) {
	return s.permissionRepo.ListModulesWithPermissions(ctx)
}

// ListPermissions returns all permissions.
func (s *RoleService) ListPermissions(ctx context.Context) ([]*role.Permission, error) {
	return s.permissionRepo.ListPermissions(ctx)
}
