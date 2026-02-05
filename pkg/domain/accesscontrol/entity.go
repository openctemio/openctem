package accesscontrol

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// AssetOwner represents ownership of an asset by a group or user.
// Either groupID or userID must be set (but not both).
type AssetOwner struct {
	id            shared.ID
	assetID       shared.ID
	groupID       *shared.ID // Optional: group that owns this asset
	userID        *shared.ID // Optional: user that directly owns this asset
	ownershipType OwnershipType
	assignedAt    time.Time
	assignedBy    *shared.ID
}

// NewAssetOwnerForGroup creates a new asset owner relationship for a group.
func NewAssetOwnerForGroup(assetID, groupID shared.ID, ownershipType OwnershipType, assignedBy *shared.ID) (*AssetOwner, error) {
	if assetID.IsZero() {
		return nil, fmt.Errorf("%w: assetID is required", shared.ErrValidation)
	}
	if groupID.IsZero() {
		return nil, fmt.Errorf("%w: groupID is required for group ownership", shared.ErrValidation)
	}
	if !ownershipType.IsValid() {
		return nil, fmt.Errorf("%w: invalid ownership type", shared.ErrValidation)
	}

	return &AssetOwner{
		id:            shared.NewID(),
		assetID:       assetID,
		groupID:       &groupID,
		userID:        nil,
		ownershipType: ownershipType,
		assignedAt:    time.Now().UTC(),
		assignedBy:    assignedBy,
	}, nil
}

// NewAssetOwnerForUser creates a new asset owner relationship for a user (direct ownership).
func NewAssetOwnerForUser(assetID, userID shared.ID, ownershipType OwnershipType, assignedBy *shared.ID) (*AssetOwner, error) {
	if assetID.IsZero() {
		return nil, fmt.Errorf("%w: assetID is required", shared.ErrValidation)
	}
	if userID.IsZero() {
		return nil, fmt.Errorf("%w: userID is required for user ownership", shared.ErrValidation)
	}
	if !ownershipType.IsValid() {
		return nil, fmt.Errorf("%w: invalid ownership type", shared.ErrValidation)
	}

	return &AssetOwner{
		id:            shared.NewID(),
		assetID:       assetID,
		groupID:       nil,
		userID:        &userID,
		ownershipType: ownershipType,
		assignedAt:    time.Now().UTC(),
		assignedBy:    assignedBy,
	}, nil
}

// NewAssetOwner creates a new asset owner relationship (legacy - defaults to group ownership).
// Deprecated: Use NewAssetOwnerForGroup or NewAssetOwnerForUser instead.
func NewAssetOwner(assetID, groupID shared.ID, ownershipType OwnershipType, assignedBy *shared.ID) (*AssetOwner, error) {
	return NewAssetOwnerForGroup(assetID, groupID, ownershipType, assignedBy)
}

// ReconstituteAssetOwner recreates an AssetOwner from persistence.
func ReconstituteAssetOwner(
	id shared.ID,
	assetID shared.ID,
	groupID *shared.ID,
	userID *shared.ID,
	ownershipType OwnershipType,
	assignedAt time.Time,
	assignedBy *shared.ID,
) *AssetOwner {
	return &AssetOwner{
		id:            id,
		assetID:       assetID,
		groupID:       groupID,
		userID:        userID,
		ownershipType: ownershipType,
		assignedAt:    assignedAt,
		assignedBy:    assignedBy,
	}
}

// ID returns the owner record ID.
func (ao *AssetOwner) ID() shared.ID {
	return ao.id
}

// AssetID returns the asset ID.
func (ao *AssetOwner) AssetID() shared.ID {
	return ao.assetID
}

// GroupID returns the group ID (nil if user ownership).
func (ao *AssetOwner) GroupID() *shared.ID {
	return ao.groupID
}

// UserID returns the user ID (nil if group ownership).
func (ao *AssetOwner) UserID() *shared.ID {
	return ao.userID
}

// IsGroupOwnership returns true if this is group-level ownership.
func (ao *AssetOwner) IsGroupOwnership() bool {
	return ao.groupID != nil
}

// IsUserOwnership returns true if this is direct user-level ownership.
func (ao *AssetOwner) IsUserOwnership() bool {
	return ao.userID != nil
}

// OwnershipType returns the ownership type.
func (ao *AssetOwner) OwnershipType() OwnershipType {
	return ao.ownershipType
}

// AssignedAt returns when the ownership was assigned.
func (ao *AssetOwner) AssignedAt() time.Time {
	return ao.assignedAt
}

// AssignedBy returns who assigned the ownership.
func (ao *AssetOwner) AssignedBy() *shared.ID {
	return ao.assignedBy
}

// HasFullAccess checks if this ownership grants full access.
func (ao *AssetOwner) HasFullAccess() bool {
	return ao.ownershipType.HasFullAccess()
}

// HasViewAccess checks if this ownership grants view access.
func (ao *AssetOwner) HasViewAccess() bool {
	return ao.ownershipType.HasViewAccess()
}

// UpdateOwnershipType updates the ownership type.
func (ao *AssetOwner) UpdateOwnershipType(ownershipType OwnershipType) error {
	if !ownershipType.IsValid() {
		return fmt.Errorf("%w: invalid ownership type", shared.ErrValidation)
	}
	ao.ownershipType = ownershipType
	return nil
}

// GroupPermission represents a custom permission override for a group.
type GroupPermission struct {
	groupID      shared.ID
	permissionID string
	effect       PermissionEffect
	scopeType    *ScopeType
	scopeValue   *ScopeValue
	createdAt    time.Time
	createdBy    *shared.ID
}

// NewGroupPermission creates a new group permission override.
func NewGroupPermission(groupID shared.ID, permissionID string, effect PermissionEffect, createdBy *shared.ID) (*GroupPermission, error) {
	if groupID.IsZero() {
		return nil, fmt.Errorf("%w: groupID is required", shared.ErrValidation)
	}
	if permissionID == "" {
		return nil, fmt.Errorf("%w: permissionID is required", shared.ErrValidation)
	}
	if !effect.IsValid() {
		return nil, fmt.Errorf("%w: invalid permission effect", shared.ErrValidation)
	}

	return &GroupPermission{
		groupID:      groupID,
		permissionID: permissionID,
		effect:       effect,
		createdAt:    time.Now().UTC(),
		createdBy:    createdBy,
	}, nil
}

// ReconstituteGroupPermission recreates a GroupPermission from persistence.
func ReconstituteGroupPermission(
	groupID shared.ID,
	permissionID string,
	effect PermissionEffect,
	scopeType *ScopeType,
	scopeValue *ScopeValue,
	createdAt time.Time,
	createdBy *shared.ID,
) *GroupPermission {
	return &GroupPermission{
		groupID:      groupID,
		permissionID: permissionID,
		effect:       effect,
		scopeType:    scopeType,
		scopeValue:   scopeValue,
		createdAt:    createdAt,
		createdBy:    createdBy,
	}
}

// GroupID returns the group ID.
func (gp *GroupPermission) GroupID() shared.ID {
	return gp.groupID
}

// PermissionID returns the permission ID.
func (gp *GroupPermission) PermissionID() string {
	return gp.permissionID
}

// Effect returns the permission effect.
func (gp *GroupPermission) Effect() PermissionEffect {
	return gp.effect
}

// ScopeType returns the scope type (if any).
func (gp *GroupPermission) ScopeType() *ScopeType {
	return gp.scopeType
}

// ScopeValue returns the scope value (if any).
func (gp *GroupPermission) ScopeValue() *ScopeValue {
	return gp.scopeValue
}

// CreatedAt returns when this permission was created.
func (gp *GroupPermission) CreatedAt() time.Time {
	return gp.createdAt
}

// CreatedBy returns who created this permission.
func (gp *GroupPermission) CreatedBy() *shared.ID {
	return gp.createdBy
}

// IsAllow checks if this is an allow effect.
func (gp *GroupPermission) IsAllow() bool {
	return gp.effect == EffectAllow
}

// IsDeny checks if this is a deny effect.
func (gp *GroupPermission) IsDeny() bool {
	return gp.effect == EffectDeny
}

// HasScope checks if this permission has a scope restriction.
func (gp *GroupPermission) HasScope() bool {
	return gp.scopeType != nil
}

// SetScope sets the scope for this permission.
func (gp *GroupPermission) SetScope(scopeType ScopeType, scopeValue *ScopeValue) error {
	if !scopeType.IsValid() {
		return fmt.Errorf("%w: invalid scope type", shared.ErrValidation)
	}
	gp.scopeType = &scopeType
	gp.scopeValue = scopeValue
	return nil
}

// AssignmentRule represents an auto-routing rule for findings.
type AssignmentRule struct {
	id            shared.ID
	tenantID      shared.ID
	name          string
	description   string
	priority      int
	isActive      bool
	conditions    AssignmentConditions
	targetGroupID shared.ID
	options       AssignmentOptions
	createdAt     time.Time
	updatedAt     time.Time
	createdBy     *shared.ID
}

// NewAssignmentRule creates a new assignment rule.
func NewAssignmentRule(
	tenantID shared.ID,
	name string,
	conditions AssignmentConditions,
	targetGroupID shared.ID,
	createdBy *shared.ID,
) (*AssignmentRule, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenantID is required", shared.ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if targetGroupID.IsZero() {
		return nil, fmt.Errorf("%w: targetGroupID is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &AssignmentRule{
		id:            shared.NewID(),
		tenantID:      tenantID,
		name:          name,
		priority:      0,
		isActive:      true,
		conditions:    conditions,
		targetGroupID: targetGroupID,
		options:       AssignmentOptions{},
		createdAt:     now,
		updatedAt:     now,
		createdBy:     createdBy,
	}, nil
}

// ReconstituteAssignmentRule recreates an AssignmentRule from persistence.
func ReconstituteAssignmentRule(
	id shared.ID,
	tenantID shared.ID,
	name, description string,
	priority int,
	isActive bool,
	conditions AssignmentConditions,
	targetGroupID shared.ID,
	options AssignmentOptions,
	createdAt, updatedAt time.Time,
	createdBy *shared.ID,
) *AssignmentRule {
	return &AssignmentRule{
		id:            id,
		tenantID:      tenantID,
		name:          name,
		description:   description,
		priority:      priority,
		isActive:      isActive,
		conditions:    conditions,
		targetGroupID: targetGroupID,
		options:       options,
		createdAt:     createdAt,
		updatedAt:     updatedAt,
		createdBy:     createdBy,
	}
}

// ID returns the rule ID.
func (r *AssignmentRule) ID() shared.ID {
	return r.id
}

// TenantID returns the tenant ID.
func (r *AssignmentRule) TenantID() shared.ID {
	return r.tenantID
}

// Name returns the rule name.
func (r *AssignmentRule) Name() string {
	return r.name
}

// Description returns the rule description.
func (r *AssignmentRule) Description() string {
	return r.description
}

// Priority returns the rule priority (higher = evaluated first).
func (r *AssignmentRule) Priority() int {
	return r.priority
}

// IsActive returns whether the rule is active.
func (r *AssignmentRule) IsActive() bool {
	return r.isActive
}

// Conditions returns the matching conditions.
func (r *AssignmentRule) Conditions() AssignmentConditions {
	return r.conditions
}

// TargetGroupID returns the target group ID.
func (r *AssignmentRule) TargetGroupID() shared.ID {
	return r.targetGroupID
}

// Options returns the rule options.
func (r *AssignmentRule) Options() AssignmentOptions {
	return r.options
}

// CreatedAt returns the creation timestamp.
func (r *AssignmentRule) CreatedAt() time.Time {
	return r.createdAt
}

// UpdatedAt returns the last update timestamp.
func (r *AssignmentRule) UpdatedAt() time.Time {
	return r.updatedAt
}

// CreatedBy returns who created this rule.
func (r *AssignmentRule) CreatedBy() *shared.ID {
	return r.createdBy
}

// UpdateName updates the rule name.
func (r *AssignmentRule) UpdateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	r.name = name
	r.updatedAt = time.Now().UTC()
	return nil
}

// UpdateDescription updates the rule description.
func (r *AssignmentRule) UpdateDescription(description string) {
	r.description = description
	r.updatedAt = time.Now().UTC()
}

// UpdatePriority updates the rule priority.
func (r *AssignmentRule) UpdatePriority(priority int) {
	r.priority = priority
	r.updatedAt = time.Now().UTC()
}

// UpdateConditions updates the matching conditions.
func (r *AssignmentRule) UpdateConditions(conditions AssignmentConditions) {
	r.conditions = conditions
	r.updatedAt = time.Now().UTC()
}

// UpdateTargetGroup updates the target group.
func (r *AssignmentRule) UpdateTargetGroup(targetGroupID shared.ID) error {
	if targetGroupID.IsZero() {
		return fmt.Errorf("%w: targetGroupID is required", shared.ErrValidation)
	}
	r.targetGroupID = targetGroupID
	r.updatedAt = time.Now().UTC()
	return nil
}

// UpdateOptions updates the rule options.
func (r *AssignmentRule) UpdateOptions(options AssignmentOptions) {
	r.options = options
	r.updatedAt = time.Now().UTC()
}

// Activate activates the rule.
func (r *AssignmentRule) Activate() {
	r.isActive = true
	r.updatedAt = time.Now().UTC()
}

// Deactivate deactivates the rule.
func (r *AssignmentRule) Deactivate() {
	r.isActive = false
	r.updatedAt = time.Now().UTC()
}
