// Package scimgroup is the domain model for SCIM 2.0 Groups (RFC-009 Phase 9c):
// IdP-pushed groups whose membership drives a user's tenant role.
package scimgroup

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrNotFound is returned when no group matches the lookup.
var ErrNotFound = errors.New("scim group not found")

// ScimGroup is an IdP-provisioned group within a tenant.
type ScimGroup struct {
	id          shared.ID
	tenantID    shared.ID
	displayName string
	externalID  string
	members     []shared.ID // user IDs
	createdAt   time.Time
	updatedAt   time.Time
}

// New creates a group.
func New(id, tenantID shared.ID, displayName, externalID string, members []shared.ID) *ScimGroup {
	now := time.Now().UTC()
	return &ScimGroup{
		id:          id,
		tenantID:    tenantID,
		displayName: displayName,
		externalID:  externalID,
		members:     members,
		createdAt:   now,
		updatedAt:   now,
	}
}

// Reconstruct rebuilds a group from persistence.
func Reconstruct(id, tenantID shared.ID, displayName, externalID string, members []shared.ID, createdAt, updatedAt time.Time) *ScimGroup {
	return &ScimGroup{
		id:          id,
		tenantID:    tenantID,
		displayName: displayName,
		externalID:  externalID,
		members:     members,
		createdAt:   createdAt,
		updatedAt:   updatedAt,
	}
}

func (g *ScimGroup) ID() shared.ID            { return g.id }
func (g *ScimGroup) TenantID() shared.ID      { return g.tenantID }
func (g *ScimGroup) DisplayName() string      { return g.displayName }
func (g *ScimGroup) ExternalID() string       { return g.externalID }
func (g *ScimGroup) Members() []shared.ID     { return g.members }
func (g *ScimGroup) CreatedAt() time.Time     { return g.createdAt }
func (g *ScimGroup) UpdatedAt() time.Time     { return g.updatedAt }
func (g *ScimGroup) SetDisplayName(n string)  { g.displayName = n }
func (g *ScimGroup) SetMembers(m []shared.ID) { g.members = m }

// Repository persists SCIM groups + their membership.
type Repository interface {
	Create(ctx context.Context, g *ScimGroup) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*ScimGroup, error)
	ListByTenant(ctx context.Context, tenantID shared.ID) ([]*ScimGroup, error)
	UpdateDisplayName(ctx context.Context, tenantID, id shared.ID, displayName string) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	// SetMembers replaces the group's full membership.
	// All three act only on a group of tenantID; another tenant's group is
	// ErrNotFound (SetMembers) or a no-op (Add/Remove).
	SetMembers(ctx context.Context, tenantID, groupID shared.ID, userIDs []shared.ID) error
	// AddMembers / RemoveMembers apply incremental PATCH changes.
	AddMembers(ctx context.Context, tenantID, groupID shared.ID, userIDs []shared.ID) error
	RemoveMembers(ctx context.Context, tenantID, groupID shared.ID, userIDs []shared.ID) error
	// RoleGroupNamesForUser returns the display names of the groups a user
	// belongs to in a tenant, used to reconcile their effective role.
	RoleGroupNamesForUser(ctx context.Context, tenantID, userID shared.ID) ([]string, error)

	// GetRoleMappings returns the tenant's group-name → role overrides, keyed by
	// lowercased group display name, with who configured each.
	GetRoleMappings(ctx context.Context, tenantID shared.ID) (map[string]RoleMapping, error)
	// ReplaceRoleMappings replaces the tenant's group-name → role overrides with
	// what plan returns. plan runs inside the write transaction, under a
	// per-tenant lock, on the mappings as they are now, so a check it makes
	// (for example "only the owner may change an admin mapping") cannot be
	// raced by a concurrent save. An error from plan aborts the write.
	ReplaceRoleMappings(ctx context.Context, tenantID shared.ID, plan RoleMappingPlan) error
}

// RoleMapping is one SCIM group-name → tenant role override and who set it.
type RoleMapping struct {
	Role string
	// ConfiguredBy is the user who last set this mapping; nil for a mapping
	// that predates provenance (migration 000911) or whose user was deleted.
	ConfiguredBy *shared.ID
	// ConfiguredByOwner is true when ConfiguredBy was the organization's owner
	// when they set it. Only such an admin mapping may grant or remove the
	// admin role through SCIM.
	ConfiguredByOwner bool
}

// RoleMappingPlan computes the new mapping set from the current one.
type RoleMappingPlan func(current map[string]RoleMapping) (map[string]RoleMapping, error)
