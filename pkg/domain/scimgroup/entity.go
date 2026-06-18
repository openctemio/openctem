// Package scimgroup is the domain model for SCIM 2.0 Groups (RFC-009 Phase 9c):
// IdP-pushed groups whose membership drives a user's tenant role.
package scimgroup

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
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
	SetMembers(ctx context.Context, groupID shared.ID, userIDs []shared.ID) error
	// AddMembers / RemoveMembers apply incremental PATCH changes.
	AddMembers(ctx context.Context, groupID shared.ID, userIDs []shared.ID) error
	RemoveMembers(ctx context.Context, groupID shared.ID, userIDs []shared.ID) error
	// RoleGroupNamesForUser returns the display names of the groups a user
	// belongs to in a tenant, used to reconcile their effective role.
	RoleGroupNamesForUser(ctx context.Context, tenantID, userID shared.ID) ([]string, error)
}
