package asset

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// RelationshipRepository defines the interface for asset relationship persistence.
type RelationshipRepository interface {
	// Create persists a new relationship.
	Create(ctx context.Context, rel *Relationship) error

	// GetByID retrieves a relationship by ID within a tenant.
	GetByID(ctx context.Context, tenantID, id shared.ID) (*RelationshipWithAssets, error)

	// Update updates an existing relationship.
	Update(ctx context.Context, rel *Relationship) error

	// Delete removes a relationship by ID within a tenant.
	Delete(ctx context.Context, tenantID, id shared.ID) error

	// ListByAsset retrieves all relationships for an asset (both directions).
	ListByAsset(ctx context.Context, tenantID, assetID shared.ID,
		filter RelationshipFilter,
	) ([]*RelationshipWithAssets, int64, error)

	// Exists checks if a specific relationship already exists.
	Exists(ctx context.Context, tenantID, sourceID, targetID shared.ID,
		relType RelationshipType) (bool, error)

	// CountByAsset returns the count of relationships for an asset.
	CountByAsset(ctx context.Context, tenantID, assetID shared.ID) (int64, error)

	// CreateBatchIgnoreConflicts inserts multiple relationships, silently skipping duplicates.
	// Returns the number of relationships actually created (excluding conflicts).
	CreateBatchIgnoreConflicts(ctx context.Context, rels []*Relationship) (int, error)

	// CountByType returns the count of relationships per type for a tenant.
	// Used by the usage-stats endpoint so admins can see which relationship
	// types are actually being used and trim or extend the registry
	// based on real data instead of guessing.
	CountByType(ctx context.Context, tenantID shared.ID) (map[RelationshipType]int64, error)
}

// RelationshipFilter defines filtering options for relationship queries.
type RelationshipFilter struct {
	Types            []RelationshipType
	Confidences      []RelationshipConfidence
	DiscoveryMethods []RelationshipDiscoveryMethod
	Tags             []string
	MinImpactWeight  *int
	MaxImpactWeight  *int
	Direction        string // "outgoing", "incoming", or "" for both
	Page             int
	PerPage          int
}
