package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AssetRelationshipService handles relationship business logic.
type AssetRelationshipService struct {
	relRepo   asset.RelationshipRepository
	assetRepo asset.Repository
	logger    *logger.Logger
}

// NewAssetRelationshipService creates a new AssetRelationshipService.
func NewAssetRelationshipService(
	relRepo asset.RelationshipRepository,
	assetRepo asset.Repository,
	log *logger.Logger,
) *AssetRelationshipService {
	return &AssetRelationshipService{
		relRepo:   relRepo,
		assetRepo: assetRepo,
		logger:    log.With("service", "asset_relationship"),
	}
}

// CreateRelationshipInput represents the input for creating a relationship.
type CreateRelationshipInput struct {
	TenantID        string   `validate:"required,uuid"`
	SourceAssetID   string   `validate:"required,uuid"`
	TargetAssetID   string   `validate:"required,uuid"`
	Type            string   `validate:"required"`
	Description     string   `validate:"max=1000"`
	Confidence      string   `validate:"omitempty"`
	DiscoveryMethod string   `validate:"omitempty"`
	ImpactWeight    *int     `validate:"omitempty,min=1,max=10"`
	Tags            []string `validate:"omitempty,max=20,dive,max=50"`
}

// UpdateRelationshipInput represents the input for updating a relationship.
type UpdateRelationshipInput struct {
	Description  *string  `json:"description" validate:"omitempty,max=1000"`
	Confidence   *string  `json:"confidence" validate:"omitempty"`
	ImpactWeight *int     `json:"impact_weight" validate:"omitempty,min=1,max=10"`
	Tags         []string `json:"tags" validate:"omitempty,max=20,dive,max=50"`
	MarkVerified bool     `json:"mark_verified"`
}

// CreateRelationship creates a new relationship between two assets.
func (s *AssetRelationshipService) CreateRelationship(ctx context.Context, input CreateRelationshipInput) (*asset.RelationshipWithAssets, error) {
	s.logger.Info("creating relationship", "source", input.SourceAssetID, "target", input.TargetAssetID, "type", input.Type)

	// Parse IDs
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	sourceID, err := shared.IDFromString(input.SourceAssetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source asset ID", shared.ErrValidation)
	}
	targetID, err := shared.IDFromString(input.TargetAssetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid target asset ID", shared.ErrValidation)
	}

	// Parse relationship type
	relType, err := asset.ParseRelationshipType(input.Type)
	if err != nil {
		return nil, err
	}

	// Validate both assets exist and belong to same tenant
	if _, err := s.assetRepo.GetByID(ctx, tenantID, sourceID); err != nil {
		return nil, fmt.Errorf("source asset: %w", err)
	}
	if _, err := s.assetRepo.GetByID(ctx, tenantID, targetID); err != nil {
		return nil, fmt.Errorf("target asset: %w", err)
	}

	// Create domain entity
	rel, err := asset.NewRelationship(tenantID, sourceID, targetID, relType)
	if err != nil {
		return nil, err
	}

	// Set optional fields
	if input.Description != "" {
		rel.SetDescription(input.Description)
	}
	if input.Confidence != "" {
		confidence, err := asset.ParseRelationshipConfidence(input.Confidence)
		if err != nil {
			return nil, err
		}
		_ = rel.SetConfidence(confidence)
	}
	if input.DiscoveryMethod != "" {
		method, err := asset.ParseRelationshipDiscoveryMethod(input.DiscoveryMethod)
		if err != nil {
			return nil, err
		}
		_ = rel.SetDiscoveryMethod(method)
	}
	if input.ImpactWeight != nil {
		if err := rel.SetImpactWeight(*input.ImpactWeight); err != nil {
			return nil, err
		}
	}
	if input.Tags != nil {
		rel.SetTags(input.Tags)
	}

	// Persist
	if err := s.relRepo.Create(ctx, rel); err != nil {
		return nil, fmt.Errorf("failed to create relationship: %w", err)
	}

	// Fetch full data with asset names
	result, err := s.relRepo.GetByID(ctx, tenantID, rel.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch created relationship: %w", err)
	}

	s.logger.Info("relationship created", "id", rel.ID().String())
	return result, nil
}

// GetRelationship retrieves a relationship by ID.
func (s *AssetRelationshipService) GetRelationship(ctx context.Context, tenantID, relationshipID string) (*asset.RelationshipWithAssets, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(relationshipID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	return s.relRepo.GetByID(ctx, parsedTenantID, parsedID)
}

// UpdateRelationship updates a relationship's mutable fields.
func (s *AssetRelationshipService) UpdateRelationship(ctx context.Context, tenantID, relationshipID string, input UpdateRelationshipInput) (*asset.RelationshipWithAssets, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(relationshipID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	// Fetch existing
	existing, err := s.relRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}
	rel := existing.Relationship

	// Apply updates
	if input.Description != nil {
		rel.SetDescription(*input.Description)
	}
	if input.Confidence != nil {
		confidence, err := asset.ParseRelationshipConfidence(*input.Confidence)
		if err != nil {
			return nil, err
		}
		if err := rel.SetConfidence(confidence); err != nil {
			return nil, err
		}
	}
	if input.ImpactWeight != nil {
		if err := rel.SetImpactWeight(*input.ImpactWeight); err != nil {
			return nil, err
		}
	}
	if input.Tags != nil {
		rel.SetTags(input.Tags)
	}
	if input.MarkVerified {
		rel.Verify()
	}

	// Persist
	if err := s.relRepo.Update(ctx, rel); err != nil {
		return nil, fmt.Errorf("failed to update relationship: %w", err)
	}

	// Re-fetch to get updated data
	return s.relRepo.GetByID(ctx, parsedTenantID, parsedID)
}

// DeleteRelationship removes a relationship.
func (s *AssetRelationshipService) DeleteRelationship(ctx context.Context, tenantID, relationshipID string) error {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(relationshipID)
	if err != nil {
		return shared.ErrNotFound
	}

	return s.relRepo.Delete(ctx, parsedTenantID, parsedID)
}

// ListAssetRelationships lists all relationships for an asset.
func (s *AssetRelationshipService) ListAssetRelationships(
	ctx context.Context,
	tenantID, assetID string,
	filter asset.RelationshipFilter,
) ([]*asset.RelationshipWithAssets, int64, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	parsedAssetID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, 0, shared.ErrNotFound
	}

	return s.relRepo.ListByAsset(ctx, parsedTenantID, parsedAssetID, filter)
}
