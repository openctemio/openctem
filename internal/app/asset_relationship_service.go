package app

import (
	"context"
	"errors"
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

// =============================================================================
// Batch creation
// =============================================================================

// BatchCreateRelationshipInput is the per-item payload for the batch
// create endpoint. The TenantID and SourceAssetID are NOT here — the
// service takes them once for the whole batch and reuses for every
// item, which is the entire point of the batch endpoint.
type BatchCreateRelationshipInput struct {
	TargetAssetID   string   `validate:"required,uuid"`
	Type            string   `validate:"required"`
	Description     string   `validate:"max=1000"`
	Confidence      string   `validate:"omitempty"`
	DiscoveryMethod string   `validate:"omitempty"`
	ImpactWeight    *int     `validate:"omitempty,min=1,max=10"`
	Tags            []string `validate:"omitempty,max=20,dive,max=50"`
}

// BatchCreateRelationshipResultStatus enumerates the possible outcomes
// for one item in a batch create call.
type BatchCreateRelationshipResultStatus string

const (
	BatchCreateStatusCreated   BatchCreateRelationshipResultStatus = "created"
	BatchCreateStatusDuplicate BatchCreateRelationshipResultStatus = "duplicate"
	BatchCreateStatusError     BatchCreateRelationshipResultStatus = "error"
)

// BatchCreateRelationshipResultItem is one slot in the batch response.
// `Index` matches the position of the corresponding input in the
// request, so the frontend can map results back to target names
// without re-fetching anything.
type BatchCreateRelationshipResultItem struct {
	Index          int                                  `json:"index"`
	Status         BatchCreateRelationshipResultStatus  `json:"status"`
	TargetAssetID  string                               `json:"target_asset_id"`
	RelationshipID string                               `json:"relationship_id,omitempty"`
	Error          string                               `json:"error,omitempty"`
}

// BatchCreateRelationshipResult is the aggregate response.
type BatchCreateRelationshipResult struct {
	Results    []BatchCreateRelationshipResultItem `json:"results"`
	CreatedN   int                                 `json:"created"`
	DuplicateN int                                 `json:"duplicates"`
	ErrorN     int                                 `json:"errors"`
	TotalN     int                                 `json:"total"`
}

// CreateRelationshipBatch creates many relationships from one source
// asset in a single call. The source asset and tenant are validated
// ONCE for the whole batch (instead of per-item like the singleton
// CreateRelationship), and each item's outcome is reported separately
// so the caller can produce a per-target success/failure UI.
//
// Semantics intentionally match Promise.allSettled on the frontend:
// a per-item failure does NOT abort the rest of the batch. The whole
// thing returns 200 with a results array even if every item failed —
// the caller decides what to do based on the per-item statuses.
//
// This is what the frontend Add Relationship dialog calls when the
// user multi-selects targets. It replaces the previous N parallel
// POSTs at the cost of one slightly bigger response.
func (s *AssetRelationshipService) CreateRelationshipBatch(
	ctx context.Context,
	tenantID, sourceAssetID string,
	items []BatchCreateRelationshipInput,
) (*BatchCreateRelationshipResult, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	parsedSourceID, err := shared.IDFromString(sourceAssetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source asset ID", shared.ErrValidation)
	}

	// Validate the source asset ONCE for the whole batch — every item
	// shares it. This is the primary efficiency win vs N singleton calls.
	if _, err := s.assetRepo.GetByID(ctx, parsedTenantID, parsedSourceID); err != nil {
		return nil, fmt.Errorf("source asset: %w", err)
	}

	result := &BatchCreateRelationshipResult{
		Results: make([]BatchCreateRelationshipResultItem, 0, len(items)),
		TotalN:  len(items),
	}

	for i, item := range items {
		entry := BatchCreateRelationshipResultItem{
			Index:         i,
			TargetAssetID: item.TargetAssetID,
		}

		// Per-item failure paths bail out via this closure so we can
		// keep the loop body flat. Each `fail` updates the entry and
		// appends — we never `continue` past it.
		fail := func(status BatchCreateRelationshipResultStatus, msg string) {
			entry.Status = status
			entry.Error = msg
			result.Results = append(result.Results, entry)
			switch status {
			case BatchCreateStatusDuplicate:
				result.DuplicateN++
			case BatchCreateStatusError:
				result.ErrorN++
			}
		}

		// Parse + validate target ID
		parsedTargetID, perr := shared.IDFromString(item.TargetAssetID)
		if perr != nil {
			fail(BatchCreateStatusError, "invalid target asset ID")
			continue
		}

		// Validate relationship type
		relType, perr := asset.ParseRelationshipType(item.Type)
		if perr != nil {
			fail(BatchCreateStatusError, perr.Error())
			continue
		}

		// Verify the target asset belongs to the tenant
		if _, gerr := s.assetRepo.GetByID(ctx, parsedTenantID, parsedTargetID); gerr != nil {
			fail(BatchCreateStatusError, "target asset not found")
			continue
		}

		// Placement mutex — same rule the singleton path enforces.
		if relType == asset.RelTypeRunsOn || relType == asset.RelTypeDeployedTo {
			conflictingType := asset.RelTypeDeployedTo
			if relType == asset.RelTypeDeployedTo {
				conflictingType = asset.RelTypeRunsOn
			}
			exists, eerr := s.relRepo.Exists(ctx, parsedTenantID, parsedSourceID, parsedTargetID, conflictingType)
			if eerr != nil {
				fail(BatchCreateStatusError, "failed to check placement mutex")
				continue
			}
			if exists {
				fail(BatchCreateStatusDuplicate,
					fmt.Sprintf("a %q relationship already exists between these assets", conflictingType))
				continue
			}
		}

		// Build the domain entity
		rel, nerr := asset.NewRelationship(parsedTenantID, parsedSourceID, parsedTargetID, relType)
		if nerr != nil {
			fail(BatchCreateStatusError, nerr.Error())
			continue
		}
		if item.Description != "" {
			rel.SetDescription(item.Description)
		}
		if item.Confidence != "" {
			confidence, cerr := asset.ParseRelationshipConfidence(item.Confidence)
			if cerr != nil {
				fail(BatchCreateStatusError, cerr.Error())
				continue
			}
			_ = rel.SetConfidence(confidence)
		}
		if item.DiscoveryMethod != "" {
			method, mderr := asset.ParseRelationshipDiscoveryMethod(item.DiscoveryMethod)
			if mderr != nil {
				fail(BatchCreateStatusError, mderr.Error())
				continue
			}
			_ = rel.SetDiscoveryMethod(method)
		}
		if item.ImpactWeight != nil {
			if iwerr := rel.SetImpactWeight(*item.ImpactWeight); iwerr != nil {
				fail(BatchCreateStatusError, iwerr.Error())
				continue
			}
		}
		if item.Tags != nil {
			rel.SetTags(item.Tags)
		}

		// Persist. Map the unique-violation error to a duplicate
		// status so the user sees "already related" not "internal
		// error" when picking a pair that's already in the table.
		if perr := s.relRepo.Create(ctx, rel); perr != nil {
			if errors.Is(perr, shared.ErrAlreadyExists) {
				fail(BatchCreateStatusDuplicate, "a relationship of this type already exists between these assets")
				continue
			}
			fail(BatchCreateStatusError, perr.Error())
			continue
		}

		entry.Status = BatchCreateStatusCreated
		entry.RelationshipID = rel.ID().String()
		result.Results = append(result.Results, entry)
		result.CreatedN++
	}

	return result, nil
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

	// Placement mutex: `runs_on` and `deployed_to` describe overlapping
	// concepts ("where this thing lives") so we forbid both existing for
	// the same source/target pair. The UI constraint table also enforces
	// this client-side, but agents and ingest pipelines bypass that path
	// — this is the authoritative check.
	//
	// We only run this check when the requested type is one half of the
	// pair; for every other relationship type the loop below is skipped.
	if relType == asset.RelTypeRunsOn || relType == asset.RelTypeDeployedTo {
		var conflictingType asset.RelationshipType
		if relType == asset.RelTypeRunsOn {
			conflictingType = asset.RelTypeDeployedTo
		} else {
			conflictingType = asset.RelTypeRunsOn
		}
		exists, existsErr := s.relRepo.Exists(ctx, tenantID, sourceID, targetID, conflictingType)
		if existsErr != nil {
			return nil, fmt.Errorf("failed to check placement mutex: %w", existsErr)
		}
		if exists {
			return nil, fmt.Errorf(
				"%w: a %q relationship already exists between these assets — runs_on and deployed_to are mutually exclusive for the same source/target pair",
				shared.ErrAlreadyExists,
				conflictingType,
			)
		}
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

// RelationshipTypeUsage holds usage stats for a single relationship type.
type RelationshipTypeUsage struct {
	ID          string `json:"id"`
	Direct      string `json:"direct"`
	Inverse     string `json:"inverse"`
	Description string `json:"description"`
	Category    string `json:"category"`
	// Count is the number of relationships of this type that exist
	// for the tenant. 0 means the type is registered but unused —
	// a candidate for removal from the registry.
	Count int64 `json:"count"`
}

// GetRelationshipTypeUsage returns counts per relationship type for a
// tenant joined with the metadata from the generated registry. The
// result includes EVERY registered type (zero-count entries are
// preserved) so admins can see which types are unused and prune the
// registry based on real data instead of guessing.
func (s *AssetRelationshipService) GetRelationshipTypeUsage(
	ctx context.Context,
	tenantID string,
) ([]RelationshipTypeUsage, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	counts, err := s.relRepo.CountByType(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("count relationships by type: %w", err)
	}

	// Walk every type in the registry so unused types appear with
	// count=0. The order is the YAML declaration order which keeps
	// the response stable across calls.
	out := make([]RelationshipTypeUsage, 0, len(asset.AllRelationshipTypes()))
	for _, t := range asset.AllRelationshipTypes() {
		meta, ok := asset.RelationshipTypeRegistry[t]
		if !ok {
			continue
		}
		out = append(out, RelationshipTypeUsage{
			ID:          string(t),
			Direct:      meta.Direct,
			Inverse:     meta.Inverse,
			Description: meta.Description,
			Category:    meta.Category,
			Count:       counts[t],
		})
	}
	return out, nil
}
