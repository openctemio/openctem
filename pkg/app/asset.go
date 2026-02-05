package app

import (
	"context"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// CreateAssetInput represents the input for creating an asset.
type CreateAssetInput struct {
	TenantID    string   `json:"tenant_id" validate:"omitempty,uuid"`
	Name        string   `json:"name" validate:"required,min=1,max=255"`
	Type        string   `json:"type" validate:"required,asset_type"`
	Criticality string   `json:"criticality" validate:"required,criticality"`
	Scope       string   `json:"scope" validate:"omitempty,scope"`
	Exposure    string   `json:"exposure" validate:"omitempty,exposure"`
	Description string   `json:"description" validate:"max=1000"`
	Tags        []string `json:"tags" validate:"max=20,dive,max=50"`
}

// UpdateAssetInput represents the input for updating an asset.
type UpdateAssetInput struct {
	TenantID    string    `json:"tenant_id" validate:"required,uuid"`
	ID          string    `json:"id" validate:"required,uuid"`
	Name        *string   `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Criticality *string   `json:"criticality,omitempty" validate:"omitempty,criticality"`
	Scope       *string   `json:"scope,omitempty" validate:"omitempty,scope"`
	Exposure    *string   `json:"exposure,omitempty" validate:"omitempty,exposure"`
	Description *string   `json:"description,omitempty" validate:"omitempty,max=1000"`
	Tags        *[]string `json:"tags,omitempty" validate:"omitempty,max=20,dive,max=50"`
	Status      *string   `json:"status,omitempty" validate:"omitempty,asset_status"`
}

// ListAssetsFilter represents filters for listing assets.
type ListAssetsFilter struct {
	TenantID    string   `json:"tenant_id"`
	Search      string   `json:"search"`
	Types       []string `json:"types"`
	Criticality []string `json:"criticality"`
	Status      []string `json:"status"`
	Scope       []string `json:"scope"`
	Exposure    []string `json:"exposure"`
	GroupIDs    []string `json:"group_ids"`
	Tags        []string `json:"tags"`
	Page        int      `json:"page"`
	PerPage     int      `json:"per_page"`
	SortBy      string   `json:"sort_by"`
	SortOrder   string   `json:"sort_order"`
}

// AssetService defines the interface for asset operations.
// Implementations:
//   - OSS: internal/app.AssetService (direct)
//   - Enterprise: enterprise/app.AssetServiceWithRBAC (wrapped)
type AssetService interface {
	// Create creates a new asset.
	Create(ctx context.Context, input CreateAssetInput) (*asset.Asset, error)

	// Get retrieves an asset by ID within a tenant.
	// Returns ErrNotFound if asset doesn't exist or belongs to different tenant.
	Get(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error)

	// GetByName retrieves an asset by name within a tenant.
	GetByName(ctx context.Context, tenantID shared.ID, name string) (*asset.Asset, error)

	// List returns paginated assets matching the filter.
	List(ctx context.Context, filter ListAssetsFilter) (*ListResult[*asset.Asset], error)

	// Update updates an existing asset.
	Update(ctx context.Context, input UpdateAssetInput) (*asset.Asset, error)

	// Delete soft-deletes an asset.
	Delete(ctx context.Context, tenantID, assetID shared.ID) error

	// BulkDelete soft-deletes multiple assets.
	BulkDelete(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error

	// UpdateRiskScores recalculates risk scores for assets.
	UpdateRiskScores(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error
}
