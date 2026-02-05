package asset

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// AssetServiceRepository defines the interface for asset service persistence.
// Services are stored in the `asset_services` table and linked to assets via asset_id.
// This follows the same pattern as RepositoryExtensionRepository (asset_repositories table).
type AssetServiceRepository interface {
	// ==========================================================================
	// Basic CRUD Operations
	// ==========================================================================

	// Create persists a new asset service.
	Create(ctx context.Context, service *AssetService) error

	// GetByID retrieves an asset service by its ID.
	GetByID(ctx context.Context, tenantID, id shared.ID) (*AssetService, error)

	// Update updates an existing asset service.
	Update(ctx context.Context, service *AssetService) error

	// Delete removes an asset service by its ID.
	Delete(ctx context.Context, tenantID, id shared.ID) error

	// ==========================================================================
	// Query Operations
	// ==========================================================================

	// GetByAssetID retrieves all services for an asset.
	GetByAssetID(ctx context.Context, tenantID, assetID shared.ID) ([]*AssetService, error)

	// GetByAssetAndPort retrieves a service by asset ID and port.
	// Used for upsert operations to find existing service.
	GetByAssetAndPort(ctx context.Context, tenantID, assetID shared.ID, port int, protocol Protocol) (*AssetService, error)

	// List retrieves services with filtering and pagination.
	List(ctx context.Context, tenantID shared.ID, opts ListAssetServicesOptions) ([]*AssetService, int, error)

	// ListPublic retrieves all public (internet-exposed) services for a tenant.
	ListPublic(ctx context.Context, tenantID shared.ID, limit, offset int) ([]*AssetService, int, error)

	// ListByServiceType retrieves services of a specific type.
	ListByServiceType(ctx context.Context, tenantID shared.ID, serviceType ServiceType, limit, offset int) ([]*AssetService, int, error)

	// ListHighRisk retrieves services with risk score above threshold.
	ListHighRisk(ctx context.Context, tenantID shared.ID, minRiskScore int, limit, offset int) ([]*AssetService, int, error)

	// ==========================================================================
	// Batch Operations
	// ==========================================================================

	// UpsertBatch creates or updates multiple services in a single operation.
	// Uses PostgreSQL ON CONFLICT (tenant_id, asset_id, port, protocol) for atomic upsert.
	// Returns the number of created and updated services.
	UpsertBatch(ctx context.Context, services []*AssetService) (created int, updated int, err error)

	// DeleteByAssetID removes all services for an asset.
	// Called when asset is deleted (also handled by FK CASCADE).
	DeleteByAssetID(ctx context.Context, tenantID, assetID shared.ID) error

	// UpdateFindingCounts updates finding counts for multiple services.
	// Maps serviceID -> count
	UpdateFindingCounts(ctx context.Context, counts map[shared.ID]int) error

	// ==========================================================================
	// Statistics & Aggregations
	// ==========================================================================

	// CountByTenant returns the total number of services for a tenant.
	CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error)

	// CountByAsset returns the number of services for an asset.
	CountByAsset(ctx context.Context, tenantID, assetID shared.ID) (int, error)

	// CountPublic returns the number of public services for a tenant.
	CountPublic(ctx context.Context, tenantID shared.ID) (int64, error)

	// GetServiceTypeCounts returns count of services grouped by service type.
	GetServiceTypeCounts(ctx context.Context, tenantID shared.ID) (map[ServiceType]int, error)

	// GetPortCounts returns count of services grouped by port (top N).
	GetPortCounts(ctx context.Context, tenantID shared.ID, topN int) (map[int]int, error)

	// ==========================================================================
	// Search Operations
	// ==========================================================================

	// SearchByProduct searches services by product name (partial match).
	SearchByProduct(ctx context.Context, tenantID shared.ID, product string, limit int) ([]*AssetService, error)

	// SearchByVersion searches services by version (partial match).
	// Useful for finding vulnerable versions.
	SearchByVersion(ctx context.Context, tenantID shared.ID, version string, limit int) ([]*AssetService, error)

	// SearchByCPE searches services by CPE (partial match).
	// Used for vulnerability correlation.
	SearchByCPE(ctx context.Context, tenantID shared.ID, cpe string, limit int) ([]*AssetService, error)
}

// AssetServiceWithAsset combines a service with its parent asset information.
// Used for list views that need to show asset context.
type AssetServiceWithAsset struct {
	Service   *AssetService
	AssetName string
	AssetType AssetType
}

// AssetServiceStats contains aggregated statistics for services.
type AssetServiceStats struct {
	TotalServices    int64
	PublicServices   int64
	ActiveServices   int64
	InactiveServices int64
	HighRiskServices int64 // risk_score > 70

	// By Type
	HTTPServices     int64
	DatabaseServices int64
	RemoteAccess     int64

	// Top Ports
	TopPorts []PortCount

	// Top Products
	TopProducts []ProductCount
}

// PortCount represents a port and its count.
type PortCount struct {
	Port  int
	Count int
}

// ProductCount represents a product and its count.
type ProductCount struct {
	Product string
	Count   int
}
