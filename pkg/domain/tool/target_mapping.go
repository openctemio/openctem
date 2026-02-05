package tool

import (
	"context"
	"slices"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// TargetAssetTypeMapping represents a mapping between a tool's target type
// and an asset type that it can scan.
//
// For example:
//   - target_type="url" -> asset_type="website"
//   - target_type="domain" -> asset_type="domain"
//   - target_type="ip" -> asset_type="ip_address"
type TargetAssetTypeMapping struct {
	ID          shared.ID
	TargetType  string          // e.g., "url", "domain", "ip", "repository"
	AssetType   asset.AssetType // e.g., "website", "domain", "ip_address"
	Priority    int             // Lower = higher priority (10 = primary)
	IsActive    bool
	Description string // Optional description for admin UI
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   *shared.ID // Optional: who created this mapping
}

// IsPrimary returns true if this mapping has primary priority (10).
// Primary mappings are used for reverse lookups (asset_type -> target_type).
func (m *TargetAssetTypeMapping) IsPrimary() bool {
	return m.Priority == 10
}

// SetPrimary sets the mapping as primary (priority = 10) or non-primary (priority = 100).
func (m *TargetAssetTypeMapping) SetPrimary(isPrimary bool) {
	if isPrimary {
		m.Priority = 10
	} else if m.Priority == 10 {
		m.Priority = 100 // Reset to default if was primary
	}
}

// NewTargetAssetTypeMapping creates a new mapping with defaults.
func NewTargetAssetTypeMapping(targetType string, assetType asset.AssetType) *TargetAssetTypeMapping {
	now := time.Now().UTC()
	return &TargetAssetTypeMapping{
		ID:         shared.NewID(),
		TargetType: targetType,
		AssetType:  assetType,
		Priority:   100, // Default priority
		IsActive:   true,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// TargetMappingFilter defines filtering options for target mapping queries.
type TargetMappingFilter struct {
	TargetType  *string  // Filter by specific target type
	AssetType   *string  // Filter by specific asset type
	IsActive    *bool    // Filter by active status
	TargetTypes []string // Filter by multiple target types (IN clause)
	AssetTypes  []string // Filter by multiple asset types (IN clause)
}

// TargetMappingRepository defines the interface for target mapping persistence.
type TargetMappingRepository interface {
	// CRUD operations
	Create(ctx context.Context, mapping *TargetAssetTypeMapping) error
	GetByID(ctx context.Context, id shared.ID) (*TargetAssetTypeMapping, error)
	Update(ctx context.Context, mapping *TargetAssetTypeMapping) error
	Delete(ctx context.Context, id shared.ID) error
	List(ctx context.Context, filter TargetMappingFilter, page pagination.Pagination) (pagination.Result[*TargetAssetTypeMapping], error)

	// Compatibility check methods
	// GetAssetTypesForTargets returns all asset types that can be scanned by the given target types.
	// Example: GetAssetTypesForTargets(["url", "domain"]) -> ["website", "web_application", "domain", "subdomain"]
	GetAssetTypesForTargets(ctx context.Context, targetTypes []string) ([]asset.AssetType, error)

	// GetTargetsForAssetType returns all target types that can scan the given asset type.
	// Example: GetTargetsForAssetType("website") -> ["url"]
	GetTargetsForAssetType(ctx context.Context, assetType asset.AssetType) ([]string, error)

	// CanToolScanAssetType checks if a tool (via its supported_targets) can scan a specific asset type.
	// Returns true if any of the tool's target types map to the asset type.
	CanToolScanAssetType(ctx context.Context, targetTypes []string, assetType asset.AssetType) (bool, error)

	// GetIncompatibleAssetTypes returns asset types from the list that CANNOT be scanned
	// by any of the given target types.
	GetIncompatibleAssetTypes(ctx context.Context, targetTypes []string, assetTypes []asset.AssetType) ([]asset.AssetType, error)

	// GetCompatibleAssetTypes returns asset types from the list that CAN be scanned
	// by at least one of the given target types.
	GetCompatibleAssetTypes(ctx context.Context, targetTypes []string, assetTypes []asset.AssetType) ([]asset.AssetType, error)
}

// CompatibilityResult holds the result of an asset compatibility check.
type CompatibilityResult struct {
	// Compatible asset types (can be scanned)
	CompatibleTypes []asset.AssetType

	// Incompatible asset types (will be skipped)
	IncompatibleTypes []asset.AssetType

	// Total counts
	TotalAssetTypes      int
	CompatibleCount      int
	IncompatibleCount    int
	CompatibilityPercent float64

	// Whether any unclassified assets exist
	HasUnclassified   bool
	UnclassifiedCount int
}

// IsFullyCompatible returns true if all asset types are compatible.
func (r *CompatibilityResult) IsFullyCompatible() bool {
	return r.IncompatibleCount == 0 && r.UnclassifiedCount == 0
}

// IsPartiallyCompatible returns true if some (but not all) asset types are compatible.
func (r *CompatibilityResult) IsPartiallyCompatible() bool {
	return r.CompatibleCount > 0 && (r.IncompatibleCount > 0 || r.UnclassifiedCount > 0)
}

// IsFullyIncompatible returns true if no asset types are compatible.
func (r *CompatibilityResult) IsFullyIncompatible() bool {
	return r.CompatibleCount == 0
}

// ValidTargetTypes defines the allowed target types for security (input validation).
// New target types should be added here after careful consideration.
var ValidTargetTypes = []string{
	"url",
	"domain",
	"ip",
	"host",
	"repository",
	"file",
	"container",
	"kubernetes",
	"cloud_account", // Cloud accounts (AWS, GCP, Azure)
	"compute",       // VMs, instances
	"storage",       // S3, Blob, GCS
	"serverless",    // Lambda, Cloud Functions
	"network",
	"service",
	"port",
	"database",
	"mobile",
	"api",
	"certificate",
}

// IsValidTargetType checks if a target type is in the allowed list.
func IsValidTargetType(targetType string) bool {
	return slices.Contains(ValidTargetTypes, targetType)
}
