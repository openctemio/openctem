package asset

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// StateHistoryRepository defines the interface for asset state history persistence.
// This table is append-only with deletion protection (see migration 000111).
type StateHistoryRepository interface {
	// ==========================================================================
	// Write Operations (Append-only)
	// ==========================================================================

	// Create appends a new state change record.
	// Note: Records cannot be updated or deleted (append-only audit log).
	Create(ctx context.Context, change *AssetStateChange) error

	// CreateBatch appends multiple state change records in a single operation.
	CreateBatch(ctx context.Context, changes []*AssetStateChange) error

	// ==========================================================================
	// Query Operations
	// ==========================================================================

	// GetByID retrieves a state change by its ID.
	GetByID(ctx context.Context, tenantID, id shared.ID) (*AssetStateChange, error)

	// GetByAssetID retrieves all state changes for an asset.
	GetByAssetID(ctx context.Context, tenantID, assetID shared.ID, opts ListStateHistoryOptions) ([]*AssetStateChange, int, error)

	// List retrieves state changes with filtering and pagination.
	List(ctx context.Context, tenantID shared.ID, opts ListStateHistoryOptions) ([]*AssetStateChange, int, error)

	// GetLatestByAsset retrieves the most recent state change for each asset.
	// Useful for getting current state summary across all assets.
	GetLatestByAsset(ctx context.Context, tenantID shared.ID, changeTypes []StateChangeType) (map[shared.ID]*AssetStateChange, error)

	// ==========================================================================
	// Shadow IT Detection Queries
	// ==========================================================================

	// GetRecentAppearances retrieves assets that appeared within the time window.
	// Used for shadow IT detection - finding newly discovered assets.
	GetRecentAppearances(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*AssetStateChange, error)

	// GetRecentDisappearances retrieves assets that disappeared within the time window.
	GetRecentDisappearances(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*AssetStateChange, error)

	// GetShadowITCandidates retrieves assets that appeared but have unknown/shadow scope.
	// These are potential shadow IT assets that need review.
	GetShadowITCandidates(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*AssetStateChange, error)

	// ==========================================================================
	// Exposure Change Queries
	// ==========================================================================

	// GetExposureChanges retrieves all exposure-related changes within a time window.
	GetExposureChanges(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*AssetStateChange, error)

	// GetNewlyExposedAssets retrieves assets that became internet-accessible.
	// High priority for security review.
	GetNewlyExposedAssets(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*AssetStateChange, error)

	// ==========================================================================
	// Compliance Audit Queries
	// ==========================================================================

	// GetComplianceChanges retrieves compliance-related changes within a time window.
	GetComplianceChanges(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*AssetStateChange, error)

	// GetChangesByUser retrieves all changes made by a specific user.
	// Used for compliance auditing.
	GetChangesByUser(ctx context.Context, tenantID, userID shared.ID, opts ListStateHistoryOptions) ([]*AssetStateChange, int, error)

	// ==========================================================================
	// Statistics
	// ==========================================================================

	// CountByType returns count of changes grouped by change type.
	CountByType(ctx context.Context, tenantID shared.ID, since time.Time) (map[StateChangeType]int, error)

	// CountBySource returns count of changes grouped by source.
	CountBySource(ctx context.Context, tenantID shared.ID, since time.Time) (map[ChangeSource]int, error)

	// GetActivityTimeline returns daily counts of changes over a time period.
	// Used for activity trend visualization.
	GetActivityTimeline(ctx context.Context, tenantID shared.ID, from, to time.Time) ([]DailyActivityCount, error)
}

// DailyActivityCount represents activity count for a single day.
type DailyActivityCount struct {
	Date           time.Time
	Appeared       int
	Disappeared    int
	Recovered      int
	ExposureChange int
	OtherChanges   int
	Total          int
}

// StateHistorySummary provides a summary of state history for an asset.
type StateHistorySummary struct {
	AssetID          shared.ID
	FirstSeenAt      *time.Time // When asset first appeared
	LastSeenAt       *time.Time // When asset was last seen active
	DisappearedAt    *time.Time // When asset last disappeared (if currently gone)
	TotalAppearances int        // How many times asset appeared
	TotalChanges     int        // Total number of state changes
	LastChangeAt     *time.Time // Most recent change timestamp
	LastChangeType   StateChangeType
}
