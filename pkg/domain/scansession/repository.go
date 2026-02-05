package scansession

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Repository defines the interface for scan session persistence.
type Repository interface {
	// Create creates a new scan session.
	Create(ctx context.Context, session *ScanSession) error

	// GetByID retrieves a scan session by ID.
	GetByID(ctx context.Context, id shared.ID) (*ScanSession, error)

	// GetByTenantAndID retrieves a scan session by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*ScanSession, error)

	// Update updates a scan session.
	Update(ctx context.Context, session *ScanSession) error

	// List lists scan sessions with filtering and pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*ScanSession], error)

	// Delete deletes a scan session by ID.
	Delete(ctx context.Context, id shared.ID) error

	// FindBaseline finds the most recent completed scan for incremental scanning.
	// Returns the baseline commit SHA from the last completed scan on the same branch/asset.
	FindBaseline(ctx context.Context, tenantID shared.ID, assetType, assetValue, branch string) (string, error)

	// GetStats returns scan session statistics for a tenant.
	GetStats(ctx context.Context, tenantID shared.ID, since time.Time) (*Stats, error)

	// ListRunning lists all running scans for a tenant.
	ListRunning(ctx context.Context, tenantID shared.ID) ([]*ScanSession, error)
}

// Filter defines the filter options for listing scan sessions.
type Filter struct {
	TenantID    *shared.ID
	AgentID     *shared.ID
	AssetID     *shared.ID
	ScannerName string
	AssetType   string
	AssetValue  string
	Branch      string
	Status      *Status
	Since       *time.Time
	Until       *time.Time
}

// Stats represents scan session statistics.
type Stats struct {
	Total     int64            `json:"total"`
	Pending   int64            `json:"pending"`
	Running   int64            `json:"running"`
	Completed int64            `json:"completed"`
	Failed    int64            `json:"failed"`
	Canceled  int64            `json:"canceled"`
	ByScanner map[string]int64 `json:"by_scanner"`
	ByAsset   map[string]int64 `json:"by_asset_type"`

	// Findings stats
	TotalFindings    int64 `json:"total_findings"`
	TotalFindingsNew int64 `json:"total_findings_new"`

	// Timing stats
	AvgDurationMs int64 `json:"avg_duration_ms"`
}
