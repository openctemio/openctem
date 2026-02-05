package scan

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Filter represents filter options for listing scans.
type Filter struct {
	TenantID     *shared.ID
	AssetGroupID *shared.ID
	PipelineID   *shared.ID
	ScanType     *ScanType
	ScheduleType *ScheduleType
	Status       *Status
	Tags         []string
	Search       string
}

// Stats represents aggregated statistics for scans.
type Stats struct {
	Total          int64                  `json:"total"`
	Active         int64                  `json:"active"`
	Paused         int64                  `json:"paused"`
	Disabled       int64                  `json:"disabled"`
	ByScheduleType map[ScheduleType]int64 `json:"by_schedule_type"`
	ByScanType     map[ScanType]int64     `json:"by_scan_type"`
}

// OverviewStats represents the scan management overview statistics.
type OverviewStats struct {
	Pipelines StatusCounts `json:"pipelines"`
	Scans     StatusCounts `json:"scans"`
	Jobs      StatusCounts `json:"jobs"`
}

// StatusCounts represents counts by status.
type StatusCounts struct {
	Total     int64 `json:"total"`
	Running   int64 `json:"running"`
	Pending   int64 `json:"pending"`
	Completed int64 `json:"completed"`
	Failed    int64 `json:"failed"`
	Canceled  int64 `json:"canceled"`
}

// Repository defines the interface for scan persistence.
type Repository interface {
	// Create creates a new scan.
	Create(ctx context.Context, scan *Scan) error

	// GetByID retrieves a scan by ID.
	GetByID(ctx context.Context, id shared.ID) (*Scan, error)

	// GetByTenantAndID retrieves a scan by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Scan, error)

	// GetByName retrieves a scan by tenant and name.
	GetByName(ctx context.Context, tenantID shared.ID, name string) (*Scan, error)

	// List lists scans with filters and pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*Scan], error)

	// Update updates a scan.
	Update(ctx context.Context, scan *Scan) error

	// Delete deletes a scan.
	Delete(ctx context.Context, id shared.ID) error

	// Scheduling

	// ListDueForExecution lists scans that are due for scheduled execution.
	ListDueForExecution(ctx context.Context, now time.Time) ([]*Scan, error)

	// UpdateNextRunAt updates the next run time for a scan.
	UpdateNextRunAt(ctx context.Context, id shared.ID, nextRunAt *time.Time) error

	// RecordRun records a run result for a scan.
	RecordRun(ctx context.Context, id shared.ID, runID shared.ID, status string) error

	// Statistics

	// GetStats returns aggregated statistics for scans.
	GetStats(ctx context.Context, tenantID shared.ID) (*Stats, error)

	// Count counts scans matching the filter.
	Count(ctx context.Context, filter Filter) (int64, error)

	// Bulk Operations

	// ListByAssetGroupID lists all scans for an asset group.
	ListByAssetGroupID(ctx context.Context, assetGroupID shared.ID) ([]*Scan, error)

	// ListByPipelineID lists all scans using a pipeline.
	ListByPipelineID(ctx context.Context, pipelineID shared.ID) ([]*Scan, error)

	// UpdateStatusByAssetGroupID updates status for all scans in an asset group.
	UpdateStatusByAssetGroupID(ctx context.Context, assetGroupID shared.ID, status Status) error
}
