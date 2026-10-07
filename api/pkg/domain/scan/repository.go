package scan

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Filter represents filter options for listing scans.
type Filter struct {
	TenantID       *shared.ID
	AssetGroupID   *shared.ID
	ScanWorkflowID *shared.ID
	ScanType       *ScanType
	ScheduleType   *ScheduleType
	Status         *Status
	Tags           []string
	Search         string
	// Archived scans (never-run one-off scans the archive job retired) are
	// left out of every list.
	//
	// ExcludeAdHoc leaves out quick scans that were never saved (Scan.AdHoc):
	// the Configurations list shows saved configurations only.
	ExcludeAdHoc bool
	// Sort orders the list; the zero value is by name.
	Sort ListSort
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
	ScanRuns StatusCounts `json:"scan_runs"`
	Scans    StatusCounts `json:"scans"`
	Jobs     StatusCounts `json:"jobs"`
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

	// GetByTenantAndID retrieves a scan by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Scan, error)

	// GetByName retrieves a scan by tenant and name.
	GetByName(ctx context.Context, tenantID shared.ID, name string) (*Scan, error)

	// List lists scans with filters and pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*Scan], error)

	// Update updates a scan.
	Update(ctx context.Context, scan *Scan) error

	// Delete deletes a scan of tenantID. A scan of another tenant is
	// shared.ErrNotFound.
	Delete(ctx context.Context, tenantID, id shared.ID) error

	// Scheduling

	// ListDueForExecution lists scans that are due for scheduled execution.
	ListDueForExecution(ctx context.Context, now time.Time) ([]*Scan, error)

	// CountScheduledWithoutNextRun counts active scans that carry a real
	// schedule but no next_run_at.
	//
	// ListDueForExecution requires next_run_at IS NOT NULL, so such a scan is
	// invisible to the scheduler forever while still presenting itself as
	// "daily" or "weekly" everywhere a human looks. Counting them is what turns
	// that from a silent state into a reportable one.
	CountScheduledWithoutNextRun(ctx context.Context) (int, []string, error)

	// UpdateNextRunAt updates the next run time for a scan.
	UpdateNextRunAt(ctx context.Context, tenantID, id shared.ID, nextRunAt *time.Time) error

	// RefreshRunSummary recomputes the scan's last run and run counters from
	// its runs (scan_runs), the one source of both. Called after any
	// change to one of its runs.
	RefreshRunSummary(ctx context.Context, tenantID, id shared.ID) error

	// Statistics

	// GetStats returns aggregated statistics for scans.
	GetStats(ctx context.Context, tenantID shared.ID) (*Stats, error)

	// Count counts scans matching the filter.
	Count(ctx context.Context, filter Filter) (int64, error)

	// Bulk Operations

	// ListByAssetGroupID lists all scans for an asset group.
	ListByAssetGroupID(ctx context.Context, assetGroupID shared.ID) ([]*Scan, error)

	// ListByScanWorkflowID lists all scans using a scan workflow.
	ListByScanWorkflowID(ctx context.Context, scanWorkflowID shared.ID) ([]*Scan, error)

	// UpdateStatusByAssetGroupID updates status for all scans in an asset group.
	UpdateStatusByAssetGroupID(ctx context.Context, assetGroupID shared.ID, status Status) error

	// Distributed Locking (for multi-instance schedulers)

	// ClaimScheduledRun atomically moves next_run_at from dueAt to next if it
	// still equals dueAt and the scan is active. It returns true for exactly
	// one caller per due occurrence, across replicas.
	ClaimScheduledRun(ctx context.Context, tenantID, id shared.ID, dueAt time.Time, next *time.Time) (bool, error)
}

// ArchivedScan is a one-off scan the archive job archived.
type ArchivedScan struct {
	TenantID shared.ID
	ID       shared.ID
	Name     string
}
