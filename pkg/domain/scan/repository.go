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

	// CountScheduledWithoutNextRun counts active scans that carry a real
	// schedule but no next_run_at.
	//
	// ListDueForExecution requires next_run_at IS NOT NULL, so such a scan is
	// invisible to the scheduler forever while still presenting itself as
	// "daily" or "weekly" everywhere a human looks. Counting them is what turns
	// that from a silent state into a reportable one.
	CountScheduledWithoutNextRun(ctx context.Context) (int, []string, error)

	// UpdateNextRunAt updates the next run time for a scan.
	UpdateNextRunAt(ctx context.Context, id shared.ID, nextRunAt *time.Time) error

	// RecordRun records a run result for a scan.
	RecordRun(ctx context.Context, id shared.ID, runID shared.ID, status string) error

	// RecordTriggerFailure records that a scheduled trigger failed BEFORE any
	// run was created (e.g. no agent available). It sets last_run_at/last_run_status
	// so the failure is visible in the scan's own state — the scheduler advances
	// next_run_at regardless (to avoid re-trigger storms), which otherwise makes a
	// scan that can never start look identical to one that simply hasn't run yet.
	// Deliberately does NOT touch the run counters: no run existed, so inflating
	// total_runs would be a second lie on top of the one this fixes.
	RecordTriggerFailure(ctx context.Context, id shared.ID, status string) error

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

	// Distributed Locking (for multi-instance schedulers)

	// TryLockScanForScheduler attempts to acquire a session-level advisory lock
	// for the given scan ID. Returns true if the lock was acquired, false if
	// another instance already holds it. The lock must be released with
	// UnlockScanForScheduler when the trigger completes.
	TryLockScanForScheduler(ctx context.Context, id shared.ID) (bool, error)

	// UnlockScanForScheduler releases a previously acquired scheduler lock for the given scan ID.
	UnlockScanForScheduler(ctx context.Context, id shared.ID) error
}
