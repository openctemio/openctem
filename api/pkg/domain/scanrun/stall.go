package scanrun

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// StalledRun names a running workflow run that has steps left to start but
// nothing in flight: no step queued or running and no report of its steps
// still being ingested (research/62 SG-10).
type StalledRun struct {
	TenantID shared.ID
	RunID    shared.ID
}

// StallRepairStore finds the runs a missed wake-up left stalled. Both reads
// span tenants (the repair controller is a system job); every run found is
// then read and advanced in its own tenant.
type StallRepairStore interface {
	// ReleaseOrphanStagePlans deletes stage plans (and their targets) saved
	// before olderThan for a step that is still pending and has no command:
	// the planner stopped between saving the plan and creating the commands.
	// The next advance plans the step again. At most limit plans.
	ReleaseOrphanStagePlans(ctx context.Context, olderThan time.Time, limit int) (int64, error)
	// StalledRuns returns running workflow runs with a pending step, nothing
	// queued, running or being ingested, and no step change since quietSince.
	StalledRuns(ctx context.Context, quietSince time.Time, limit int) ([]StalledRun, error)
}
