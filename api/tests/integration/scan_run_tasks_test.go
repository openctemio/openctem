package integration

import (
	"context"
	"errors"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The runs page reads a run's tasks (RFC-046 §4.1): the commands its trigger
// dispatched. Another tenant cannot read the run, and so not its tasks.
func TestScanRun_TasksOfATriggeredRun(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)
	pipeSvc := newRecordingPipelineService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)
	stranger := seedLifecycleTenant(ctx, t, db)

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantID.String(), ScanID: scanID.String()})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	got, err := pipeSvc.GetRunWithStepsForTenant(ctx, tenantID.String(), run.ID.String())
	if err != nil {
		t.Fatalf("GetRunWithStepsForTenant: %v", err)
	}
	tasks, err := pipeSvc.GetRunTasks(ctx, got)
	if err != nil || tasks == nil {
		t.Fatalf("GetRunTasks = %+v, %v", tasks, err)
	}
	if tasks.Summary.Total != 1 || tasks.Summary.Queued != 1 || len(tasks.Items) != 1 || tasks.Truncated {
		t.Fatalf("tasks = %+v, want the one queued command", tasks)
	}
	if tasks.Items[0].Status != pipeline.TaskStatusQueued || tasks.Items[0].Targets < 1 {
		t.Fatalf("task = %+v", tasks.Items[0])
	}

	sums, err := pipeSvc.RunTaskSummaries(ctx, tenantID.String(), []*pipeline.Run{got})
	if err != nil || sums[run.ID].Total != 1 {
		t.Fatalf("RunTaskSummaries = %+v, %v", sums, err)
	}
	if sums, err := pipeSvc.RunTaskSummaries(ctx, stranger.String(), []*pipeline.Run{got}); err != nil || len(sums) != 0 {
		t.Fatalf("stranger summaries = %+v, %v; want none", sums, err)
	}

	if _, err := pipeSvc.GetRunWithStepsForTenant(ctx, stranger.String(), run.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read err = %v, want not found", err)
	}
}
