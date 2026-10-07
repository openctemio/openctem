package unit

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Pausing a scan turns its schedule off. A member may still run it by hand
// (POST /scans/{id}/trigger sets Interactive); automatic triggers and a
// disabled scan are refused, as a blocked run with the reason.
func TestPausedScan_RunByHandButNotAutomatically(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      scan.Status
		interactive bool
		wantRun     bool
	}{
		{"paused, run by hand", scan.StatusPaused, true, true},
		{"paused, automatic", scan.StatusPaused, false, false},
		{"disabled, run by hand", scan.StatusDisabled, true, false},
		{"active, automatic", scan.StatusActive, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, deps := newTestScanService()
			tenantID := shared.NewID()
			deps.toolRepo.addTool("nuclei", true)
			sc := createTestScanInRepo(deps, tenantID, "Paused", scan.ScanTypeSingle)
			sc.Status = tc.status

			run, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
				TenantID: tenantID.String(), ScanID: sc.ID.String(), Interactive: tc.interactive,
			})
			if tc.wantRun {
				if err != nil || run == nil {
					t.Fatalf("TriggerScan: run=%v err=%v, want a run", run, err)
				}
				return
			}
			if err == nil {
				t.Fatal("trigger accepted, want it refused")
			}
			b := blockedRuns(deps, sc.ID)
			if len(b) != 1 || b[0].RefusalCode != "SCAN_NOT_TRIGGERABLE" {
				t.Fatalf("blocked runs = %+v, want one SCAN_NOT_TRIGGERABLE", b)
			}
		})
	}
}

func TestLastRun_Progress(t *testing.T) {
	run := &scanrun.Run{TotalSteps: 4, CompletedSteps: 1}
	if got := (scanservice.LastRun{Run: run}).Progress(); got != 25 {
		t.Errorf("steps progress = %d, want 25", got)
	}
	tasks := &scanrun.TaskSummary{Total: 8, Completed: 3, Failed: 1, Running: 4}
	if got := (scanservice.LastRun{Run: run, Tasks: tasks}).Progress(); got != 50 {
		t.Errorf("task progress = %d, want 50 (tasks win over steps)", got)
	}
	if got := (scanservice.LastRun{}).Progress(); got != 0 {
		t.Errorf("no run progress = %d, want 0", got)
	}
}
