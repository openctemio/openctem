package scan

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// The scan list measures a live run in one unit, the steps the run planned:
// the figure the scan page and the run drawer show. Two of five steps done is
// 40 %, whatever the task counts say.
func TestLastRunProgress_UsesPlannedSteps(t *testing.T) {
	run := &scanrun.Run{TotalSteps: 5, CompletedSteps: 2}
	// Tasks exist only for the steps started so far: 2 of 3 finished.
	tasks := &scanrun.TaskSummary{Total: 3, Completed: 2, Running: 1}
	if got := (LastRun{Run: run, Tasks: tasks}).Progress(); got != 40 {
		t.Fatalf("progress = %d, want 40 (2 of 5 steps), not the task share", got)
	}
}

func TestLastRunProgress_TasksStandInBeforeStepsAreKnown(t *testing.T) {
	run := &scanrun.Run{}
	tasks := &scanrun.TaskSummary{Total: 4, Completed: 1}
	if got := (LastRun{Run: run, Tasks: tasks}).Progress(); got != 25 {
		t.Fatalf("progress = %d, want 25", got)
	}
	if got := (LastRun{Run: run}).Progress(); got != 0 {
		t.Fatalf("progress = %d, want 0", got)
	}
}
