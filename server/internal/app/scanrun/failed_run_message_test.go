package scanrun

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// A failed run says which step failed, why, and with which code, so the run
// row shows the cause (research/62 SG-3, SG-4).
func TestFailedRunMessage(t *testing.T) {
	run := &scanrun.Run{StepRuns: []*scanrun.StepRun{
		{StepKey: "discover", StepName: "Subdomains", Status: scanrun.StepRunStatusCompleted},
		{StepKey: "ports", StepName: "Port scan", Status: scanrun.StepRunStatusFailed,
			ErrorMessage: "Failed to queue: no tool can run scan.ports", ErrorCode: "NO_MATCHING_TOOL"},
		{StepKey: "vuln", Status: scanrun.StepRunStatusFailed, ErrorMessage: "later"},
	}}
	want := `Step "Port scan" failed: Failed to queue: no tool can run scan.ports (NO_MATCHING_TOOL)`
	if got := failedRunMessage(run); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := failedRunMessage(&scanrun.Run{}); got != "Scan run completed with failures" {
		t.Fatalf("no failed step: %q", got)
	}
}
