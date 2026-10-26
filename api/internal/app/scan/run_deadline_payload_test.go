package scan

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A scan command carries its run's deadline, so the sensor ends the job a
// margin before it and reports what the tool settled in time (live
// 2026-10-25: the sensor did not know the run's deadline). A run whose
// deadline is not fixed yet sends none.
func TestCommandPayloadsCarryTheRunDeadline(t *testing.T) {
	deadline := time.Date(2026, 10, 25, 16, 27, 5, 0, time.FixedZone("ICT", 7*3600))
	want := "2026-10-25T09:27:05Z"
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "vulns", Tool: "nuclei", Capabilities: []string{"vulnerability"}}

	withDeadline := &scanrun.Run{ID: shared.NewID(), DeadlineAt: &deadline, Context: map[string]any{"targets": []string{"a.example.com"}}}
	p, err := StepCommandPayload(withDeadline, step, "nuclei", "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p[PayloadKeyDeadline] != want {
		t.Fatalf("workflow step payload deadline %v, want %s", p[PayloadKeyDeadline], want)
	}
	sc := &scan.Scan{ID: shared.NewID(), ScannerName: "nuclei"}
	if got := (&Service{}).scannerPayload(sc, withDeadline, nil, nil, nil, []string{"a.example.com"}, nil)[PayloadKeyDeadline]; got != want {
		t.Fatalf("scan payload deadline %v, want %s", got, want)
	}

	noDeadline := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"a.example.com"}}}
	p, _ = StepCommandPayload(noDeadline, step, "nuclei", "sr", nil)
	if _, ok := p[PayloadKeyDeadline]; ok {
		t.Fatal("a run without a deadline sent one")
	}
	if _, ok := (&Service{}).scannerPayload(sc, noDeadline, nil, nil, nil, []string{"a.example.com"}, nil)[PayloadKeyDeadline]; ok {
		t.Fatal("a scan run without a deadline sent one")
	}
}
